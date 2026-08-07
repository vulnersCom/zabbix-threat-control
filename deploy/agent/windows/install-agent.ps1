#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Vulners UserParameters into zabbix-agent2 on a Windows host.
.DESCRIPTION
    Drops deploy/agent/windows/vulners.conf into the agent's include directory,
    adds an Include= line to the main config only if none covers that directory,
    restarts the agent, and self-tests the keys against the running service.
    Idempotent: a second run with the same content changes nothing.
.NOTES
    Windows PowerShell 5.1 compatible on purpose - that is what ships with the OS.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Where to read vulners.conf from: a path, a UNC share, or an http(s) URL.
    [string]$ConfSource,
    # Service name, when the agent was installed under a non-default one.
    [string]$ServiceName,
    # Include directory override.
    [string]$IncludeDir,
    # Agent Timeout to enforce; Get-HotFix does not fit in the 3s default.
    [int]$Timeout = 30,
    # Report what is missing and change nothing.
    [switch]$Check,
    # Remove the drop-in and restart the agent.
    [switch]$Uninstall,
    # Mirror all output to a file - under GPO nobody sees the console.
    [string]$LogPath,
    # Test hook: dot-source the functions without running anything.
    [switch]$NoRun
)

if (-not $NoRun) {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
}

# --- pure helpers -----------------------------------------------------------

# Split-Path and Join-Path resolve against the *host* path syntax, so they do
# not treat "\" as a separator when the tests run on macOS. These two do the
# string work themselves and behave identically everywhere.
function Split-WindowsParent {
    # Both separators: Zabbix accepts forward slashes in a config path, and the
    # tests run on macOS against real directories.
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -replace '[\\/][^\\/]*$', '')
}

function Join-WindowsPath {
    param([Parameter(Mandatory)][string]$Parent, [Parameter(Mandatory)][string]$Child)
    return ($Parent.TrimEnd('\') + '\' + $Child.TrimStart('\'))
}

# Zabbix takes the last active occurrence of a non-multi parameter.
function Get-ActiveConfigValue {
    param([string[]]$Lines, [Parameter(Mandatory)][string]$Name)
    $value = $null
    foreach ($line in $Lines) {
        if ($line -match ('^\s*{0}\s*=\s*(.*?)\s*$' -f [regex]::Escape($Name))) {
            $value = $Matches[1]
        }
    }
    return $value
}

function Get-ActiveIncludePaths {
    param([string[]]$Lines)
    $paths = @()
    foreach ($line in $Lines) {
        if ($line -match '^\s*Include\s*=\s*(.*?)\s*$') { $paths += $Matches[1] }
    }
    return ,$paths
}

function Resolve-AgainstConfDir {
    # Include= accepts a path relative to the agent's working directory (the
    # stock MSI config ships one for plugins.d). Resolved against the process
    # working directory instead, it would point wherever the admin happened to
    # run the script from - so anchor anything that is not already a
    # drive-letter or UNC path to the config file's own directory.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ConfPath)
    if ($Path -match '^[A-Za-z]:[\\/]' -or $Path -match '^\\\\' -or $Path -match '^/') { return $Path }
    $relative = $Path -replace '^\.[\\/]', ''
    return (Join-WindowsPath (Split-WindowsParent $ConfPath) $relative)
}

function Resolve-IncludeDirectory {
    param(
        [string[]]$Lines,
        [Parameter(Mandatory)][string]$ConfPath,
        [string]$Override
    )

    # An Include= entry is usable for UserParameters when it points at a
    # directory or a *.conf mask. plugins.d holds agent2's Go plugin configs -
    # dropping UserParameters there works by accident at best, so skip it.
    $dirs = @()
    foreach ($inc in (Get-ActiveIncludePaths -Lines $Lines)) {
        if ($inc -match '(?i)plugins\.d') { continue }
        if ($inc -match '\*') { $dirs += (Split-WindowsParent $inc) }
        else {
            # Zabbix accepts a bare-directory Include= with no trailing
            # separator (Include=C:\...\zabbix_agent2.d) and forward-slash
            # forms, not just the "\" -terminated spelling. A trailing "\" or
            # "/" is enough to tell a directory from a file syntactically, but
            # the common case on real installs has neither - so resolve the
            # path first and ask the filesystem. Get-ParsedConfigFiles already
            # answers exactly this question with Test-Path -PathType Container;
            # reuse that mechanism here rather than growing a second one that
            # could disagree with it. Filesystem tests on this pure, unit-tested
            # function are fine as an ADDITIONAL check: a path that does not
            # exist yet just falls through to the syntactic fallback below, so
            # the existing tests (which use paths nothing on disk backs) are
            # unaffected.
            $resolved = (Resolve-AgainstConfDir -Path $inc -ConfPath $ConfPath).TrimEnd('\', '/')
            if (Test-Path -LiteralPath $resolved -PathType Container -ErrorAction SilentlyContinue) {
                $dirs += $resolved
            } elseif ($inc.EndsWith('\') -or $inc.EndsWith('/')) {
                $dirs += $inc.TrimEnd('\', '/')
            }
        }
    }

    if ($Override) {
        $dir = $Override.TrimEnd('\')
        $needs = -not ($dirs -contains $dir)
    } elseif ($dirs.Count -gt 0) {
        $dir = $dirs[0]
        $needs = $false
    } else {
        $dir = Join-WindowsPath (Split-WindowsParent $ConfPath) 'zabbix_agent2.d'
        $needs = $true
    }

    # Include= accepts a directory relative to the agent's working directory
    # (the stock MSI config ships one for plugins.d), and a site could write
    # a relative UserParameters include just as easily. Resolved against the
    # process working directory instead, the drop-in would land wherever the
    # admin happened to run the script from and the agent would never load
    # it - so anchor anything that is not already a drive-letter or UNC path
    # to the config file's own directory.
    $dir = Resolve-AgainstConfDir -Path $dir -ConfPath $ConfPath

    return [pscustomobject]@{
        Directory        = $dir
        NeedsIncludeLine = $needs
        IncludeLine      = 'Include=' + (Join-WindowsPath $dir '*.conf')
    }
}

function Enable-Tls12 {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

function Test-VulnersConfPayload {
    param([string]$Text)
    if (-not $Text) { return $false }
    return [bool]($Text -match '(?m)^\s*UserParameter=vulners\.os\s*,')
}

function Get-VulnersConfText {
    param(
        [string]$ConfSource,
        [Parameter(Mandatory)][string]$ScriptDir,
        # Where the sibling-file fallback goes when the script was fetched
        # on its own rather than unpacked from a release archive.
        [string]$DefaultUrl = 'https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/agent/windows/vulners.conf'
    )

    if ($ConfSource -and $ConfSource -match '^(?i)https?://') {
        # PowerShell 5.1 still negotiates SSL3/TLS 1.0 by default; GitHub has
        # required TLS 1.2 for years, so the download fails without this.
        Enable-Tls12
        $text = (Invoke-WebRequest -Uri $ConfSource -UseBasicParsing).Content
        $origin = $ConfSource
    } elseif ($ConfSource) {
        if (-not (Test-Path -LiteralPath $ConfSource)) {
            throw "vulners.conf not found at '$ConfSource'"
        }
        # [IO.File]::ReadAllText decodes UTF-8 (honouring a BOM if present) on
        # both PowerShell 5.1 and 7; Get-Content -Raw on 5.1 falls back to the
        # ANSI code page instead, mangling any non-ASCII byte. But it resolves
        # a relative path against the *process* working directory, not
        # PowerShell's current location, and the two can differ - so resolve
        # to an absolute, provider-native path first.
        $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ConfSource).ProviderPath)
        $origin = $ConfSource
    } else {
        $sibling = Join-Path $ScriptDir 'vulners.conf'
        if (Test-Path -LiteralPath $sibling) {
            $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $sibling).ProviderPath)
            $origin = $sibling
        } else {
            Enable-Tls12
            $text = (Invoke-WebRequest -Uri $DefaultUrl -UseBasicParsing).Content
            $origin = $DefaultUrl
        }
    }

    if (-not (Test-VulnersConfPayload -Text $text)) {
        throw "the content from '$origin' does not look like vulners.conf (no active UserParameter=vulners.os line)"
    }
    return $text
}

function Set-ConfTimeout {
    param([string]$Text, [Parameter(Mandatory)][int]$Timeout)
    $line = "Timeout=$Timeout"
    if ($Text -match '(?m)^\s*Timeout\s*=') {
        return [regex]::Replace($Text, '(?m)^\s*Timeout\s*=.*$', $line)
    }
    if ($Text -and -not $Text.EndsWith("`n")) { $Text += "`n" }
    return $Text + $line + "`n"
}

function Get-ConfigHash {
    param([string]$Text)
    if ($null -eq $Text) { $Text = '' }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Text -replace "`r`n", "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }))
    } finally {
        $sha.Dispose()
    }
}

function Test-DropInCurrent {
    param([Parameter(Mandatory)][string]$Path, [string]$Text)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    # [IO.File]::ReadAllText decodes UTF-8 (honouring a BOM if present) on both
    # PowerShell 5.1 and 7. Get-Content -Raw on 5.1 falls back to the ANSI code
    # page instead, which turns any non-ASCII byte in the file into a different
    # string than the one we wrote - the hashes would never match and the agent
    # would be restarted on every single run.
    $existing = [IO.File]::ReadAllText($Path)
    return ((Get-ConfigHash -Text $existing) -eq (Get-ConfigHash -Text $Text))
}

function ConvertTo-ZabbixRequest {
    param([Parameter(Mandatory)][string]$Key)
    $payload = [Text.Encoding]::UTF8.GetBytes($Key)
    $length  = [BitConverter]::GetBytes([int64]$payload.Length)
    if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }

    $buffer = New-Object 'System.Collections.Generic.List[byte]'
    $buffer.AddRange([Text.Encoding]::ASCII.GetBytes('ZBXD'))
    $buffer.Add([byte]0x01)
    $buffer.AddRange($length)
    $buffer.AddRange($payload)
    return ,$buffer.ToArray()
}

function ConvertFrom-ZabbixResponse {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -lt 13) { throw 'short response from the agent (fewer than 13 bytes)' }
    if ([Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'ZBXD') {
        throw 'not a Zabbix response (bad header)'
    }
    $length = [BitConverter]::ToInt64($Bytes, 5)
    if ($Bytes.Length -lt (13 + $length)) {
        throw "truncated response: header announces $length bytes, got $($Bytes.Length - 13)"
    }
    return [Text.Encoding]::UTF8.GetString($Bytes, 13, [int]$length)
}

# Query the *running service* rather than `zabbix_agent2.exe -t`: only this
# proves the include was actually loaded by the process the server talks to.
function Invoke-AgentKey {
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$AgentHost = '127.0.0.1',
        [int]$Port = 10050,
        [int]$TimeoutMs = 45000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($AgentHost, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(5000)) {
            throw "connection to ${AgentHost}:${Port} timed out"
        }
        $client.EndConnect($connect)

        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $request = ConvertTo-ZabbixRequest -Key $Key
        $stream.Write($request, 0, $request.Length)
        $stream.Flush()

        $memory = New-Object System.IO.MemoryStream
        $chunk = New-Object byte[] 8192
        while (($read = $stream.Read($chunk, 0, $chunk.Length)) -gt 0) {
            $memory.Write($chunk, 0, $read)
        }
        return ConvertFrom-ZabbixResponse -Bytes $memory.ToArray()
    } finally {
        $client.Close()
    }
}

function Get-AgentPathsFromImagePath {
    param([Parameter(Mandatory)][string]$ImagePath)

    $exe = $null
    if ($ImagePath -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
    elseif ($ImagePath -match '^\s*(\S+)')  { $exe = $Matches[1] }

    $conf = $null
    if ($ImagePath -match '(?:^|\s)(?:--config|-c)\s+"([^"]+)"') { $conf = $Matches[1] }
    elseif ($ImagePath -match '(?:^|\s)(?:--config|-c)\s+(\S+)')  { $conf = $Matches[1] }

    if (-not $conf -and $exe) {
        $conf = Join-WindowsPath (Split-WindowsParent $exe) 'zabbix_agent2.conf'
    }

    return [pscustomobject]@{ Exe = $exe; Conf = $conf }
}

function Get-ZabbixAgentService {
    param([string]$ServiceName)

    if ($ServiceName) {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName.Replace("'", "''")) -ErrorAction SilentlyContinue
        if (-not $svc) { throw "no service named '$ServiceName' on this host" }
        return $svc
    }

    $svc = Get-CimInstance Win32_Service -Filter "Name='Zabbix Agent 2'" -ErrorAction SilentlyContinue
    if ($svc) { return $svc }

    $svc = Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -match '(?i)zabbix_agent2\.exe' } |
        Select-Object -First 1
    if ($svc) { return $svc }

    throw "zabbix-agent2 is not installed: no service named 'Zabbix Agent 2' and none running zabbix_agent2.exe. Install the Zabbix agent 2 MSI first, then re-run this script."
}

# --- orchestration ----------------------------------------------------------

function Write-Log {
    param([string]$Message, [ValidateSet('info', 'warn', 'error')][string]$Level = 'info')
    $line = '{0} {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    switch ($Level) {
        'warn'  { Write-Host $line -ForegroundColor Yellow }
        'error' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    if (-not $LogPath) { return }
    # A logging failure (unwritable directory, full disk) must never abort the
    # install - warn once on the console and keep going without the file.
    try {
        Add-Content -LiteralPath $LogPath -Value $line
    } catch {
        if (-not (Get-Variable -Name LogWriteFailed -Scope Script -ErrorAction SilentlyContinue)) {
            $script:LogWriteFailed = $true
            Write-Host "cannot write to -LogPath '$LogPath' ($($_.Exception.Message)); continuing without the log file" -ForegroundColor Yellow
        }
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-AgentService {
    # Restart-Service is unusable here. agent2 on a live host takes 15-30s to
    # stop; Restart-Service stops waiting well before that and issues the start
    # against a service that is still stopping, which fails with "Failed to
    # start service". On the stand that made the installer roll back a perfectly
    # good config on every single run, while the agent quietly came up a second
    # later. Stop, wait for Stopped, start, wait for Running - each with the
    # full budget.
    param([Parameter(Mandatory)][string]$Name, [int]$WaitSeconds = 60)
    $budget = [TimeSpan]::FromSeconds($WaitSeconds)

    if ((Get-Service -Name $Name).Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        (Get-Service -Name $Name).WaitForStatus('Stopped', $budget)
    }

    Start-Service -Name $Name -ErrorAction Stop
    (Get-Service -Name $Name).WaitForStatus('Running', $budget)
    return ((Get-Service -Name $Name).Status -eq 'Running')
}

function Test-DeclaresVulnersKeys {
    param([string]$Text)
    if (-not $Text) { return $false }
    return [bool]($Text -match '(?m)^\s*UserParameter=vulners\.')
}

function Get-ParsedConfigFiles {
    # Every file agent2 actually reads: the main config, plus the expansion of
    # each active Include - a *.conf mask, a whole directory, or a single file.
    # Scanning only the directory we install into is not enough: on the stand a
    # copy of vulners.conf sat in plugins.d, which the stock config includes on
    # a separate line, and that was the duplicate that stopped the agent.
    param([string[]]$Lines, [Parameter(Mandatory)][string]$ConfPath)
    $files = @($ConfPath)
    foreach ($inc in (Get-ActiveIncludePaths -Lines $Lines)) {
        $resolved = Resolve-AgainstConfDir -Path $inc -ConfPath $ConfPath
        if ($resolved -match '\*') {
            $dir = Split-WindowsParent $resolved
            $mask = $resolved.Substring($dir.Length + 1)
            if (Test-Path -LiteralPath $dir) {
                $files += (Get-ChildItem -LiteralPath $dir -File -Filter $mask -Force -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.FullName })
            }
        } elseif (Test-Path -LiteralPath $resolved.TrimEnd('\') -PathType Container) {
            $files += (Get-ChildItem -LiteralPath $resolved.TrimEnd('\') -File -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName })
        } elseif (Test-Path -LiteralPath $resolved) {
            $files += $resolved
        }
    }
    return ,@($files | Select-Object -Unique)
}

function Get-ConflictingConfs {
    # Anything other than our own drop-in that declares the vulners keys is a
    # duplicate waiting to stop the agent.
    param(
        [string[]]$Lines,
        [Parameter(Mandatory)][string]$ConfPath,
        [Parameter(Mandatory)][string]$DropInPath
    )
    $conflicts = @()
    foreach ($file in (Get-ParsedConfigFiles -Lines $Lines -ConfPath $ConfPath)) {
        if ($file -eq $DropInPath) { continue }
        try {
            if (Test-DeclaresVulnersKeys -Text ([IO.File]::ReadAllText($file))) {
                $conflicts += $file
            }
        } catch {
            continue
        }
    }
    return ,$conflicts
}

function Restore-DropIn {
    # Puts the drop-in back the way it was and REPORTS whether it managed to.
    # The rollback path used to do this with -ErrorAction SilentlyContinue, so a
    # restore that failed produced no error at all and the operator was told the
    # host had been rolled back when it had not.
    param(
        [Parameter(Mandatory)][string]$Path,
        [bool]$Existed,
        [string]$PreviousContent
    )
    try {
        if ($Existed) {
            [IO.File]::WriteAllText($Path, $PreviousContent, (New-Object Text.UTF8Encoding($false)))
            if (-not (Test-Path -LiteralPath $Path)) {
                return [pscustomobject]@{ Ok = $false; Message = "wrote the previous content back to $Path but the file is not there" }
            }
            return [pscustomobject]@{ Ok = $true; Message = '' }
        }

        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $Path) {
            return [pscustomobject]@{ Ok = $false; Message = "$Path is still there after Remove-Item reported success" }
        }
        return [pscustomobject]@{ Ok = $true; Message = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; Message = "$Path : $($_.Exception.Message)" }
    }
}

function ConvertFrom-AgentTestOutput {
    # zabbix_agent2.exe -t prints "<key>   [<type>|<value>]", not a bare value -
    # e.g. "ztc.slow    [s|ok]". <type> is one character: s string, t text,
    # d double, m not supported.
    #
    # The value can span many lines: vulners.win.software returns one line per
    # installed product. Without (?s) the dot stops at the first newline, the
    # match fails, and a perfectly good answer is reported as unparseable -
    # which is exactly how the -t fallback failed on the stand.
    #
    # Deliberately not anchored with \s*$: the caller merges the process's
    # stderr into the same string via 2>&1, and a stderr line arriving after
    # the closing "]" used to turn a good answer into "unexpected -t output".
    # The greedy .* still finds the LAST "]" in the string first, so a normal
    # single-bracket answer is captured in full regardless of what stderr
    # tacks on afterwards.
    param([string]$Raw)
    if ($Raw -match '(?s)\[(?<type>[a-z])\|(?<value>.*)\]') {
        return [pscustomobject]@{ Ok = $true; Type = $Matches['type']; Value = $Matches['value'] }
    }
    return [pscustomobject]@{ Ok = $false; Type = ''; Value = '' }
}

function Split-AgentResponse {
    # An unsupported key comes back as "ZBX_NOTSUPPORTED", a NUL byte, then the
    # reason. Printed as one string the two run together
    # ("ZBX_NOTSUPPORTEDUnknown metric vulners.os"), which is how the stand's
    # first clean run reported it.
    param([string]$Response)
    if ($null -eq $Response) { $Response = '' }
    $nul = [string][char]0
    if ($Response.Contains($nul)) {
        $parts = $Response -split $nul, 2
        return [pscustomobject]@{ Status = $parts[0]; Reason = $parts[1].TrimEnd([char]0) }
    }
    return [pscustomobject]@{ Status = $Response; Reason = '' }
}

function Test-LoopbackAllowed {
    # The self-test queries the agent on 127.0.0.1, which it answers only if
    # Server= covers that address. A bare 0.0.0.0/0 covers everything, loopback
    # included - warning about it sends the operator looking for a problem that
    # is not there.
    param([string]$Servers)
    if (-not $Servers) { return $false }
    $entries = $Servers -split ',' | ForEach-Object { $_.Trim() }
    foreach ($entry in $entries) {
        if ($entry -eq '0.0.0.0/0' -or $entry -eq '::/0') { return $true }
        if ($entry -eq '127.0.0.1' -or $entry -eq '::1' -or $entry -eq 'localhost') { return $true }
        if ($entry -match '^127\.0\.0\.0/(8|16|24|32)$') { return $true }
    }
    return $false
}

function Get-AgentLogTail {
    param([string]$ConfPath, [int]$Lines = 20)
    $configured = Get-ActiveConfigValue -Lines (Get-Content -LiteralPath $ConfPath -ErrorAction SilentlyContinue) -Name 'LogFile'
    if (-not $configured -or -not (Test-Path -LiteralPath $configured)) { return @() }
    # -ErrorAction here, not just at the call site: with $ErrorActionPreference
    # = 'Stop' in force, a locked or unreadable log would otherwise turn this
    # normally non-terminating Get-Content error into a terminating one - and
    # this helper is called from the rollback path, which must never throw.
    $tail = Get-Content -LiteralPath $configured -Tail $Lines -ErrorAction SilentlyContinue
    if ($null -eq $tail) { return @() }
    return ,$tail
}

function Invoke-SelfTest {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string]$ConfPath,
        [string[]]$Keys = @('vulners.os', 'vulners.version', 'vulners.win.software', 'vulners.win.kb')
    )

    $failed = @()
    foreach ($key in $Keys) {
        $value = $null
        $reason = ''
        try {
            $answer = Split-AgentResponse -Response (Invoke-AgentKey -Key $key)
            $value = $answer.Status
            $reason = $answer.Reason
        } catch {
            # A refused or rejected connection usually means Server= does not
            # list 127.0.0.1. Fall back to running the check out-of-process:
            # weaker evidence (it re-reads the config rather than proving the
            # service loaded it), so say so.
            Write-Log "cannot query $key over 127.0.0.1:10050 ($($_.Exception.Message)); falling back to zabbix_agent2.exe -t" 'warn'

            # This call gets its own try/catch and its own, local
            # $ErrorActionPreference: under the script-wide 'Stop', a native
            # process's stderr merged in through 2>&1 raises a terminating
            # NativeCommandError on Windows PowerShell 5.1, and this whole
            # block already runs inside a catch - an uncaught error here would
            # escape Invoke-SelfTest, and from there Invoke-Main, entirely.
            $raw = ''
            $savedEap = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $raw = (& $Exe -c $ConfPath -t $key 2>&1 | Out-String).Trim()
            } catch {
                Write-Log "$key -> zabbix_agent2.exe -t failed to run: $($_.Exception.Message)" 'error'
                $failed += $key
                continue
            } finally {
                $ErrorActionPreference = $savedEap
            }

            $parsed = ConvertFrom-AgentTestOutput -Raw $raw
            if (-not $parsed.Ok) {
                Write-Log "$key -> unexpected -t output: $raw" 'error'
                $failed += $key
                continue
            }
            if ($parsed.Type -eq 'm') { $value = 'ZBX_NOTSUPPORTED' } else { $value = $parsed.Value }
        }

        if (-not $value -or $value -match 'ZBX_NOTSUPPORTED') {
            $detail = $value
            if ($reason) { $detail = "$value ($reason)" }
            Write-Log "$key -> $detail" 'error'
            $failed += $key
        } else {
            $lines = ($value -split "`n").Count
            Write-Log ("{0} -> {1} line(s), first: {2}" -f $key, $lines, (($value -split "`n")[0].Trim()))
        }
    }
    return ,$failed
}

# Shared by the failed-restart path and the write-failure path below: undo
# whatever this run actually wrote and try once to get the agent back to
# where it was. Must never throw - both callers depend on it returning
# normally so *they* can still return the contracted 1 rather than letting an
# exception escape Invoke-Main - so every internal step here is wrapped and a
# failure to restore is logged, not propagated.
#
# DropInWritten/DropInPreviousContent carry provenance explicitly rather than
# letting this function infer it from Test-Path: a drop-in that already
# existed and already worked, left untouched because Move-Item itself is what
# failed, must never be deleted just because the file happens to be there.
function Restore-AgentState {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$ConfPath,
        [string]$BackupPath,
        [string]$DropInPath,
        [bool]$DropInWritten,
        # Whether a drop-in was on disk before this run. This is the flag that
        # decides restore-versus-delete, NOT the content below: a [string]
        # parameter turns a passed $null into '', so a "was there previous
        # content?" test on it is always true. On the stand that wrote a 0-byte
        # vulners.conf on every rollback instead of removing the file.
        [bool]$DropInExisted,
        [string]$DropInPreviousContent
    )
    # This run only ever replaced the on-disk drop-in if Move-Item actually
    # completed. If it did not, whatever was there before - present or absent -
    # was never touched, so leave it alone.
    if ($DropInWritten -and $DropInPath) {
        $restored = Restore-DropIn -Path $DropInPath -Existed $DropInExisted -PreviousContent $DropInPreviousContent
        if (-not $restored.Ok) {
            Write-Log "ROLLBACK INCOMPLETE: $($restored.Message)" 'error'
            Write-Log "the host is NOT back to its previous state; fix $DropInPath by hand" 'error'
        }
    }

    if ($BackupPath -and (Test-Path -LiteralPath $BackupPath)) {
        try {
            Copy-Item -LiteralPath $BackupPath -Destination $ConfPath -Force -ErrorAction Stop
        } catch {
            Write-Log "ROLLBACK INCOMPLETE: could not restore $ConfPath from $BackupPath : $($_.Exception.Message)" 'error'
        }
    }

    # Read the log BEFORE restarting. The lines that explain why the agent
    # refused the config are the last thing in it right now; a successful
    # rollback restart appends a full plugin listing on top of them and buries
    # the reason out of the tail's reach.
    try {
        foreach ($line in (Get-AgentLogTail -ConfPath $ConfPath)) { Write-Log "agent log: $line" 'error' }
    } catch {
        Write-Log "could not read the agent log: $($_.Exception.Message)" 'error'
    }

    try {
        Restart-AgentService -Name $ServiceName | Out-Null
    } catch {
        # Not fatal on its own - the status line below is the verdict - but the
        # reason belongs in the log rather than nowhere.
        Write-Log "the restart during rollback failed: $($_.Exception.Message)" 'error'
    }

    try {
        Write-Log ("agent status after rollback: {0}" -f (Get-Service -Name $ServiceName).Status) 'error'
    } catch {
        Write-Log "could not read the agent's service status after rollback: $($_.Exception.Message)" 'error'
    }
}

function Invoke-Main {
    if (-not (Test-Administrator)) {
        Write-Log 'this script must run elevated (Run as administrator, or the SYSTEM context under GPO/SCCM)' 'error'
        return 1
    }

    $service = Get-ZabbixAgentService -ServiceName $ServiceName
    $paths = Get-AgentPathsFromImagePath -ImagePath $service.PathName
    Write-Log "agent service '$($service.Name)' ($($service.State)), config $($paths.Conf)"

    if (-not (Test-Path -LiteralPath $paths.Conf)) {
        Write-Log "the service points at '$($paths.Conf)' but that file does not exist" 'error'
        return 1
    }

    $confLines = Get-Content -LiteralPath $paths.Conf

    $include = Resolve-IncludeDirectory -Lines $confLines -ConfPath $paths.Conf -Override $IncludeDir
    $dropIn = Join-WindowsPath $include.Directory 'vulners.conf'
    Write-Log "include directory $($include.Directory)"

    $servers = Get-ActiveConfigValue -Lines $confLines -Name 'Server'
    if ($servers -and -not (Test-LoopbackAllowed -Servers $servers)) {
        Write-Log "Server=$servers does not cover 127.0.0.1; the self-test will fall back to -t" 'warn'
    }

    if ($Uninstall) {
        if (-not (Test-Path -LiteralPath $dropIn)) {
            Write-Log 'nothing to remove'
            return 0
        }
        if ($PSCmdlet.ShouldProcess($dropIn, 'Remove')) {
            try {
                Remove-Item -LiteralPath $dropIn -Force
                Write-Log "removed $dropIn"
                if (-not (Restart-AgentService -Name $service.Name)) {
                    Write-Log 'the agent did not come back up after removal' 'error'
                    return 1
                }
            } catch {
                Write-Log "failed to remove $dropIn or restart the agent: $($_.Exception.Message)" 'error'
                return 1
            }
            Write-Log "the Include= line in $($paths.Conf) was left in place: other configs may rely on it"
        }
        return 0
    }

    # An included file can *set* Timeout, but it does not follow that it can
    # *override* one already active in the main config - Zabbix takes the
    # last active occurrence across the whole config, main file included. A
    # lower value there can still starve vulners.win.kb even though the
    # drop-in asks for more time, so flag it rather than silently trusting
    # the drop-in's value. (Skipped above, under -Uninstall: nothing to warn
    # about in a drop-in that is being removed.)
    $mainTimeout = Get-ActiveConfigValue -Lines $confLines -Name 'Timeout'
    if ($mainTimeout -match '^\d+$' -and [int]$mainTimeout -lt $Timeout) {
        Write-Log ("{0} sets Timeout={1}, lower than the {2}s this script configures for the drop-in; vulners.win.kb may time out because the main config's value may win over the drop-in" -f $paths.Conf, $mainTimeout, $Timeout) 'warn'
    }

    # -- Branch A (Task 1): the Timeout lives in the drop-in.
    $desired = Set-ConfTimeout -Text (Get-VulnersConfText -ConfSource $ConfSource -ScriptDir $PSScriptRoot) -Timeout $Timeout
    $current = Test-DropInCurrent -Path $dropIn -Text $desired

    # agent2 refuses to start if two files declare the same UserParameter, and
    # its log names the key but never the file. With a bare-directory Include=
    # every file in there counts, so say which one is in the way.
    $conflicts = Get-ConflictingConfs -Lines $confLines -ConfPath $paths.Conf -DropInPath $dropIn
    foreach ($conflict in $conflicts) {
        Write-Log "$conflict also declares vulners UserParameters; agent2 will refuse to start with duplicates" 'error'
    }

    if ($Check) {
        # "missing" and "outdated" call for different reactions - an outdated
        # drop-in still answers the keys, so saying only that something is wrong
        # leaves the operator guessing which.
        $dropInState = 'missing'
        if ($current) { $dropInState = 'current' }
        elseif (Test-Path -LiteralPath $dropIn) { $dropInState = 'outdated' }
        Write-Log ("drop-in: {0} ({1})" -f $dropInState, $dropIn)
        Write-Log ("Include= line: {0}" -f $(if ($include.NeedsIncludeLine) { 'must be added' } else { 'present' }))
        $failed = Invoke-SelfTest -Exe $paths.Exe -ConfPath $paths.Conf
        if ($current -and -not $include.NeedsIncludeLine -and $failed.Count -eq 0 `
                -and $conflicts.Count -eq 0 -and $service.State -eq 'Running') {
            Write-Log 'host is fully configured'
            return 0
        }
        return 1
    }

    if ($conflicts.Count -gt 0) {
        Write-Log 'remove the file(s) above from the include directory and re-run; installing on top of them would only stop the agent' 'error'
        return 1
    }

    if ($current -and -not $include.NeedsIncludeLine -and $service.State -eq 'Running') {
        # A drop-in that is current and a service that is Running is
        # necessary but not sufficient: a host where a *previous* run's
        # self-test failed looks identical on every later boot, since the
        # failure never touched the drop-in or the service. Left unchecked, a
        # GPO startup script would report green forever on such a host while
        # it collects nothing. Probe with one cheap key rather than all four,
        # to keep the cost of the common (healthy) case low; Invoke-SelfTest's
        # own -t fallback still applies, so a host whose Server= excludes
        # 127.0.0.1 does not restart on every boot just because of this check.
        $probeFailed = Invoke-SelfTest -Exe $paths.Exe -ConfPath $paths.Conf -Keys @('vulners.os')
        if ($probeFailed.Count -eq 0) {
            Write-Log 'already current, not restarting the agent'
            return 0
        }
        Write-Log 'drop-in looks current but vulners.os did not answer; reinstalling' 'warn'
    }

    if (-not $PSCmdlet.ShouldProcess($dropIn, 'Install the Vulners UserParameters')) { return 0 }

    # Backup, main-config edit, directory creation and the drop-in write/move
    # all mutate the host. A locked file, a full disk or a permission error
    # here must not escape as an uncaught exception - that would exit with
    # something other than the contracted 0/1 and, if the Include= line was
    # already added before a later step throws, leave the host with an
    # edited main config, no drop-in, and no rollback.
    #
    # $dropInPreviousContent is captured *before* Move-Item can overwrite it,
    # so that if this run is replacing an already-working drop-in and a later
    # step fails, the rollback restores that content instead of just deleting
    # a config that was fine before this run started.
    $dropInExisted = Test-Path -LiteralPath $dropIn
    $dropInPreviousContent = $null
    $dropInWritten = $false
    $backup = $null
    # NOT "$dropIn.new". The stand's Include= points at the directory with no
    # *.conf mask, so agent2 parses every file in it - a temp file left behind
    # by an interrupted run becomes a second copy of the same UserParameters and
    # the agent refuses to start with "duplicate user parameter". Stage outside
    # the directory; the move is no longer atomic, which matters far less.
    $temp = Join-Path $env:TEMP ('vulners.conf.' + [guid]::NewGuid().ToString('n') + '.tmp')
    try {
        if ($include.NeedsIncludeLine) {
            $backup = "$($paths.Conf).bak"
            Copy-Item -LiteralPath $paths.Conf -Destination $backup -Force
            Add-Content -LiteralPath $paths.Conf -Value ''
            Add-Content -LiteralPath $paths.Conf -Value '# Added by install-agent.ps1 (zabbix-threat-control)'
            Add-Content -LiteralPath $paths.Conf -Value $include.IncludeLine
            Write-Log "added '$($include.IncludeLine)' to $($paths.Conf) (backup: $backup)"
        }

        if (-not (Test-Path -LiteralPath $include.Directory)) {
            New-Item -ItemType Directory -Path $include.Directory -Force | Out-Null
        }

        if ($dropInExisted) {
            $dropInPreviousContent = [IO.File]::ReadAllText($dropIn)
        }

        # UTF-8 without a BOM, written and read through [IO.File] on both sides, so
        # the idempotency hash in Test-DropInCurrent compares like with like. Set-Content
        # -Encoding UTF8 on PowerShell 5.1 emits a BOM; -Encoding ASCII destroys the
        # non-ASCII characters in the header.
        [IO.File]::WriteAllText($temp, $desired, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $dropIn -Force
        $dropInWritten = $true
        Write-Log "wrote $dropIn"
    } catch {
        Write-Log "failed to write the drop-in or update the main config: $($_.Exception.Message)" 'error'
        # Move-Item may have thrown after WriteAllText succeeded, orphaning
        # the temp file; clean it up best-effort, same as the rollback itself.
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        Restore-AgentState -ServiceName $service.Name -ConfPath $paths.Conf -BackupPath $backup `
            -DropInPath $dropIn -DropInWritten $dropInWritten -DropInExisted $dropInExisted `
            -DropInPreviousContent $dropInPreviousContent
        return 1
    }

    $restarted = $false
    try {
        $restarted = Restart-AgentService -Name $service.Name
    } catch {
        Write-Log "restart failed: $($_.Exception.Message)" 'error'
    }

    if (-not $restarted) {
        Write-Log 'the agent did not come back up; rolling back' 'error'
        Restore-AgentState -ServiceName $service.Name -ConfPath $paths.Conf -BackupPath $backup `
            -DropInPath $dropIn -DropInWritten $dropInWritten -DropInExisted $dropInExisted `
            -DropInPreviousContent $dropInPreviousContent
        return 1
    }

    $failed = Invoke-SelfTest -Exe $paths.Exe -ConfPath $paths.Conf
    if ($failed.Count -gt 0) {
        Write-Log ("these keys did not answer: {0}" -f ($failed -join ', ')) 'error'
        # WaitForStatus('Running') above only proves the SCM saw the service
        # start; agent2 can still exit right after (a config it accepts at
        # startup but chokes on once it actually reads it). If that happened,
        # the self-test's loopback query got refused, its -t fallback ran
        # against a dead process, and the drop-in - plus any Include= edit -
        # would otherwise stay in place with a stopped agent that never comes
        # back on its own. Roll back in that case. When the agent is still
        # running, leave it as-is: that is the deliberately debuggable case,
        # where a config problem answers ZBX_NOTSUPPORTED rather than killing
        # the process.
        $stillRunning = $false
        try {
            $stillRunning = ((Get-Service -Name $service.Name).Status -eq 'Running')
        } catch {
            Write-Log "could not read the agent's service status after the self-test: $($_.Exception.Message)" 'error'
        }
        if (-not $stillRunning) {
            Write-Log 'the agent is not running after the self-test failure; rolling back' 'error'
            Restore-AgentState -ServiceName $service.Name -ConfPath $paths.Conf -BackupPath $backup `
                -DropInPath $dropIn -DropInWritten $dropInWritten -DropInExisted $dropInExisted `
                -DropInPreviousContent $dropInPreviousContent
        }
        return 1
    }

    Write-Log 'done. Next: link "Template Vulners OS-Report Windows" to this host in Zabbix.'
    return 0
}

if (-not $NoRun) {
    # Invoke-Main is not itself wrapped: several of its early steps (finding the
    # service, reading the main config, fetching vulners.conf from a UNC path or
    # URL) can throw before anything is written, and under GPO the network or
    # the DC may simply not be up yet at boot. Catching here, rather than inside
    # Invoke-Main, guarantees every exit is a logged, explicit 0 or 1 - never an
    # unhandled exception that bypasses Write-Log (and therefore -LogPath) and
    # leaves the operator with an empty log file for the one run that mattered.
    exit $(
        try { Invoke-Main }
        catch { Write-Log $_.Exception.Message 'error'; 1 }
    )
}
