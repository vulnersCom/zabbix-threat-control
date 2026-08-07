BeforeAll {
    . "$PSScriptRoot/install-agent.ps1" -NoRun
}

Describe 'Get-ActiveConfigValue' {
    It 'returns the last active value and ignores comments' {
        $lines = @('# Timeout=3', 'Timeout=10', '  Timeout = 30  ')
        Get-ActiveConfigValue -Lines $lines -Name 'Timeout' | Should -Be '30'
    }

    It 'returns $null when the parameter is only commented out' {
        Get-ActiveConfigValue -Lines @('# Timeout=3') -Name 'Timeout' | Should -BeNullOrEmpty
    }
}

Describe 'Split-WindowsParent / Join-WindowsPath' {
    It 'splits a Windows path regardless of the host OS' {
        Split-WindowsParent 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf' |
            Should -Be 'C:\Program Files\Zabbix Agent 2'
    }

    It 'joins without doubling separators' {
        Join-WindowsPath 'C:\Program Files\Zabbix Agent 2\' '\zabbix_agent2.d' |
            Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.d'
    }
}

Describe 'Resolve-IncludeDirectory' {
    # Pester 5 runs Describe bodies during discovery and It bodies during the
    # run phase; a variable assigned in the Describe body is not reliably
    # visible inside It. BeforeAll with $script: scope is the supported way.
    BeforeAll { $script:conf = 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf' }

    It 'uses an existing *.conf include and needs no new line' {
        $lines = @(
            'Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\*.conf'
        )
        $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf
        $r.Directory | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.d'
        $r.NeedsIncludeLine | Should -BeFalse
    }

    It 'skips plugins.d and falls back to the default directory' {
        $lines = @(
            'Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\plugins.d\*.conf'
        )
        $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf
        $r.Directory | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.d'
        $r.NeedsIncludeLine | Should -BeTrue
        $r.IncludeLine | Should -Be 'Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\*.conf'
    }

    It 'ignores commented includes' {
        $lines = @('# Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\*.conf')
        (Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf).NeedsIncludeLine | Should -BeTrue
    }

    It 'ignores an include that points at a single file' {
        $lines = @('Include=C:\Program Files\Zabbix Agent 2\extra.conf')
        (Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf).NeedsIncludeLine | Should -BeTrue
    }

    It 'honours an override and reports whether it is already covered' {
        $lines = @('Include=C:\agent\confs\*.conf')
        $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf -Override 'C:\agent\confs\'
        $r.Directory | Should -Be 'C:\agent\confs'
        $r.NeedsIncludeLine | Should -BeFalse
    }

    It 'resolves a relative include directory against the config file directory' {
        # The stock MSI config ships Include=.\zabbix_agent2.d\plugins.d\*.conf
        # (skipped as a plugin dir); a site could write a relative include for
        # UserParameters just as easily.
        $lines = @('Include=.\zabbix_agent2.d\*.conf')
        $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf
        $r.Directory | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.d'
        $r.NeedsIncludeLine | Should -BeFalse
        $r.IncludeLine | Should -Be 'Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\*.conf'
    }

    It 'leaves an absolute include directory unchanged' {
        $lines = @('Include=C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\*.conf')
        $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:conf
        $r.Directory | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.d'
    }

    Context 'a bare-directory include backed by a real directory on disk' {
        # This is the stock MSI form on a real host - a directory Include=
        # with no *.conf mask and no trailing separator - and Zabbix accepts
        # it in forward-slash spelling too. Nothing above exercises either, so
        # this is the input that would have caught the installer appending a
        # second Include= line over the one already covering the directory.
        BeforeEach {
            $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
            $script:incDir = Join-Path $script:tmp 'zabbix_agent2.d'
            New-Item -ItemType Directory -Path $script:incDir -Force | Out-Null
            $script:realConf = Join-Path $script:tmp 'zabbix_agent2.conf'
            Set-Content -Path $script:realConf -Value 'placeholder'
        }
        AfterEach { Remove-Item -Recurse -Force $script:tmp }

        It 'recognises a directory include with no trailing separator' {
            $lines = @('Include=' + $script:incDir)
            $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:realConf
            $r.Directory | Should -Be $script:incDir
            $r.NeedsIncludeLine | Should -BeFalse
        }

        It 'recognises a directory include with a trailing separator' {
            $lines = @('Include=' + $script:incDir + [IO.Path]::DirectorySeparatorChar)
            $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:realConf
            $r.Directory | Should -Be $script:incDir
            $r.NeedsIncludeLine | Should -BeFalse
        }

        It 'recognises a forward-slash directory include' {
            $forward = $script:incDir -replace '\\', '/'
            $lines = @('Include=' + $forward)
            $r = Resolve-IncludeDirectory -Lines $lines -ConfPath $script:realConf
            $r.NeedsIncludeLine | Should -BeFalse
        }
    }
}

Describe 'dot-sourcing with -NoRun' {
    It 'does not change the caller''s ErrorActionPreference' {
        $before = $ErrorActionPreference
        . "$PSScriptRoot/install-agent.ps1" -NoRun
        $ErrorActionPreference | Should -Be $before
    }
}

Describe 'Test-VulnersConfPayload' {
    It 'accepts a real conf' {
        Test-VulnersConfPayload -Text "# comment`nUserParameter=vulners.os,echo win`n" |
            Should -BeTrue
    }

    It 'rejects an HTML error page from a proxy' {
        Test-VulnersConfPayload -Text '<html><body>403 Forbidden</body></html>' |
            Should -BeFalse
    }

    It 'rejects a conf whose vulners.os line is commented out' {
        Test-VulnersConfPayload -Text '# UserParameter=vulners.os,echo win' | Should -BeFalse
    }
}

Describe 'Get-VulnersConfText' {
    BeforeEach {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tmp | Out-Null
    }
    AfterEach { Remove-Item -Recurse -Force $script:tmp }

    It 'prefers an explicit -ConfSource path' {
        $explicit = Join-Path $script:tmp 'explicit.conf'
        Set-Content -Path $explicit -Value 'UserParameter=vulners.os,echo explicit'
        Set-Content -Path (Join-Path $script:tmp 'vulners.conf') -Value 'UserParameter=vulners.os,echo sibling'
        Get-VulnersConfText -ConfSource $explicit -ScriptDir $script:tmp |
            Should -Match 'echo explicit'
    }

    It 'falls back to vulners.conf next to the script' {
        Set-Content -Path (Join-Path $script:tmp 'vulners.conf') -Value 'UserParameter=vulners.os,echo sibling'
        Get-VulnersConfText -ConfSource '' -ScriptDir $script:tmp | Should -Match 'echo sibling'
    }

    It 'throws a useful error when the payload is not a vulners conf' {
        $bad = Join-Path $script:tmp 'bad.conf'
        Set-Content -Path $bad -Value '<html>404</html>'
        { Get-VulnersConfText -ConfSource $bad -ScriptDir $script:tmp } |
            Should -Throw -ExpectedMessage '*does not look like vulners.conf*'
    }

    It 'throws when an explicit path does not exist' {
        { Get-VulnersConfText -ConfSource (Join-Path $script:tmp 'nope.conf') -ScriptDir $script:tmp } |
            Should -Throw -ExpectedMessage '*not found*'
    }
}

Describe 'Set-ConfTimeout' {
    It 'replaces an existing active Timeout line' {
        $out = Set-ConfTimeout -Text "Timeout=3`nUserParameter=vulners.os,echo win`n" -Timeout 30
        $out | Should -Match '(?m)^Timeout=30$'
        ([regex]::Matches($out, '(?m)^\s*Timeout\s*=')).Count | Should -Be 1
    }

    It 'appends the line when none is present' {
        $out = Set-ConfTimeout -Text "UserParameter=vulners.os,echo win`n" -Timeout 30
        $out | Should -Match '(?m)^Timeout=30$'
        $out | Should -Match 'UserParameter=vulners\.os'
    }

    It 'leaves commented Timeout lines alone' {
        $out = Set-ConfTimeout -Text "# Timeout=3`nUserParameter=vulners.os,echo win`n" -Timeout 30
        $out | Should -Match '(?m)^# Timeout=3$'
        ([regex]::Matches($out, '(?m)^\s*Timeout\s*=')).Count | Should -Be 1
    }

    It 'does not lose the trailing newline' {
        (Set-ConfTimeout -Text 'UserParameter=vulners.os,echo win' -Timeout 30).EndsWith("`n") |
            Should -BeTrue
    }
}

Describe 'Test-DropInCurrent' {
    BeforeEach {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tmp | Out-Null
        $script:target = Join-Path $script:tmp 'vulners.conf'
    }
    AfterEach { Remove-Item -Recurse -Force $script:tmp }

    It 'is false when the file does not exist' {
        Test-DropInCurrent -Path $script:target -Text 'Timeout=30' | Should -BeFalse
    }

    It 'is true for identical content' {
        Set-Content -Path $script:target -Value "Timeout=30`nUserParameter=vulners.os,echo win" -NoNewline
        Test-DropInCurrent -Path $script:target -Text "Timeout=30`nUserParameter=vulners.os,echo win" |
            Should -BeTrue
    }

    It 'ignores line-ending differences' {
        Set-Content -Path $script:target -Value "Timeout=30`r`nUserParameter=vulners.os,echo win" -NoNewline
        Test-DropInCurrent -Path $script:target -Text "Timeout=30`nUserParameter=vulners.os,echo win" |
            Should -BeTrue
    }

    It 'is false when the content differs' {
        Set-Content -Path $script:target -Value 'Timeout=3' -NoNewline
        Test-DropInCurrent -Path $script:target -Text 'Timeout=30' | Should -BeFalse
    }

    It 'round-trips non-ASCII content written the way the installer writes it' {
        # vulners.conf ships an em dash in its header. If the write and the
        # read disagree about the encoding, this run and every future run see
        # a difference and restart the agent forever.
        $text = "# Vulners OS report - Windows inventory `u{2014} zabbix-agent2`nTimeout=30`n"
        [IO.File]::WriteAllText($script:target, $text, (New-Object Text.UTF8Encoding($false)))
        Test-DropInCurrent -Path $script:target -Text $text | Should -BeTrue
    }
}

Describe 'ConvertTo-ZabbixRequest' {
    It 'frames a key with the ZBXD header and a little-endian length' {
        $bytes = ConvertTo-ZabbixRequest -Key 'vulners.os'
        $bytes.Length | Should -Be (13 + 10)
        [Text.Encoding]::ASCII.GetString($bytes[0..3]) | Should -Be 'ZBXD'
        $bytes[4] | Should -Be 1
        $bytes[5] | Should -Be 10
        ($bytes[6..12] | Where-Object { $_ -ne 0 }).Count | Should -Be 0
        [Text.Encoding]::UTF8.GetString($bytes[13..22]) | Should -Be 'vulners.os'
    }
}

Describe 'ConvertFrom-ZabbixResponse' {
    It 'round-trips a framed payload' {
        $frame = ConvertTo-ZabbixRequest -Key 'Windows 10'
        ConvertFrom-ZabbixResponse -Bytes $frame | Should -Be 'Windows 10'
    }

    It 'throws on a response that is not Zabbix' {
        $junk = [Text.Encoding]::ASCII.GetBytes('HTTP/1.1 400 Bad Request')
        { ConvertFrom-ZabbixResponse -Bytes $junk } | Should -Throw -ExpectedMessage '*bad header*'
    }

    It 'throws on a short frame' {
        { ConvertFrom-ZabbixResponse -Bytes ([byte[]]@(90, 66, 88, 68, 1)) } |
            Should -Throw -ExpectedMessage '*short response*'
    }

    It 'throws when the payload is truncated' {
        $frame = ConvertTo-ZabbixRequest -Key 'vulners.os'
        { ConvertFrom-ZabbixResponse -Bytes $frame[0..17] } |
            Should -Throw -ExpectedMessage '*truncated*'
    }
}

Describe 'Get-AgentPathsFromImagePath' {
    It 'parses the quoted MSI form with --config' {
        $image = '"C:\Program Files\Zabbix Agent 2\zabbix_agent2.exe" --config "C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf"'
        $r = Get-AgentPathsFromImagePath -ImagePath $image
        $r.Exe  | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.exe'
        $r.Conf | Should -Be 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf'
    }

    It 'parses the unquoted short form with -c' {
        $r = Get-AgentPathsFromImagePath -ImagePath 'C:\zbx\zabbix_agent2.exe -c C:\zbx\agent2.conf'
        $r.Exe  | Should -Be 'C:\zbx\zabbix_agent2.exe'
        $r.Conf | Should -Be 'C:\zbx\agent2.conf'
    }

    It 'defaults the conf to the executable directory when no flag is present' {
        $r = Get-AgentPathsFromImagePath -ImagePath '"C:\zbx\zabbix_agent2.exe"'
        $r.Conf | Should -Be 'C:\zbx\zabbix_agent2.conf'
    }

    It 'does not mistake a path fragment for the -c flag' {
        $r = Get-AgentPathsFromImagePath -ImagePath '"C:\svc-config\zabbix_agent2.exe"'
        $r.Conf | Should -Be 'C:\svc-config\zabbix_agent2.conf'
    }
}

Describe 'shipped files stay ASCII-only' {
    # Windows PowerShell 5.1 decodes a BOM-less file with the system ANSI code
    # page, not UTF-8. A U+2014 em dash then arrives as three CP1252 characters,
    # the last of which (0x94) is a closing quote - which is enough to make 5.1
    # fail to parse the script at all. It happened to a helper script in this
    # project's own workspace. These two files ship to Windows hosts, so pin them
    # to ASCII rather than relying on everyone downstream reading them as UTF-8.
    It 'has no non-ASCII bytes in <_>' -ForEach @('install-agent.ps1', 'vulners.conf') {
        $path = Join-Path $PSScriptRoot $_
        $bytes = [IO.File]::ReadAllBytes($path)
        $offenders = @()
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -gt 127) { $offenders += ('offset {0}: 0x{1:x2}' -f $i, $bytes[$i]) }
        }
        $offenders -join '; ' | Should -BeNullOrEmpty
    }
}

Describe 'Test-LoopbackAllowed' {
    It 'accepts an explicit loopback entry' {
        Test-LoopbackAllowed -Servers '10.211.55.2,127.0.0.1' | Should -BeTrue
    }

    It 'accepts a catch-all mask, which covers loopback too' {
        # The stand's stock config is Server=0.0.0.0/0. Warning about that one
        # sends the operator hunting for a problem that does not exist.
        Test-LoopbackAllowed -Servers '0.0.0.0/0' | Should -BeTrue
    }

    It 'accepts the loopback network and the IPv6 forms' {
        Test-LoopbackAllowed -Servers '127.0.0.0/8' | Should -BeTrue
        Test-LoopbackAllowed -Servers '::1'         | Should -BeTrue
        Test-LoopbackAllowed -Servers '::/0'        | Should -BeTrue
    }

    It 'rejects a server list that does not cover loopback' {
        Test-LoopbackAllowed -Servers '10.211.55.2, 192.168.0.0/16' | Should -BeFalse
    }

    It 'rejects an empty Server=' {
        Test-LoopbackAllowed -Servers '' | Should -BeFalse
    }

    It 'does not accept an address that merely contains a loopback substring' {
        Test-LoopbackAllowed -Servers '10.127.0.0.1.5' | Should -BeFalse
    }
}

Describe 'Test-DeclaresVulnersKeys' {
    It 'spots an active vulners UserParameter' {
        Test-DeclaresVulnersKeys -Text "# header`nUserParameter=vulners.os,echo win`n" | Should -BeTrue
    }

    It 'ignores a commented-out declaration' {
        Test-DeclaresVulnersKeys -Text '# UserParameter=vulners.os,echo win' | Should -BeFalse
    }

    It 'ignores a file with unrelated UserParameters' {
        # The Task 1 probe left exactly this behind on the stand.
        Test-DeclaresVulnersKeys -Text "Timeout=30`nUserParameter=ztc.slow,echo ok`n" | Should -BeFalse
    }

    It 'is false for empty content' {
        Test-DeclaresVulnersKeys -Text '' | Should -BeFalse
    }
}

Describe 'Get-ConflictingConfs' {
    BeforeEach {
        # Mirror the stand's real layout: a main config, an include directory
        # holding our drop-in, and a plugins.d that the main config includes on
        # a separate line with a relative path.
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $script:incDir = Join-Path $script:tmp 'zabbix_agent2.d'
        $script:pluginsDir = Join-Path $script:incDir 'plugins.d'
        New-Item -ItemType Directory -Path $script:pluginsDir -Force | Out-Null

        $script:conf = Join-Path $script:tmp 'zabbix_agent2.conf'
        # Native paths, so the include expansion can be exercised against a
        # real directory on whichever OS the tests run.
        Set-Content -Path $script:conf -Value @(
            'Server=0.0.0.0/0'
            ('Include=' + (Join-Path $script:pluginsDir '*.conf'))
            ('Include=' + $script:incDir)
        )
        $script:lines = Get-Content -Path $script:conf
        $script:dropIn = Join-Path $script:incDir 'vulners.conf'
        Set-Content -Path $script:dropIn -Value 'UserParameter=vulners.os,echo win'
    }
    AfterEach { Remove-Item -Recurse -Force $script:tmp }

    It 'does not report our own drop-in' {
        (Get-ConflictingConfs -Lines $script:lines -ConfPath $script:conf -DropInPath $script:dropIn).Count |
            Should -Be 0
    }

    It 'reports a copy hiding in plugins.d' {
        # Exactly what stopped the agent on the stand: an older manual install
        # had left vulners.conf in plugins.d, which is reached through its own
        # relative Include= line and so was invisible to a scan of the target
        # directory alone.
        $stray = Join-Path $script:pluginsDir 'vulners.conf'
        Set-Content -Path $stray -Value 'UserParameter=vulners.os,echo win'
        $found = Get-ConflictingConfs -Lines $script:lines -ConfPath $script:conf -DropInPath $script:dropIn
        $found.Count | Should -Be 1
        $found[0] | Should -Match 'plugins\.d'
    }

    It 'reports keys declared in the main config itself' {
        Add-Content -Path $script:conf -Value 'UserParameter=vulners.os,echo win'
        $lines = Get-Content -Path $script:conf
        $found = Get-ConflictingConfs -Lines $lines -ConfPath $script:conf -DropInPath $script:dropIn
        $found.Count | Should -Be 1
        $found[0] | Should -Be $script:conf
    }

    It 'reports a leftover temp file in the include directory' {
        $stale = Join-Path $script:incDir 'vulners.conf.new'
        Set-Content -Path $stale -Value 'UserParameter=vulners.os,echo win'
        (Get-ConflictingConfs -Lines $script:lines -ConfPath $script:conf -DropInPath $script:dropIn).Count |
            Should -Be 1
    }

    It 'leaves unrelated files alone' {
        Set-Content -Path (Join-Path $script:incDir 'ztc-probe.conf') -Value "Timeout=30`nUserParameter=ztc.slow,echo ok"
        Set-Content -Path (Join-Path $script:pluginsDir 'redis.conf') -Value 'Plugins.Redis.Timeout=5'
        (Get-ConflictingConfs -Lines $script:lines -ConfPath $script:conf -DropInPath $script:dropIn).Count |
            Should -Be 0
    }
}

Describe 'Split-AgentResponse' {
    It 'splits the unsupported-key answer at the NUL byte' {
        # Exactly what the stand returned over 127.0.0.1:10050.
        $raw = 'ZBX_NOTSUPPORTED' + [char]0 + 'Unknown metric vulners.os'
        $r = Split-AgentResponse -Response $raw
        $r.Status | Should -Be 'ZBX_NOTSUPPORTED'
        $r.Reason | Should -Be 'Unknown metric vulners.os'
    }

    It 'leaves an ordinary value alone' {
        $r = Split-AgentResponse -Response 'Microsoft Windows 11 Pro'
        $r.Status | Should -Be 'Microsoft Windows 11 Pro'
        $r.Reason | Should -Be ''
    }

    It 'keeps a multi-line value intact' {
        $r = Split-AgentResponse -Response "KB5101001`nKB5102002"
        $r.Status | Should -Be "KB5101001`nKB5102002"
    }

    It 'handles an empty response' {
        (Split-AgentResponse -Response '').Status | Should -Be ''
    }
}

Describe 'Restore-DropIn' {
    BeforeEach {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tmp | Out-Null
        $script:target = Join-Path $script:tmp 'vulners.conf'
    }
    AfterEach { Remove-Item -Recurse -Force $script:tmp }

    It 'deletes a drop-in this run created' {
        Set-Content -Path $script:target -Value 'UserParameter=vulners.os,echo new'
        $r = Restore-DropIn -Path $script:target -Existed $false
        $r.Ok | Should -BeTrue
        Test-Path -LiteralPath $script:target | Should -BeFalse
    }

    It 'restores the previous content byte-for-byte when one existed' {
        $previous = "# was here`nUserParameter=vulners.os,echo old`n"
        Set-Content -Path $script:target -Value 'UserParameter=vulners.os,echo new' -NoNewline
        $r = Restore-DropIn -Path $script:target -Existed $true -PreviousContent $previous
        $r.Ok | Should -BeTrue
        [IO.File]::ReadAllText($script:target) | Should -Be $previous
    }

    It 'restores through the same UTF-8 no-BOM path the installer writes with' {
        # A restore that re-encoded differently would leave the next run seeing
        # a "not current" drop-in and restarting the agent for nothing.
        $previous = "# dash \u{2014} here`nUserParameter=vulners.os,echo old`n"
        Restore-DropIn -Path $script:target -Existed $true -PreviousContent $previous | Out-Null
        $bytes = [IO.File]::ReadAllBytes($script:target)
        $bytes[0] | Should -Not -Be 0xEF   # no BOM
        [IO.File]::ReadAllText($script:target) | Should -Be $previous
    }

    It 'succeeds when there is nothing to delete' {
        (Restore-DropIn -Path $script:target -Existed $false).Ok | Should -BeTrue
    }

    It 'reports failure instead of staying silent when the write cannot land' {
        # Restoring into a directory that does not exist makes WriteAllText
        # throw. The point is that the caller is told, not that this particular
        # obstacle is realistic.
        $missing = Join-Path (Join-Path $script:tmp 'no-such-dir') 'vulners.conf'
        $r = Restore-DropIn -Path $missing -Existed $true -PreviousContent 'UserParameter=vulners.os,echo old'
        $r.Ok | Should -BeFalse
        $r.Message | Should -Not -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-AgentTestOutput' {
    It 'parses a single-line value' {
        $r = ConvertFrom-AgentTestOutput -Raw 'vulners.os                    [s|Microsoft Windows 11 Pro]'
        $r.Ok    | Should -BeTrue
        $r.Type  | Should -Be 's'
        $r.Value | Should -Be 'Microsoft Windows 11 Pro'
    }

    It 'parses a multi-line value' {
        # vulners.win.software returns one line per installed product. The stand
        # reported these as "unexpected -t output" until the pattern went
        # single-line mode.
        $raw = "vulners.win.software      [s|LightBurn version 2.0.05 2.0.05`nGoogle Chrome 151.0.7922.75`nMicrosoft Edge 151.0.4129.59]"
        $r = ConvertFrom-AgentTestOutput -Raw $raw
        $r.Ok | Should -BeTrue
        ($r.Value -split "`n").Count | Should -Be 3
        ($r.Value -split "`n")[0] | Should -Be 'LightBurn version 2.0.05 2.0.05'
        ($r.Value -split "`n")[2] | Should -Be 'Microsoft Edge 151.0.4129.59'
    }

    It 'parses the KB list, which is also multi-line' {
        $raw = "vulners.win.kb        [s|KB5101001`nKB5050575`nKB5120102]"
        (ConvertFrom-AgentTestOutput -Raw $raw).Value -split "`n" | Should -HaveCount 3
    }

    It 'reports type m for an unsupported key' {
        $r = ConvertFrom-AgentTestOutput -Raw 'vulners.os   [m|ZBX_NOTSUPPORTED] [Unknown metric vulners.os]'
        $r.Ok   | Should -BeTrue
        $r.Type | Should -Be 'm'
    }

    It 'refuses output that has no [type|value] at all' {
        (ConvertFrom-AgentTestOutput -Raw 'zabbix_agent2 [1234]: cannot open config file').Ok | Should -BeFalse
    }

    It 'refuses empty output' {
        (ConvertFrom-AgentTestOutput -Raw '').Ok | Should -BeFalse
    }

    It 'still parses when the caller merged a stderr line in after the closing bracket' {
        # The caller runs the exe with 2>&1, so the process's stderr lands in
        # the same string as its stdout. A line arriving after the value used
        # to turn a good answer into "unexpected -t output" because the old
        # pattern anchored on \]\s*$.
        $raw = "vulners.os                    [s|Microsoft Windows 11 Pro]`nWARNING: something noisy on stderr"
        $r = ConvertFrom-AgentTestOutput -Raw $raw
        $r.Ok    | Should -BeTrue
        $r.Value | Should -Be 'Microsoft Windows 11 Pro'
    }
}

Describe 'Invoke-SelfTest' {
    # Exercises the -t fallback path itself, not just its parser: Invoke-AgentKey
    # is mocked to throw (as it does when Server= excludes 127.0.0.1), so every
    # key in these tests goes through "& $Exe -c $ConfPath -t $key 2>&1" for real.
    BeforeEach {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
        $script:conf = Join-Path $script:tmp 'zabbix_agent2.conf'
        Set-Content -Path $script:conf -Value 'placeholder'
    }
    AfterEach { Remove-Item -Recurse -Force $script:tmp }

    It 'falls back to -t and still succeeds when the fallback output has trailing noise' {
        Mock Invoke-AgentKey { throw 'connection refused' }
        $fakeExe = Join-Path $script:tmp 'fake-agent2.ps1'
        # A stand-in for zabbix_agent2.exe -t: prints the key's answer, then a
        # line as if it were stderr merged in by the caller's 2>&1 - exactly
        # the shape that used to defeat the \]\s*$ anchor.
        Set-Content -Path $fakeExe -Value @'
param($c, $t)
Write-Output ("$t    [s|fallback value]")
Write-Output "a trailing diagnostic line after the bracket"
'@
        $failed = Invoke-SelfTest -Exe $fakeExe -ConfPath $script:conf -Keys @('vulners.os')
        $failed | Should -BeNullOrEmpty
    }

    It 'records the key as failed, without throwing, when the -t fallback itself cannot run' {
        Mock Invoke-AgentKey { throw 'connection refused' }
        $missingExe = Join-Path $script:tmp 'does-not-exist.ps1'
        # Not "{ ... } | Should -Not -Throw": that scriptblock is its own scope,
        # so a $failed assigned inside it never reaches the one asserted below.
        $caught = $null
        $failed = $null
        try {
            $failed = Invoke-SelfTest -Exe $missingExe -ConfPath $script:conf -Keys @('vulners.os')
        } catch {
            $caught = $_
        }
        $caught | Should -BeNullOrEmpty
        $failed | Should -Contain 'vulners.os'
    }

    It 'reports a key as failed when the -t fallback prints unparseable output' {
        Mock Invoke-AgentKey { throw 'connection refused' }
        $fakeExe = Join-Path $script:tmp 'fake-agent2-broken.ps1'
        Set-Content -Path $fakeExe -Value @'
param($c, $t)
Write-Output "zabbix_agent2 [1234]: cannot open config file"
'@
        $failed = Invoke-SelfTest -Exe $fakeExe -ConfPath $script:conf -Keys @('vulners.os')
        $failed | Should -Contain 'vulners.os'
    }
}
