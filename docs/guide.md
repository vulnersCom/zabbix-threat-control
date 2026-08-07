# ztc — how it works

A plain-language explanation of the architecture, annotated config examples, and an
FAQ. No prior Zabbix knowledge assumed.

---

## 1. Zabbix mini-glossary

A few terms are enough to follow the rest:

| Term | In plain words |
|---|---|
| **Zabbix server** | The monitoring brain: polls hosts, stores data, evaluates triggers. |
| **Zabbix agent (agent2)** | A program on the monitored machine that answers the server's requests. |
| **Host** | A record in Zabbix for one machine (address + a set of metrics). |
| **Item** | One metric of a host; it has a **key** (e.g. `vulners.os`) and a value. |
| **Key** | The metric's name. The server sends a key to the agent; the agent returns a value. |
| **UserParameter** | A custom agent key: "when asked for key X, run command Y." |
| **Template** | A set of items; link it to a host and the host gains those metrics. |
| **Trapper** | An item that receives data pushed **from outside** (not polled). ztc writes results this way. |
| **LLD (low-level discovery)** | Auto-creates items from a list (e.g. one per vulnerable package). |
| **Problem / Trigger** | A rule "if the value is X, this is a problem"; problems show in the UI. |
| **Passive / Active** | Passive — the server polls the agent (this project). Active — the agent pushes. |

---

## 2. Overall scheme

```
                                            ┌───────────────┐
                                    (3)     │  Vulners API  │
                          ┌─────────────────►               │  audit: packages -> vulns
                          │                 └───────────────┘
                    ┌─────┴──────┐
                    │    ztc     │  (single central service)
                    │ scan/prov/ │
                    │    fix     │
                    └─┬───┬───┬──┘
             (2) API  │   │   │  (5) fix: vulners.fix[pkg]
        read inventory│   │   └───────────────────────────┐
           provision  │   │ (4) push results (sender)      │
                      ▼   ▼                                ▼
             ┌──────────────────┐  10051         ┌──────────────────────┐
             │  Zabbix (web/API │                │  zabbix-agent2        │
             │  + server + DB)  │                │  on a monitored host  │
             └─────────┬────────┘                │  vulners.os/packages  │
                       │  (1) poll (daily)        │  vulners.fix[*]       │
                       └────────────────────────►│  :10050               │
                          inventory collection    └──────────────────────┘
```

Who connects to whom:

| Arrow | From → To | Port / protocol | When |
|---|---|---|---|
| (1) | **Zabbix server** → agent2 | 10050, passive poll | on the item interval (default daily) — **collects packages** |
| (2) | ztc → **Zabbix API** (web) | 80/443 (8080 in the stand), JSON-RPC | scan (read inventory), provision |
| (3) | ztc → **Vulners API** | 443 | scan (audit) |
| (4) | ztc → **Zabbix server** | 10051, sender (trapper) | scan (push results) |
| (5) | ztc → **agent2** | 10050 | **fix only** (`vulners.fix[pkg]`) |

Commonly confused:
- **The Zabbix server collects packages (step 1), not ztc.** ztc only **reads** them
  back through the Zabbix API (step 2).
- ztc contacts an agent directly (step 5) **only for remediation**, never to collect.

Roles (do not mix up):
- **agent2 on hosts** — answers polls (inventory collection; replaces the old Vulners
  agent) and accepts `vulners.fix`.
- **ztc** — the brain, running in one place; the only component that talks to Vulners.
- **worker (root cron on the host)** — the only component that installs upgrades (`fix`).

Step by step:
1. The Zabbix server polls the agent's `vulners.*` keys on schedule → OS/packages are
   stored in the host's items.
2. ztc reads those values via the Zabbix API.
3. ztc sends them to Vulners → gets the list of vulnerabilities.
4. ztc aggregates and pushes results back to Zabbix (trapper, :10051) — visible on the
   "board" hosts (`Vulners - Hosts/Packages/Bulletins/Statistics`) and the dashboard.
5. (remediation) `ztc fix` sends `vulners.fix[pkg]` to the agent (:10050) → the package
   lands in an on-host queue → a root cron worker performs the upgrade.

---

## 3. UserParameters — how inventory is collected

A line in the agent config:

```ini
UserParameter=<key>,<shell-command>
```

Meaning: "when someone asks for `<key>`, run `<shell-command>` and return its stdout as
the value." Test it locally on the host:

```sh
zabbix_agent2 -t vulners.os
# vulners.os   [s|ubuntu]
```

The project's keys (`deploy/agent/linux/vulners.conf`):

```ini
# OS, version, architecture — from standard Linux files
UserParameter=vulners.os,. /etc/os-release 2>/dev/null; echo "$ID"
UserParameter=vulners.version,. /etc/os-release 2>/dev/null; echo "$VERSION_ID"
UserParameter=vulners.arch,uname -m

# Package list — via the native package manager (deb/rpm/apk)
UserParameter=vulners.packages,if command -v dpkg-query >/dev/null 2>&1; then \
  dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\n' \
  | awk '($1=="install"||$1=="hold")&&($2=="ok"){print $4" "$5" "$6}'; \
  elif command -v rpm >/dev/null 2>&1; then rpm -qa; \
  elif command -v apk >/dev/null 2>&1; then apk info -v; fi
```

Key points:
- These are plain keys (no `[*]`) — "run a command." The commands are **read-only**;
  no root needed.
- The server can invoke **only** these predefined keys. It cannot run an arbitrary
  command — that is the security boundary (unlike `system.run[*]`).
- Example `vulners.packages` value (one line per package):
  ```
  openssl 3.0.13-0ubuntu3 amd64
  bash 5.2.21-2ubuntu4 amd64
  ...
  ```

### Flexible key with an argument (for `fix`)

```ini
UserParameter=vulners.fix[*],Q=${VULNERS_FIX_QUEUE:-/var/lib/zabbix/vulners-fix.queue}; \
  printf '%s\n' '$1' >> "$Q" && echo queued || echo error
```

- `[*]` means the key takes an argument. `vulners.fix[openssl]` → `$1` = `openssl`.
- Zabbix substitutes `$1` **before** running. With `UnsafeUserParameters=0` (the
  default) the agent **rejects** shell metacharacters (`; | & $ …`) in the argument, so
  a command cannot be injected — only a package name gets through.
- This command installs nothing; it only **appends the package name to a queue file**.
  See section 6 for why.

---

## 4. What goes where (file map)

**On every monitored Linux host** (nothing else; no Vulners code):

| File | Destination | Purpose |
|---|---|---|
| `deploy/agent/linux/vulners.conf` | `/etc/zabbix/zabbix_agent2.d/` | collection keys + `vulners.fix` |
| `deploy/agent/linux/vulners-fix-worker.sh` | `/usr/local/bin/` | upgrade worker (only if fix is used) |
| `deploy/agent/linux/vulners-fix.cron` | `/etc/cron.d/` | runs the worker every minute (root) |

**On every monitored Windows host:**

| File | Destination | Purpose |
|---|---|---|
| `deploy/agent/windows/install-agent.ps1` | run once, elevated | puts the file below in place, fixes `Include=`, restarts the agent, self-tests |
| `deploy/agent/windows/vulners.conf` | the agent's include directory | collection keys + `Timeout` |

Detection works on Windows; automatic remediation does not. There is no
`vulners.fix` equivalent — see
[ADR 0001](adr/0001-remediation-mechanism.md) and section 5.3.

**Centrally (once, anywhere with access to Zabbix and Vulners):**

| File | Purpose |
|---|---|
| `config.yaml` (or env) | ztc settings |
| `ztc` binary | the service itself (scan/provision/fix) |

---

## 5. Config examples

### 5.1 ztc config (`config.yaml`)

Only the secrets are required; everything else has sensible defaults. Prefer supplying
secrets via environment variables.

```yaml
vulners:
  api_key: ""            # Vulners API key (or env VULNERS_API_KEY)
  base_url: ""           # empty = https://vulners.com; can point to a proxy / self-hosted endpoint
  timeout: 30s
  retries: 3

zabbix:
  url: http://zabbix.example.com   # Zabbix frontend URL (also serves the JSON-RPC API)
  token: ""                        # API token (Zabbix 7.2+), or...
  user: Admin                      # ...user + password (env ZABBIX_USER/ZABBIX_PASSWORD)
  password: zabbix
  verify_ssl: true
  server_fqdn: zabbix.example.com  # where to push results (zabbix-sender), usually the server
  server_port: 10051               # server trapper port

fix:
  key: vulners.fix                 # remediation key name on agents
  trusted_users: [ Admin ]         # whose acknowledgement authorises auto-fix
  agent_port: 10050                # agent port ztc sends vulners.fix to
  agent_timeout: 60s

min_cvss: 1                        # drop findings below this before creating objects
schedule: 24h                      # daemon scan interval
log_level: info
```

Minimal run with no file, env only:

```sh
export VULNERS_API_KEY=xxxxx
export ZABBIX_URL=http://zabbix.example.com
export ZABBIX_USER=Admin ZABBIX_PASSWORD=secret
export ZABBIX_SERVER_FQDN=zabbix.example.com
ztc scan --once
```

### 5.2 Linux agent snippet (`/etc/zabbix/zabbix_agent2.d/vulners.conf`)

Full contents are in section 3. Install on a host:

```sh
sudo cp vulners.conf /etc/zabbix/zabbix_agent2.d/
sudo systemctl restart zabbix-agent2
zabbix_agent2 -t vulners.packages | head    # sanity check: package lines
```

The agent must also **allow polling** from the server's address (and from ztc, for
fix). In `/etc/zabbix/zabbix_agent2.conf`:

```ini
Server=10.0.0.5            # Zabbix server IP (and ztc, if fix is sent from ztc)
# a list/subnet also works: Server=10.0.0.5,10.0.0.6
```

### 5.3 Windows agent (`install-agent.ps1` + `vulners.conf`)

Windows hosts report four keys. Software comes from the registry Uninstall keys
in both the 64- and 32-bit views; installed updates come from `Get-HotFix`:

| Key | Returns | Feeds |
|---|---|---|
| `vulners.os` | `Win32_OperatingSystem.Caption`, e.g. `Microsoft Windows 11 Pro` | OS family |
| `vulners.version` | the build version, e.g. `10.0.26100` | OS family |
| `vulners.win.software` | one `Name Version` line per installed product | `v4/audit/smart` |
| `vulners.win.kb` | one KB identifier per line | `v3/audit/kb` |

Install from the unpacked release archive, in an **elevated** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File install-agent.ps1
```

The script finds the `Zabbix Agent 2` service and the config it was started
with, copies `vulners.conf` into the agent's include directory, adds an
`Include=` line to the main config only when none covers that directory (keeping
a `.bak`), restarts the service, and then queries all four keys over
`127.0.0.1:10050` — the running service, not a separate process, because only
that proves the agent actually loaded the file. If the agent fails to come back
up it puts everything back and says so. Run it again and it does nothing:
that is what makes it safe as a GPO startup script.

Useful switches: `-Check` (diagnose, change nothing; exit code 0 only when the
host is fully configured, so it doubles as a health probe), `-Uninstall`,
`-ConfSource <path|url>`, `-IncludeDir`, `-ServiceName`, `-Timeout <seconds>`,
`-LogPath <file>`, `-WhatIf`.

Three things worth knowing before you run it:

- **It is not quick.** Stopping agent2 on a live host takes 15–30 seconds, so a
  run that changes anything takes roughly a minute. That is the agent, not the
  script.
- **`Timeout=30` ships in `vulners.conf`** and applies to the whole agent, not
  just these keys. `Get-HotFix` reads WMI and does not fit in the 3 s default;
  without this the server reports "Timeout occurred while gathering data" for
  `vulners.win.kb`. If your main config sets a lower `Timeout`, the script warns
  rather than editing a file that GPO or Ansible probably owns.
- **Two copies of the keys stop the agent dead.** agent2 refuses to start on a
  duplicate `UserParameter`, and its log names the key but not the file. If an
  older manual install left a copy anywhere the config includes — `plugins.d` is
  the classic hiding place — the script finds it and prints the path before
  touching anything.

Verify from the server side: link `Template Vulners OS-Report Windows` to the
host and watch the four items in *Latest data*. They poll **daily**, so use
*Execute now* if you do not want to wait.

### 5.4 Remediation: worker + cron (only where fix is used)

`/etc/cron.d/vulners-fix`:

```cron
# run the worker every minute as root
* * * * * root /usr/local/bin/vulners-fix-worker.sh
```

The worker (`vulners-fix-worker.sh`) reads the queue
`/var/lib/zabbix/vulners-fix.queue`, upgrades each package
(`apt-get --only-upgrade` / `yum update` / `apk upgrade`), and appends to
`/var/log/vulners-fix.log`. It runs as root, so no sudoers rules are needed.

Check on the host:

```sh
cat /var/lib/zabbix/vulners-fix.queue     # what is queued
tail -f /var/log/vulners-fix.log          # START <pkg> / output / END rc=<code>
```

### 5.5 What `ztc provision` does

One command creates everything in Zabbix (no manual setup):

```sh
ztc provision --all
```

- **collection templates** (Linux and Windows) with `vulners.*` items;
- **four board hosts**: `Vulners - Hosts / Packages / Bulletins / Statistics`;
- **triggers** (problem when score ≥ `min_cvss`) and a **dashboard**.

You then only **link the template** to your real hosts (UI: Data collection → Hosts →
host → Templates) so they expose the `vulners.*` keys.

Re-running it reconciles: objects that exist are updated to what this version of
ztc expects, not skipped. That is what makes an upgrade land — run
`ztc provision --all` after every `ztc upgrade`
([`docs/MIGRATION.md`](MIGRATION.md#upgrading-an-existing-ztc-install)).

---

## 6. Why `fix` goes through a queue (not directly)

Reasonable question: why doesn't `vulners.fix[openssl]` just run `apt upgrade` in the
agent? Two reasons:
1. An agent check is bounded by `Timeout` (≤30 s), but an upgrade often takes longer.
2. zabbix-agent2 **kills** any process a UserParameter backgrounds as soon as the check
   returns — `&`, `nohup`, `setsid` do not survive it.

So the key only **appends the package name to a queue** (instant), and a separate root
cron worker on the same host drains the queue and performs the upgrade. This is
reliable, auditable (log), and needs no arbitrary `system.run`.

```
ztc fix openssl ──► agent: echo openssl >> queue ──► (within ~1 min)
                                                     cron: worker → apt upgrade → log
```

---

## 7. FAQ

**Do hosts need a "Vulners agent"?** No. Only stock zabbix-agent2 + a text config.
Calls to the Vulners API happen only from the central ztc.

**Is `system.run` required?** No — neither for collection nor for fix.

**What privileges are needed on a host?** Collection is read-only, no sudo. Fix uses a
root cron worker (no sudo needed), installed only where auto-remediation is wanted.

**What access does ztc need?** Zabbix API (read + provision), the server trapper port
(10051), and the Vulners API. For fix, also the agent port (10050) of target hosts.

**How often is data refreshed?** Collection — the item interval in the template
(default daily). ztc scanning — `schedule`/`ZTC_SCHEDULE` (daemon) or an external cron.

**What is sent to Vulners?** OS name/version + the package list (for Windows, software
strings and the KB list). Logs and application data are not sent.

**Host offline / agent didn't answer?** Its item has no fresh value — ztc skips that
host and processes the rest.

**How do I confirm a fix actually applied?** On the host: the queue
`/var/lib/zabbix/vulners-fix.queue` and the log `/var/log/vulners-fix.log`; the package
version (`dpkg -l <pkg>` / `rpm -q <pkg>`) before/after; on the next scan the finding
disappears.

**Windows?** Detection works (registry software → smart-audit, KBs → winaudit);
set a host up with the installer in section 5.3. Automatic remediation does not
— the `vulners.fix` flow in section 6 is Linux-only.

**Does it scale to many hosts?** Yes: ztc is a single node reading data in batches via
the API; collection is distributed across agents. The main cost is Vulners API calls
(batched).

**Older Zabbix versions?** 7.x is implemented; Zabbix access sits behind an interface,
so 6.0/5.0 can be added as separate implementations without rewriting the logic.

**Why is a package still listed after upgrading?** Either the item hasn't refreshed yet
(use Execute now / wait for the poll), or the CVE has no fixed version ("won't-fix") —
then an upgrade cannot clear it; that is a property of the data, not a bug.
