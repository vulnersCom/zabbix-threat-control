# AGENTS.md

Runbook for **integrating ztc into a Zabbix installation**. Written so an AI
assistant (or a human integrator) can take a client's Zabbix from zero to a
working vulnerability-management view. Each step has a command and a way to
verify it worked. For hacking on the ztc code itself, see
[Developing ztc](#developing-ztc) at the end and [`docs/guide.md`](docs/guide.md).

## What ztc does

`ztc` reads each host's software inventory through the stock **zabbix-agent2**,
audits it against [Vulners](https://vulners.com), and pushes **scored, per-host
findings** back into Zabbix as problems, a dashboard and CVSS graphs. It runs as
one static Linux binary and talks to Zabbix over the JSON-RPC API + zabbix-sender.

```
agent2 UserParameters ─► Zabbix items ─► ztc scan ─► Vulners audit ─► sender ─► Zabbix problems/dashboard
```

## Prerequisites

- **Zabbix 6.0 / 7.0 LTS or 8.0** — the API version is auto-detected; no per-version setup.
- **A Vulners API key** — from <https://vulners.com> (account → API keys).
- **zabbix-agent2 on every host you want scanned**, with the ztc UserParameter snippet:
  - Linux — [`deploy/agent/linux/vulners.conf`](deploy/agent/linux/vulners.conf):
    keys `vulners.os`, `vulners.version`, `vulners.arch`, `vulners.packages`, `vulners.fix[*]`.
  - Windows — [`deploy/agent/windows/vulners.conf`](deploy/agent/windows/vulners.conf):
    keys `vulners.os`, `vulners.version`, `vulners.win.software`, `vulners.win.kb`.
- **One Linux host (amd64/arm64) to run `ztc`** — reachable to the Zabbix API and
  to Vulners. The Zabbix server itself is a fine choice.

## 1. Install ztc

On the Linux host that will run ztc:

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh | sudo sh
```

The installer detects the arch, downloads the latest **stable** release, installs
`/usr/local/bin/ztc`, creates a `ztc` service user, writes `/etc/ztc/ztc.env`, and
installs a systemd unit. Alternatives (Docker, manual, air-gapped):
[`deploy/README.md`](deploy/README.md).

- **Verify:** `ztc version` prints a version.
- *Note:* releases marked *pre-release* are not resolved by "latest" — pin one
  with `ZTC_VERSION=vX.Y.Z ... | sudo sh` if needed.

## 2. Configure

Secrets go through environment variables (they override the YAML file). The
installer collects these into `/etc/ztc/ztc.env`; every knob is documented in
[`config.example.yaml`](config.example.yaml).

| Env | Required | Purpose |
|-----|:---:|---------|
| `VULNERS_API_KEY` | ✓ | Vulners API key |
| `ZABBIX_URL` | ✓ | Zabbix frontend URL (JSON-RPC API), e.g. `https://zbx.example.com` |
| `ZABBIX_TOKEN` | ✓* | API token (preferred; Zabbix 7.2+) … |
| `ZABBIX_USER` / `ZABBIX_PASSWORD` | ✓* | … or user + password (*one auth method required) |
| `ZABBIX_SERVER_FQDN` / `ZABBIX_SERVER_PORT` | ✓ | zabbix-sender target (server/proxy, trapper `10051`) |
| `VULNERS_BASE_URL` | | self-hosted / proxy Vulners endpoint |
| `VULNERS_CLIENT_CERT` / `VULNERS_CLIENT_KEY` | | mTLS client cert for a private Vulners |
| `ZTC_SCHEDULE` | | daemon scan interval (e.g. `24h`) |
| `ZTC_LOG_LEVEL` | | `debug` / `info` / `warn` / `error` |
| `ZTC_TRUSTED_USERS` | | comma-separated Zabbix usernames who may authorise `--auto-fix` (env form of `fix.trusted_users`) |
| `ZTC_MIN_CVSS` | | drop findings below this CVSS before creating objects — the main lever on object count (env form of `min_cvss`) |
| `ZABBIX_TRAPPER_HOSTS` | | `Allowed hosts` on the trapper items provision creates; unset = accept from any host (env form of `zabbix.trapper_hosts`) |

`ztc --help` lists the same set. The only settings with no env form are the
`entities.*` names of the group/templates/report hosts/dashboard — pass a YAML
file (`--config`) if you need to rename those.

## 3. Provision the Zabbix objects

```sh
ztc provision --all
```

Creates: the **Vulners** host group, two **collection templates** (Linux +
Windows), the four **report hosts** — `Vulners - Hosts`, `- Bulletins`,
`- Packages`, `- Statistics` — with their LLD rules, prototypes and CVSS-scored
triggers, and the **Vulners dashboard**. Granular flags exist:
`--template`, `--vhosts`, `--dashboard`.

Re-running it is a **reconciliation**, not a no-op: objects that already exist are
updated in place (trapper `Allowed hosts`, `value_type`, LLD severity overrides,
trigger prototypes) and the log names what changed. **Run it after every `ztc`
upgrade** — the new binary alone does not fix objects the old one created; see
[Upgrading an existing ztc install](docs/MIGRATION.md#upgrading-an-existing-ztc-install).

- **Verify:** *Data collection → Templates* shows `Template Vulners OS-Report Linux`/`… Windows`;
  *Monitoring → Dashboards → Vulners* exists.
- *Note:* with `zabbix.trapper_hosts` unset, provision logs a warning and sets
  `Allowed hosts` to `0.0.0.0/0,::/0` (accept from anywhere) — required for Zabbix
  8.0, which otherwise rejects ztc's pushes. Set it to ztc's source address to
  narrow that down.

## 4. Link the collection template to monitored hosts

This is what connects real hosts to ztc. For each host to be scanned, in
*Data collection → Hosts → <host> → Templates*, attach:

- `Template Vulners OS-Report Linux` — for Linux hosts, or
- `Template Vulners OS-Report Windows` — for Windows hosts.

The template's items poll the agent2 `vulners.*` UserParameters into Zabbix.

- **Verify:** `zabbix_get -s <host-ip> -k vulners.os` returns the OS (agent side);
  after a minute, *Monitoring → Latest data* for the host shows `vulners.*` values.

## 5. Scan and verify

```sh
ztc scan --once      # a single collect → audit → push cycle
ztc scan --daemon    # loop on `schedule` (default 24h); this is what the systemd unit runs
```

Useful flags: `--limit N` (first N hosts), `--nopush` (dry run, audit only),
`--push-delay D`, `--auto-fix` (see step 7).

- **Verify:** `systemctl status ztc` is active; *Monitoring → Problems* fills with
  `Vulners - …` problems within a scan cycle.

## 6. Read the results

*Monitoring → Dashboards → **Vulners*** gives you:

- **Problems by severity** — findings fire at Disaster / High / Average / Warning
  by their CVSS, so the breakdown is meaningful.
- **Vulners - Hosts / Packages / Bulletins** — per-report problem lists.
- **Median CVSS Score** trend and **CVSS Score ratio by hosts** pie.

Every finding is one **(vulnerability, host)** problem, carrying a `vulners.host`
tag. To see one host's vulnerabilities: *Monitoring → Problems → Filter →
Tags: `vulners.host` **Equals** `<host>`*.

## 7. Remediate (optional)

```sh
ztc fix --host <host> --package <pkg>   # upgrade one package
ztc fix --host <host> --all             # upgrade all vulnerable packages on the host
ztc fix ... --dry-run                   # preview only
```

Auto-fix: `ztc scan --daemon --auto-fix` upgrades a package when a **trusted user**
(`fix.trusted_users`) acknowledges its problem in Zabbix. Upgrades run through the
whitelisted `vulners.fix[<pkg>]` UserParameter drained by a host-side worker
([`deploy/agent/linux/vulners-fix-worker.sh`](deploy/agent/linux/vulners-fix-worker.sh)
+ cron) — never arbitrary `system.run`. Rationale:
[`docs/adr/0001-remediation-mechanism.md`](docs/adr/0001-remediation-mechanism.md).

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Report hosts stay empty | Collection template not linked (step 4), or agent2 lacks the `vulners.*` UserParameter. Test with `zabbix_get -s <host> -k vulners.os`. |
| `scan` audits but nothing appears | sender can't reach the trapper — check `ZABBIX_SERVER_FQDN`/`ZABBIX_SERVER_PORT` (10051) and that the report hosts exist. |
| `provision` auth errors | Wrong `ZABBIX_URL` or credentials; token needs API access; user needs write on the Vulners group/templates. |
| install: `could not resolve latest release` | Only pre-release tags exist — pin `ZTC_VERSION=vX.Y.Z`. |
| Windows host reports nothing | Smart Audit works on any Zabbix version; confirm `vulners.win.software`/`vulners.win.kb` return data via `zabbix_get`. |
| `Problems by severity` all "Not classified" | Old provisioned objects — re-run `ztc provision --all` to bring them up to date. |
| Nothing arrives after an **upgrade** (`scan cycle complete`, Zabbix empty); server log says `trap: connection from … rejected, allowed hosts: "127.0.0.1,::1"` | The Zabbix objects still carry the old `Allowed hosts`. Re-run `ztc provision --all` with the new binary — see [Upgrading an existing ztc install](docs/MIGRATION.md#upgrading-an-existing-ztc-install). |
| CVSS statistics show `9` instead of `9.8` (or `NOT SUPPORTED` on 6.0) | Same cause: statistics items provisioned as unsigned by an older ztc. `ztc provision --all` flips them to float. |
| Zabbix server OOM / `out of memory ... CacheSize` after a scan | Too many findings became objects (each kept (vuln, host) pair = 1 item + 1 trigger). Raise `min_cvss` / `ZTC_MIN_CVSS` (e.g. 7) to keep only higher-severity findings, and/or raise the server's `CacheSize`. One Windows host is worth ~5.7k items at `min_cvss: 1`. |

## Commands

```sh
ztc scan --daemon                 # run the scan loop on a schedule
ztc scan --once                   # a single cycle
ztc provision --all               # create group, templates, report hosts, dashboard
ztc fix --host H --package P      # remediate a package (whitelisted, opt-in)
ztc upgrade [--version vX.Y.Z]    # self-update the binary from GitHub Releases
ztc version [--check]             # print version (and check for a newer release)
```

## Developing ztc

This file is an integrator guide, not a contributor guide. If you are changing
ztc's code, read [`docs/guide.md`](docs/guide.md) for the architecture. In short:
external systems sit behind interfaces with test doubles (`vulners.Auditor`,
`zabbix.Client`); `audit`/`aggregate` are pure transforms with table-driven
tests; add a Zabbix version as a new `zabbix.Client`, never as branches in
business logic. Build/verify: `go build ./... && go test ./... && go vet ./... && gofmt -l .`.
