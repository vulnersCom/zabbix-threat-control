# Migrating from the Python zabbix-threat-control to ztc (Go)

This guide takes an existing **Python** `zabbix-threat-control` install to the
new **Go** `ztc`. Both share the same Zabbix-side names (host group `Vulners`,
the `Vulners - *` report hosts, the `Vulners` dashboard), so the migration is
mostly: stand up `ztc`, remove the old objects/scripts, re-provision, and
re-instrument the scanned hosts with the stock agent keys.

> The original Python code is preserved in this repository's git history (the
> commits before the Go rewrite) and in the pre-Go release tags, for reference
> during the switch.

## What changes

| | Python (old) | ztc (new) |
|---|---|---|
| **Host data collection** | `report.py` deployed to every host in `/opt/monitoring/os-report/`, run by the agent (`EnableRemoteCommands=1`) | stock **zabbix-agent2** UserParameters `vulners.*` — nothing executable shipped to hosts |
| **Collection template** | one `tmpl.vulners.os-report` | two: `tmpl.vulners.os-report.linux` and `.windows` |
| **Scanner** | `scan.py` on a cron / agent item, config `ztc.conf` (INI) in `/opt/monitoring/…` | one binary `ztc scan --daemon` (systemd or Docker), config via env / YAML |
| **Remediation** | `fix.py` via a Zabbix **Action** + `system.run`/ssh + broad `zabbix` sudoers | whitelisted `vulners.fix[<pkg>]` key + host-side worker (root cron, **no sudoers, no Action**) |
| **Zabbix objects** | group, 1 template, report hosts, an **Action**, dashboard | same group / report hosts / dashboard, **2 templates, CVSS-scored triggers, `vulners.host` tags, no Action** |
| **Zabbix version** | 3.4+ | 6.0 / 7.0 / 8.0 (auto-detected) |

**Key consequence:** the report hosts and dashboard keep the **same names**, and
`ztc provision --all` does *not* overwrite pre-existing objects. So you must
**delete the old objects first** (Step 3), or provisioning will collide on
duplicate names.

## Before you start

- Your Zabbix must be **6.0, 7.0 or 8.0** (ztc's minimum). Upgrade Zabbix first
  if you are still on an older release.
- Pick the host that will run `ztc` — the Zabbix server itself is fine.
- Have the old `ztc.conf` handy; you will copy secrets out of it (Step 2).
- Nothing here is destructive to *monitoring data* beyond the Vulners view, which
  rebuilds on the next scan. Old problems on the deleted report hosts are lost.

## Step 1 — Install ztc

On the chosen host, install the binary and service (see
[`deploy/README.md`](../deploy/README.md) for Docker / manual options):

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh | sudo sh
```

Don't start scanning yet — finish the migration first. Verify with `ztc version`.

## Step 2 — Translate the config

`ztc` reads secrets from environment variables (the installer writes
`/etc/ztc/ztc.env`) and the rest from YAML ([`config.example.yaml`](../config.example.yaml)).
Map your old `ztc.conf` values across:

| Old `ztc.conf` | New env / YAML |
|---|---|
| `VulnersApiKey` | `VULNERS_API_KEY` |
| `VulnersProxyHost` | `VULNERS_BASE_URL` |
| `ZabbixFrontUrl` | `ZABBIX_URL` |
| `ZabbixApiUser` / `ZabbixApiPassword` | `ZABBIX_USER` / `ZABBIX_PASSWORD` (or a token in `ZABBIX_TOKEN`) |
| `ZabbixServerFQDN` / `ZabbixServerPort` | `ZABBIX_SERVER_FQDN` / `ZABBIX_SERVER_PORT` |
| `VerifySSL` | `zabbix.verify_ssl` (YAML) |
| `TrustedZabbixUsers` | `fix.trusted_users` (YAML) |
| `MinCVSS` | `min_cvss` (YAML) |
| `DashboardName`, `HostsHost`, `…Host`, `HostGroupName` | `entities.*` (YAML) — **defaults already match the old ones**, so leave them unless you customised the names |
| `WorkDir`, `LogFile`, `DebugLevel`, `ZabbixGet`, `ZabbixSender`, `SSHUser`, `UseZabbixAgentToFix`, `*ScriptPath/Cmd` macros | **dropped** — ztc is a single binary; logging is stdout/journald, remediation no longer shells out |

## Step 3 — Remove the old Zabbix objects

Run this once against your Zabbix API. It deletes the old report hosts (same
names ztc will recreate), the old single template, the old dashboard and the old
Action — and **keeps** the `Vulners` host group (ztc reuses it). Edit the three
values at the top first.

```python
#!/usr/bin/env python3
import json, urllib.request

URL  = "https://zabbix.example.com/api_jsonrpc.php"   # your ZABBIX_URL + /api_jsonrpc.php
USER = "Admin"
PASS = "zabbix"

def rpc(method, params, token=None, body_auth=False):
    req = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if token and method not in ("apiinfo.version", "user.login"):
        if body_auth:
            req["auth"] = token                              # Zabbix 6.0/6.2/5.x
        else:
            headers["Authorization"] = "Bearer " + token     # Zabbix 6.4+/7.x/8.x
    r = urllib.request.Request(URL, json.dumps(req).encode(), headers)
    resp = json.load(urllib.request.urlopen(r, timeout=30))
    if "error" in resp:
        raise SystemExit(f"{method}: {resp['error']}")
    return resp["result"]

ver = rpc("apiinfo.version", [])
body_auth = tuple(int(x) for x in (ver.split(".") + ["0", "0"])[:2]) < (6, 4)
tok = rpc("user.login", {("user" if body_auth else "username"): USER, "password": PASS})
def call(m, p): return rpc(m, p, tok, body_auth)

for host in ["vulners.hosts", "vulners.bulletins", "vulners.packages", "vulners.statistics"]:
    ids = [h["hostid"] for h in call("host.get", {"filter": {"host": host}, "output": ["hostid"]})]
    if ids: call("host.delete", ids); print("deleted host", host)

for tmpl in ["tmpl.vulners.os-report"]:  # old single template (unlinks it from scanned hosts)
    ids = [t["templateid"] for t in call("template.get", {"filter": {"host": tmpl}, "output": ["templateid"]})]
    if ids: call("template.delete", ids); print("deleted template", tmpl)

for dash in [d["dashboardid"] for d in call("dashboard.get", {"filter": {"name": "Vulners"}, "output": ["dashboardid"]})]:
    call("dashboard.delete", [dash]); print("deleted dashboard Vulners")

for act in [a["actionid"] for a in call("action.get", {"filter": {"name": "Vulners"}, "output": ["actionid"]})]:
    call("action.delete", [act]); print("deleted action Vulners")

print("done — old Vulners objects removed, host group 'Vulners' kept")
```

## Step 4 — Provision the new objects

```sh
ztc provision --all
```

Creates the two collection templates, the report hosts, the CVSS-scored triggers
and the new dashboard (severity overview + Median CVSS / score-distribution
graphs). See [`AGENTS.md`](../AGENTS.md) steps 3–6 for what you get.

## Step 5 — Re-instrument the scanned hosts

On **each** monitored host, swap the old push-a-script mechanism for the stock
agent keys:

1. Install the ztc UserParameter snippet into zabbix-agent2:
   - Linux: [`deploy/agent/linux/vulners.conf`](../deploy/agent/linux/vulners.conf) → `/etc/zabbix/zabbix_agent2.d/`
   - Windows: [`deploy/agent/windows/vulners.conf`](../deploy/agent/windows/vulners.conf)
   Restart the agent. Verify: `zabbix_get -s <host> -k vulners.os` returns the OS.
2. In Zabbix, **unlink** the old `Vulners OS-Report` template (already removed in
   Step 3) and **link** the new one to the host:
   - `Template Vulners OS-Report Linux` for Linux hosts, or
   - `Template Vulners OS-Report Windows` for Windows hosts.
3. You can now remove the old host agent bits: `/opt/monitoring/os-report/`, and —
   unless something else needs them — the `EnableRemoteCommands=1` /
   `LogRemoteCommands=1` lines from the agent config.

## Step 6 — Switch remediation (if you used fix.py)

The old Action-driven `fix.py` is gone. The new remediation:

- Deploy the host-side worker on hosts you want auto-fixed:
  [`deploy/agent/linux/vulners-fix-worker.sh`](../deploy/agent/linux/vulners-fix-worker.sh)
  → `/usr/local/bin/`, and
  [`deploy/agent/linux/vulners-fix.cron`](../deploy/agent/linux/vulners-fix.cron)
  → `/etc/cron.d/vulners-fix`. The worker runs as **root via cron**, so the old
  broad `zabbix` sudoers lines (`yum -y update *`, `apt-get … --only-upgrade *`)
  can be **removed**.
- Trigger fixes with `ztc fix --host H --package P`, or drive them from Zabbix by
  having a `fix.trusted_users` user acknowledge the problem and running
  `ztc scan --daemon --auto-fix`. Rationale:
  [`docs/adr/0001-remediation-mechanism.md`](adr/0001-remediation-mechanism.md).

## Step 7 — Decommission the old server-side

Once the new scan is confirmed (Step 8):

- Remove the old cron entry / agent item that ran `scan.py`.
- Delete `/opt/monitoring/zabbix-threat-control/` and `/opt/monitoring/os-report/`.
- If installed from packages, remove them:
  `yum remove zabbix-threat-control-main zabbix-threat-control-host` (RPM) or
  `apt-get remove zabbix-threat-control-main zabbix-threat-control-host` (DEB).
  Remove `zabbix-threat-control-host` on the scanned hosts too.
- Drop `/var/log/zabbix-threat-control.log`.

## Step 8 — Validate

```sh
ztc scan --once --push-delay 10s     # one full cycle
```

Then in Zabbix: *Monitoring → Dashboards → Vulners* fills in, *Problems* shows
`Vulners - …` findings scored by severity, and *Problems → Filter → Tags:
`vulners.host` Equals `<host>`* narrows to one host. Once happy, let the service
run the loop (`systemctl enable --now ztc`, or the Docker daemon).

## Rollback

The migration is reversible until you delete the old scripts (Step 7). If you
need to revert before then: stop the `ztc` service, re-run the old `prepare.py`
to recreate its objects, re-link the old `Vulners OS-Report` template, and
re-enable the old cron. Keep the old `ztc.conf` until the new setup has run
cleanly for a full cycle.
