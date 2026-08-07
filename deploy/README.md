# Deploying ztc

`ztc` is a single static binary. It runs anywhere that can reach your Zabbix
frontend (API) + server (trapper) and the Vulners API — typically on the Zabbix
server host or a small VM. Pick one of the methods below.

Prerequisites: a **Vulners API key**, your **Zabbix URL** + an **API token**
(or user/password), and the **Zabbix server** host/port for zabbix-sender.

---

## 1. One command (recommended)

Installs the binary, writes `/etc/ztc/ztc.env`, and runs it as a systemd service.

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh | sudo sh
```

It prompts for the connection details, then offers to run `ztc provision --all`
(creates the templates, dashboard and report hosts in Zabbix).

**Non-interactive** (automation) — pass everything via env:

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh -o install.sh
sudo VULNERS_API_KEY=... ZABBIX_URL=http://zbx:8080 ZABBIX_TOKEN=... \
     ZABBIX_SERVER_FQDN=zbx ZTC_PROVISION=1 sh install.sh
```

Manage it: `systemctl status ztc` · `journalctl -u ztc -f` · config in `/etc/ztc/ztc.env`.

---

## 2. Docker

Run just the scanner against your existing Zabbix (see `docker/compose.prod.yml`):

```sh
cd deploy/docker
cp ztc.env.example ztc.env        # fill in Vulners key + Zabbix connection
docker compose -f compose.prod.yml run --rm ztc provision --all   # one-time
docker compose -f compose.prod.yml up -d                          # start the daemon
```

Image: `ghcr.io/vulnerscom/zabbix-threat-control:latest` (or build from source).

---

## 3. Manual (binary + systemd)

For hosts without the installer script:

```sh
# grab the binary from the Releases page (linux amd64/arm64), then:
sudo install -m0755 ztc /usr/local/bin/ztc
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ztc
sudo install -d /etc/ztc
sudo install -m600 -o ztc /dev/stdin /etc/ztc/ztc.env <<'ENV'
VULNERS_API_KEY=...
ZABBIX_URL=http://zbx:8080
ZABBIX_TOKEN=...
ZABBIX_SERVER_FQDN=zbx
ZABBIX_SERVER_PORT=10051
ZTC_SCHEDULE=1h
# optional: ZTC_MIN_CVSS=7  ZTC_TRUSTED_USERS=Admin  ZABBIX_TRAPPER_HOSTS=10.0.0.7
ENV
sudo cp deploy/systemd/ztc.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ztc
```

---

## 4. Advanced: bootstrap via Zabbix (no SSH)

You can kick off the installer from Zabbix itself (agent already deployed) — but
this only works under specific conditions, so treat it as advanced:

- The target must reach GitHub (`raw.githubusercontent.com`, `github.com`) —
  check outbound/proxy rules.
- The step that installs to `/usr/local/bin` + systemd needs **root**; the agent
  runs as the unprivileged `zabbix` user. So run it via a **Zabbix global script**
  (Administration → Scripts) executing *on the Zabbix server* with sufficient
  privileges, or via an agent whose `system.run` is enabled **and** allowed to
  escalate. Neither is on by default.

Global-script command (Execute on: Zabbix server):

```sh
curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh | \
  VULNERS_API_KEY={$VULNERS_API_KEY} ZABBIX_URL=http://localhost:8080 ZABBIX_TOKEN=... ZTC_PROVISION=1 sh
```

If your environment forbids remote command execution or outbound internet, use
method 1 or 2 instead (download the binary/image once, then install offline).

---

## Monitored Windows hosts

`ztc` itself runs on Linux; the hosts it scans can be either. A Windows host
needs zabbix-agent2 (from the official MSI) plus the Vulners UserParameters.
Both files ship in the release archive under `deploy/agent/windows/`. From that
directory, in an **elevated** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File install-agent.ps1
```

It installs `vulners.conf` into the agent's include directory, adds an
`Include=` line only if none covers it, restarts the agent and self-tests the
four keys. `-Check` diagnoses without changing anything and exits 0 only when
the host is fully configured; `-Uninstall` removes the drop-in. Switches and
caveats: [`docs/guide.md` §5.3](../docs/guide.md).

Expect a run that changes something to take about a minute — stopping agent2
takes 15–30 seconds on a live host.

### Rolling it out with GPO

Put `install-agent.ps1` and `vulners.conf` on a share every computer account can
read (SYSVOL, or a file server with `Domain Computers: Read`). Add a **computer**
startup script — Computer Configuration → Policies → Windows Settings → Scripts →
Startup → PowerShell Scripts — pointing at the script on the share, with
parameters:

```
-ConfSource \\dc01\netlogon\ztc\vulners.conf -LogPath C:\Windows\Temp\vulners-install.log
```

Startup scripts run as SYSTEM, which is already elevated. On a healthy host the
script costs one key query and exits without touching the service, so leaving
the policy in place also repairs hosts where someone removed the drop-in. A host
that cannot answer that query is not healthy, and there the script reinstalls
and restarts the agent on every boot until someone looks at it — check
`-LogPath` before assuming a reboot loop is the script misbehaving. The tradeoff
of a startup script is that hosts pick it up on reboot; use a scheduled task via
Group Policy Preferences if that is too slow.

`-Check` exits 0 only on a fully configured host, so it works as a rollout
health probe.

### Rolling it out with SCCM / Intune

Package both files together.

| Setting | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install-agent.ps1` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File install-agent.ps1 -Uninstall` |
| Detection rule | file `vulners.conf` exists in the agent's include directory (stock MSI: `C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\vulners.conf`) |
| Context | System — the script refuses to run unelevated |

Exit code 0 means success or "already current". 1 means it did not finish —
check the log. It does **not** mean nothing changed. The installer rolls back
when the agent fails to come back up, when a write or config edit fails, and
when the self-test fails with the agent down; but a self-test failure with the
agent still **running** deliberately leaves the drop-in and any `Include=` edit
in place, so the host stays debuggable. An incomplete rollback also reports
itself and leaves partial state. Add `-LogPath` to keep that log.

One failure mode is worth knowing before a fleet-wide push: agent2 refuses to
start if two files declare the same `UserParameter`, and its own log names the
key but not the file. If an earlier manual install left a copy of `vulners.conf`
anywhere the agent's config includes — `plugins.d` is the usual place — the
installer detects it and prints the path instead of installing on top of it.

---

## Upgrading

Whichever method you used, an upgrade is **two** steps — the binary and the Zabbix
objects it provisioned:

```sh
sudo ztc upgrade                                                     # or: docker compose pull
sudo -u ztc env $(cat /etc/ztc/ztc.env | xargs) ztc provision --all  # reconcile the objects
sudo systemctl restart ztc
```

`provision --all` updates the objects it owns in place and logs what changed.
Skipping it leaves the old behaviour in Zabbix — on Zabbix 8.0 that means the
scanner reports success while the server rejects every push. Details:
[`docs/MIGRATION.md`](../docs/MIGRATION.md#upgrading-an-existing-ztc-install).
