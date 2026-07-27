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
