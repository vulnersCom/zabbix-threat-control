# Test stand

A one-command environment: Zabbix 7.0 (server + web + Postgres + agent2) plus the
`ztc` scanner.

The `zabbix-agent2` service is built from `Dockerfile.agent` — an **Ubuntu 24.04 LTS**
host running zabbix-agent2 with the ztc remediation pieces installed as on a real host
(agent as the `zabbix` user; the `vulners.fix` worker under root cron). It ships a
deliberately **old, vulnerable `openssl` (3.0.13-0ubuntu3)** so the full
detect → fix → cleared cycle can be demonstrated. Zabbix's Ubuntu repository is
amd64-only, so on an arm64 host the agent runs emulated (`platform: linux/amd64`).

## Prerequisites

- Docker + Docker Compose.
- A Vulners API key (a real key is needed to get vulnerabilities).

## Bring up

```sh
cp .env.example .env      # set VULNERS_API_KEY
docker compose up -d --build
```

Web UI: <http://localhost:8080> — `Admin` / `zabbix`.

## Provision Zabbix entities

```sh
docker compose run --rm ztc provision --all   # collection templates, board hosts, dashboard
```

## Make the host scannable (UI)

The `zabbix-agent2` container is monitored as the built-in **Zabbix server** host. In
the UI (<http://localhost:8080>):

1. **Data collection → Hosts → Zabbix server → Templates** → link
   **Template Vulners OS-Report Linux** → **Update**.
2. **Same host → Interfaces** → switch the Agent interface to **DNS**, enter
   `zabbix-agent2` → **Update** (the default `127.0.0.1` is unreachable from the server
   container).

Collection items poll on their template interval (default `1d`). For a quick demo,
either lower the interval, or use **Monitoring → Latest data**, select the `vulners.*`
items, and click **Execute now** to fetch them immediately.

## Run a scan

```sh
docker compose run --rm ztc scan --once --push-delay 10s
```

Results appear on the four board hosts and the **Vulners** dashboard. With a
placeholder API key the audit returns HTTP 401 and hosts are skipped (collection still
works).

## Remediation (fix)

`ztc fix` queues a package on the agent; the root cron worker inside the agent
container drains the queue and upgrades the package, exactly as on a real host.

Full detect → fix → cleared cycle with the pre-installed old openssl:

```sh
# 1. DETECT — scan flags openssl (3.0.13-0ubuntu3, CVSS 9.8)
docker compose run --rm ztc scan --once --nopush

# 2. FIX — queue the upgrade
docker compose run --rm ztc fix --host "Zabbix server" --package openssl   # -> response=queued

# 3. the root cron worker upgrades within ~1 min; check the on-host audit log + version
docker compose exec zabbix-agent2 tail /var/log/vulners-fix.log            # START/END rc=0 openssl
docker compose exec zabbix-agent2 dpkg-query -W -f='${Version}\n' openssl  # 3.0.13-0ubuntu3.11

# 4. CLEARED — refresh the packages item (Execute now) and re-scan; openssl is gone
docker compose run --rm ztc scan --once --nopush
```

Paths are the production defaults (`/var/lib/zabbix/vulners-fix.queue`,
`/var/log/vulners-fix.log`).

## Reset (run from scratch)

Zabbix state (templates/hosts/dashboard, links, item intervals) lives in the Postgres
volume; the agent's package state lives in its container. To replay everything —
including the Zabbix setup — from zero:

```sh
docker compose down -v                            # wipe the DB volume -> fresh Zabbix
docker compose up -d --build --force-recreate     # fresh DB + agent (old openssl reinstalled)
# wait for the API (~1-2 min), then repeat "Provision" and "Make the host scannable"
```

## Tear down

```sh
docker compose down -v
```

## Note on the agent include path

`Dockerfile.agent` copies `vulners.conf` to `/etc/zabbix/zabbix_agent2.d/vulners.conf`,
which `zabbix_agent2.stand.conf` pulls in via `Include=/etc/zabbix/zabbix_agent2.d/*.conf`
— the same include directory used on a normal zabbix-agent2 install.
