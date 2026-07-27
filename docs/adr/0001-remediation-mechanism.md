# ADR 0001: Remediation mechanism (fix)

Status: accepted.

## Context

`ztc` finds vulnerabilities and surfaces them in Zabbix. Remediation ("fix") must run
a package-upgrade command on the target host. Project constraint: **monitored hosts run
only stock zabbix-agent2 — no Vulners code — and arbitrary `system.run` is not
enabled** (avoiding the RCE surface that motivated the move to UserParameters). The
original Python `fix.py` ran arbitrary commands via `zabbix_get system.run[<cmd>]` or
ssh, both of which violate this constraint.

An agent check is also time-bounded (agent `Timeout` ≤ 30 s) and agent2 terminates any
process a UserParameter backgrounds once the check returns — so a package upgrade
cannot run inside the UserParameter itself, synchronously or in the background.

## Decision

### Execution — spool + host worker

On each host that should be remediable:

1. A fixed agent key `vulners.fix[*]` only **appends the package name to a queue file**
   (instant, executes nothing):
   ```
   UserParameter=vulners.fix[*],printf '%s\n' '$1' >> /var/lib/zabbix/vulners-fix.queue && echo queued
   ```
2. A small worker (`vulners-fix-worker.sh`) runs under **root cron**
   (`/etc/cron.d/vulners-fix`, once a minute), atomically claims the queue, upgrades
   each package with the OS package manager, and appends to the audit log
   `/var/log/vulners-fix.log` (`START` / `END rc=…` per package).

`ztc` initiates a fix with a **passive agent request** for `vulners.fix[<pkg>]` on the
agent port (10050); the agent enqueues the package and the worker applies it.

Rationale:
- **Security is preserved.** The server/ztc cannot run an arbitrary command — only
  "enqueue package X for upgrade." The surface is "upgrade a package," as intended; no
  `system.run`.
- **Decoupled from the agent lifecycle.** The spool moves the (potentially long-running,
  privileged) upgrade out from under the agent's check timeout and process cleanup.
- **Worker runs as root cron**, which removes the need for sudoers and isolates the
  upgrade from the agent. It is a narrow remediation executor (it does no collection),
  installed only where auto-remediation is wanted.
- **No ssh** — reuses the already-deployed zabbix-agent2 transport, no extra keys/access.

Rejected alternatives:
- `system.run[<cmd>]` / `system.run[<cmd>,nowait]` — reintroduces `system.run` (even if
  whitelisted via AllowKey/DenyKey), weakening the core constraint; per-package AllowKey
  patterns are brittle.
- `systemd-run --no-block` from the UserParameter — clean and worker-free, but
  systemd-only (not OpenRC/alpine) and needs sudo for `systemd-run`. Viable as an
  alternative on all-systemd fleets.
- Backgrounding the upgrade from the UserParameter (`&` / `setsid` / `nohup`) — does not
  work; agent2 kills the process.

### Trigger — manual CLI + optional daemon auto-remediation

- **Manual (baseline):** `ztc fix --host X [--package Y | --all]`.
- **Auto (opt-in, `--auto-fix`):** the daemon reads problems on the Vulners board hosts,
  selects those acknowledged by a trusted user (`fix.trusted_users`) and not manually
  closed, and remediates them. Built on the manual primitive.
- **Zabbix action → `ztc fix`** — deferred; if needed, a thin wrapper over the same CLI.

### Granularity

- A single package/bulletin (`vulners.fix[pkg]`), or
- a whole host (cumulative fix — upgrade all of the host's vulnerable packages).

### Authorisation

For the event-driven path, a fix runs only if the acknowledgement was left by a user in
`fix.trusted_users` and the event was not manually closed. The manual CLI is the
operator's responsibility.

## Consequences

- A passive agent-protocol client (a `zabbix_get` equivalent) is implemented in
  `internal/zabbix/agentget`.
- On hosts that need remediation, deploy three files from `deploy/agent/linux/`:
  `vulners.conf` (the `vulners.fix` key → queue), `vulners-fix-worker.sh` →
  `/usr/local/bin/`, `vulners-fix.cron` → `/etc/cron.d/`. Sudoers is **not** needed.
- There is a delay of up to the cron interval (default 1 minute) between `ztc fix` and
  the actual upgrade.
- Windows remediation is out of scope for this iteration (a separate update mechanism);
  Linux only.
