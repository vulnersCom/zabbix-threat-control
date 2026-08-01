#!/bin/sh
# Runs as root (PID 1): start the cron daemon that drains the vulners.fix spool,
# then drop to the zabbix user for the agent — so the agent runs unprivileged
# while the remediation worker runs as root, mirroring a real host.
set -e

mkdir -p /run/zabbix && chown zabbix:zabbix /run/zabbix 2>/dev/null || true

cron            # vixie cron daemon (backgrounds itself)

exec runuser -u zabbix -- "$@"
