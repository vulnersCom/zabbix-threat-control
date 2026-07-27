#!/bin/sh
# vulners-fix-worker — processes the vulners.fix remediation spool.
#
# The zabbix-agent2 vulners.fix[<pkg>] UserParameter appends package names to a
# spool file (agent2 kills anything a UserParameter backgrounds, so the upgrade
# cannot run there). This worker, run by root cron, claims the spool atomically,
# upgrades each queued package with the OS package manager, and appends the full
# output to an audit log. See docs/adr/0001-remediation-mechanism.md.
#
# Install:
#   cp vulners-fix-worker.sh /usr/local/bin/ && chmod 755 /usr/local/bin/vulners-fix-worker.sh
#   cp vulners-fix.cron /etc/cron.d/vulners-fix
#
# Verify: tail -f /var/log/vulners-fix.log
set -u

QUEUE="${VULNERS_FIX_QUEUE:-/var/lib/zabbix/vulners-fix.queue}"
LOG="${VULNERS_FIX_LOG:-/var/log/vulners-fix.log}"

[ -s "$QUEUE" ] || exit 0

# Atomically claim the queue so packages enqueued while we work are not lost.
WORK="${QUEUE}.processing.$$"
mv "$QUEUE" "$WORK" 2>/dev/null || exit 0

# Refresh package metadata once so --only-upgrade sees current security versions.
if command -v apt-get >/dev/null 2>&1; then
	apt-get update -qq >>"$LOG" 2>&1 || true
fi

upgrade() {
	pkg=$1
	if command -v apt-get >/dev/null 2>&1; then
		apt-get --assume-yes install --only-upgrade "$pkg"
	elif command -v yum >/dev/null 2>&1; then
		yum -y update "$pkg"
	elif command -v apk >/dev/null 2>&1; then
		apk upgrade "$pkg"
	elif command -v zypper >/dev/null 2>&1; then
		zypper --non-interactive update "$pkg"
	else
		echo "no supported package manager found" >&2
		return 1
	fi
}

# Deduplicate queued packages (order is irrelevant for upgrades).
sort -u "$WORK" | while IFS= read -r pkg; do
	[ -n "$pkg" ] || continue
	echo "$(date '+%F %T') START $pkg" >>"$LOG"
	upgrade "$pkg" >>"$LOG" 2>&1
	echo "$(date '+%F %T') END rc=$? $pkg" >>"$LOG"
done

rm -f "$WORK"
