#!/bin/sh
# ztc installer — one-command setup on a Zabbix server (or any Linux host).
#
# Interactive:
#   curl -fsSL https://raw.githubusercontent.com/vulnersCom/zabbix-threat-control/master/deploy/install.sh | sudo sh
#
# Non-interactive (CI/Ansible): pass config via env, e.g.
#   curl -fsSL .../deploy/install.sh -o install.sh
#   sudo VULNERS_API_KEY=xxx ZABBIX_URL=http://zbx:8080 ZABBIX_TOKEN=yyy ZTC_PROVISION=1 sh install.sh
#
# Recognised env: ZTC_VERSION, VULNERS_API_KEY, VULNERS_BASE_URL, ZABBIX_URL,
#   ZABBIX_TOKEN | (ZABBIX_USER + ZABBIX_PASSWORD), ZABBIX_SERVER_FQDN,
#   ZABBIX_SERVER_PORT, ZTC_SCHEDULE, ZTC_PROVISION (1 to run provision --all).
set -eu

REPO="zzeloff/zabbix-threat-control"
BIN_DIR="/usr/local/bin"
CFG_DIR="/etc/ztc"
ENV_FILE="$CFG_DIR/ztc.env"
UNIT="/etc/systemd/system/ztc.service"
SVC_USER="ztc"

info() { echo "==> $*"; }
err()  { echo "ztc-install: $*" >&2; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

# --- prerequisites ---
[ "$(uname -s)" = "Linux" ] || err "this installer supports Linux only"
[ "$(id -u)" = "0" ]        || err "run as root (e.g. via sudo)"
has systemctl               || err "systemd (systemctl) is required"
if has curl; then DL="curl -fsSL"; dlo() { curl -fsSL -o "$1" "$2"; }
elif has wget; then DL="wget -qO-"; dlo() { wget -qO "$1" "$2"; }
else err "need curl or wget"; fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "unsupported architecture '$ARCH' (linux amd64/arm64 only)" ;;
esac

# --- resolve version ---
VERSION="${ZTC_VERSION:-}"
if [ -z "$VERSION" ]; then
  info "resolving latest release"
  VERSION=$($DL "https://api.github.com/repos/$REPO/releases/latest" \
            | grep -m1 '"tag_name"' | cut -d'"' -f4)
  [ -n "$VERSION" ] || err "could not resolve latest release; set ZTC_VERSION=vX.Y.Z"
fi
NUM=${VERSION#v}

# --- download, verify, install ---
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
TAR="ztc_${NUM}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
info "downloading $TAR ($VERSION)"
dlo "$TMP/$TAR" "$BASE/$TAR"
if dlo "$TMP/checksums.txt" "$BASE/checksums.txt" && has sha256sum; then
  info "verifying checksum"
  ( cd "$TMP" && grep " $TAR\$" checksums.txt | sha256sum -c - >/dev/null ) \
    || err "checksum verification failed"
fi
tar -xzf "$TMP/$TAR" -C "$TMP" ztc
install -m 0755 "$TMP/ztc" "$BIN_DIR/ztc"
info "installed $("$BIN_DIR/ztc" version) -> $BIN_DIR/ztc"

# --- service user + config dir ---
if ! id "$SVC_USER" >/dev/null 2>&1; then
  NOLOGIN=/usr/sbin/nologin; [ -x /sbin/nologin ] && NOLOGIN=/sbin/nologin
  useradd --system --no-create-home --shell "$NOLOGIN" "$SVC_USER"
fi
mkdir -p "$CFG_DIR"

# --- gather config (env, else prompt on the terminal) ---
# read from /dev/tty because stdin is the curl pipe under `curl | sh`.
ask() { # ask VAR "prompt" [default] [secret]
  _var=$1; _txt=$2; _def=${3:-}; _sec=${4:-}
  eval "_cur=\${$_var:-}"
  [ -n "$_cur" ] && return 0
  if [ ! -e /dev/tty ]; then
    [ -n "$_def" ] && { eval "$_var=\$_def"; return 0; }
    err "$_var is unset and there is no terminal — set it via env for non-interactive install"
  fi
  if [ -n "$_sec" ]; then
    printf "%s: " "$_txt" >/dev/tty
    stty -echo 2>/dev/null </dev/tty || true; read -r _val </dev/tty
    stty echo 2>/dev/null </dev/tty || true; printf "\n" >/dev/tty
  else
    if [ -n "$_def" ]; then printf "%s [%s]: " "$_txt" "$_def" >/dev/tty
    else printf "%s: " "$_txt" >/dev/tty; fi
    read -r _val </dev/tty; [ -z "$_val" ] && _val=$_def
  fi
  eval "$_var=\$_val"
}

ask VULNERS_API_KEY   "Vulners API key" "" secret
ask ZABBIX_URL        "Zabbix frontend URL" "http://localhost"
ask ZABBIX_TOKEN      "Zabbix API token (empty = use user/password)" ""
if [ -z "${ZABBIX_TOKEN:-}" ]; then
  ask ZABBIX_USER     "Zabbix user" "Admin"
  ask ZABBIX_PASSWORD "Zabbix password" "" secret
fi
ask ZABBIX_SERVER_FQDN "Zabbix server host (for zabbix-sender)" "localhost"
ask ZABBIX_SERVER_PORT "Zabbix server trapper port" "10051"
ask ZTC_SCHEDULE       "Scan interval" "1h"

# --- write env file (secrets live here, mode 600) ---
umask 077
{
  echo "VULNERS_API_KEY=$VULNERS_API_KEY"
  [ -n "${VULNERS_BASE_URL:-}" ] && echo "VULNERS_BASE_URL=$VULNERS_BASE_URL"
  echo "ZABBIX_URL=$ZABBIX_URL"
  [ -n "${ZABBIX_TOKEN:-}" ]    && echo "ZABBIX_TOKEN=$ZABBIX_TOKEN"
  [ -n "${ZABBIX_USER:-}" ]     && echo "ZABBIX_USER=$ZABBIX_USER"
  [ -n "${ZABBIX_PASSWORD:-}" ] && echo "ZABBIX_PASSWORD=$ZABBIX_PASSWORD"
  echo "ZABBIX_SERVER_FQDN=$ZABBIX_SERVER_FQDN"
  echo "ZABBIX_SERVER_PORT=$ZABBIX_SERVER_PORT"
  echo "ZTC_SCHEDULE=$ZTC_SCHEDULE"
} > "$ENV_FILE"
chown "$SVC_USER:$SVC_USER" "$ENV_FILE"; chmod 600 "$ENV_FILE"
info "wrote $ENV_FILE"

# --- systemd unit ---
cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=Vulners Threat Control (ztc) scanner
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_DIR/ztc scan --daemon
Restart=on-failure
RestartSec=30
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
info "installed systemd unit $UNIT"

# --- one-time provisioning of Zabbix entities ---
DO_PROV="${ZTC_PROVISION:-}"
if [ -z "$DO_PROV" ] && [ -e /dev/tty ]; then
  printf "Run 'ztc provision --all' now (create templates/hosts/dashboard)? [y/N]: " >/dev/tty
  read -r _ans </dev/tty || _ans=n
  case "$_ans" in y|Y|yes|YES) DO_PROV=1 ;; *) DO_PROV=0 ;; esac
fi
if [ "${DO_PROV:-0}" = "1" ]; then
  info "provisioning Zabbix entities"
  ( set -a; . "$ENV_FILE"; set +a; "$BIN_DIR/ztc" provision --all ) \
    || info "provision failed — re-run later:  sudo -u $SVC_USER env \$(cat $ENV_FILE|xargs) $BIN_DIR/ztc provision --all"
fi

# --- start the daemon ---
systemctl enable --now ztc
info "done."
echo "   status: systemctl status ztc"
echo "   logs:   journalctl -u ztc -f"
echo "   config: $ENV_FILE"
