#!/usr/bin/env bash
# Checks that install.sh writes EGRESS_IP only when the address is global
# and confirmed by two echo services, drops a non-global value left by an
# older install, and keeps an address the operator set explicitly.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cp "$root/.env.example" "$work/"
cat >"$work/bin/curl" <<'SH'
#!/bin/sh
case "$*" in
  *-6*) exit 22 ;;
  *api.ipify.org*) echo "${IP1:-}" ;;
  *ifconfig.co*) echo "${IP2:-}" ;;
  *ipinfo.io*) echo "${IP3:-}" ;;
esac
SH
chmod +x "$work/bin/curl"
sed -n '1,/^need docker$/p' "$root/install.sh" | sed '$d' >"$work/funcs.sh"

check() {
  local want=$1 got
  (
    cd "$work"
    PATH="$work/bin:$PATH" XRAY_PORT=2053 AWG_PORT=51888 CAMOUFLAGE_DOMAIN=www.example.net \
      bash -c '. ./funcs.sh; write_env' >/dev/null 2>&1
  )
  got=$(grep '^EGRESS_IP=' "$work/.env" | cut -d= -f2-)
  if [ "$got" != "$want" ]; then
    echo "IP1=${IP1:-} IP2=${IP2:-} IP3=${IP3:-} EGRESS_IP=${EGRESS_IP:-}: got '$got', want '$want'" >&2
    exit 1
  fi
}

rm -f "$work/.env"
IP1=9.9.9.9 IP2=9.9.9.9 IP3=8.8.4.4 check 9.9.9.9
rm -f "$work/.env"
IP1=9.9.9.9 IP2=8.8.4.4 IP3="" check ""
rm -f "$work/.env"
IP1=10.0.0.5 IP2=10.0.0.5 IP3=10.0.0.5 check ""
# A LAN address pinned by an older install is replaced by a confirmed one.
printf 'EGRESS_IP=192.168.1.10\n' >"$work/.env"
IP1=9.9.9.9 IP2=9.9.9.9 check 9.9.9.9
# An address the operator passes explicitly is kept as is.
rm -f "$work/.env"
EGRESS_IP=10.1.1.1 check 10.1.1.1
echo "install egress tests passed"
