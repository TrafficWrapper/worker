#!/usr/bin/env bash
# Checks how install.sh writes PUBLIC_ADDRESS_V6: "auto" is resolved on the
# host (containers have no IPv6), a literal is kept, and a host without a
# global IPv6 gets an empty value and a warning.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cp "$root/.env.example" "$work/"
cat >"$work/bin/curl" <<'SH'
#!/bin/sh
case "$*" in
  *-6*) echo "${FAKE_V6:-}" ;;
  *) echo 203.0.113.9 ;;
esac
SH
chmod +x "$work/bin/curl"
# Only the function definitions, not the install steps.
sed -n '1,/^need docker$/p' "$root/install.sh" | sed '$d' >"$work/funcs.sh"

check() {
  local setting=$1 host_v6=$2 want=$3 got
  rm -f "$work/.env"
  (
    cd "$work"
    PATH="$work/bin:$PATH" FAKE_V6="$host_v6" PUBLIC_ADDRESS_V6="$setting" \
      XRAY_PORT=2053 AWG_PORT=51888 CAMOUFLAGE_DOMAIN=www.example.net EGRESS_IP=203.0.113.9 \
      bash -c '. ./funcs.sh; write_env' >/dev/null 2>&1
  )
  got=$(grep '^PUBLIC_ADDRESS_V6=' "$work/.env" | cut -d= -f2-)
  if [ "$got" != "$want" ]; then
    echo "PUBLIC_ADDRESS_V6=$setting with host IPv6 '$host_v6': got '$got', want '$want'" >&2
    exit 1
  fi
}

check auto 2a01:4f8:c0c:1234::1 2a01:4f8:c0c:1234::1
check auto fd00::1 ""
check auto "" ""
check 2a01:4f8::7 2a01:4f8::9 2a01:4f8::7
check "" 2a01:4f8::9 ""
echo "install env tests passed"
