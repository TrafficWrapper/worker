#!/usr/bin/env bash
# Checks install.sh port selection: REALITY takes 443 when it is free,
# otherwise a random port in 20000-59999; AWG takes a random port; explicit
# pools are honored.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
# ss reports the ports listed in $BUSY as taken.
cat >"$work/bin/ss" <<'SH'
#!/bin/sh
port=$(printf '%s\n' "$*" | sed -n 's/.*sport = :\([0-9]*\).*/\1/p')
echo "State Recv-Q Send-Q Local"
for b in ${BUSY:-}; do
  [ "$b" = "$port" ] && echo "LISTEN 0 0 *:$port"
done
exit 0
SH
chmod +x "$work/bin/ss"
sed -n '1,/^need docker$/p' "$root/install.sh" | sed '$d' >"$work/funcs.sh"

run() { (cd "$work" && PATH="$work/bin:$PATH" bash -c ". ./funcs.sh; $1"); }
in_range() { [ "$1" -ge 20000 ] && [ "$1" -le 59999 ]; }

[ "$(BUSY="" run pick_tcp_port)" = 443 ] || { echo "free 443 not chosen" >&2; exit 1; }
p=$(BUSY="443" run pick_tcp_port)
in_range "$p" || { echo "REALITY fallback port $p out of range" >&2; exit 1; }
a=$(run pick_udp_port)
b=$(run pick_udp_port)
if ! in_range "$a" || ! in_range "$b"; then
  echo "AWG port out of range: $a $b" >&2
  exit 1
fi
[ "$(REALITY_PORT_POOL="8444 2053" BUSY="8444" run pick_tcp_port)" = 2053 ] || { echo "REALITY pool ignored" >&2; exit 1; }
[ "$(AWG_PORT_POOL="51888" run pick_udp_port)" = 51888 ] || { echo "AWG pool ignored" >&2; exit 1; }
echo "install port tests passed"
