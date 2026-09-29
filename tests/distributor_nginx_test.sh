#!/usr/bin/env bash
# Serves the distributor nginx config from a temporary state directory and
# checks what /tw/ exposes: published files are served, hidden files and
# directories (in-progress downloads, temporary writes) are not.
# Needs nginx and curl or wget; skipped when nginx is missing. "http2 on" is
# dropped so older nginx builds can run it; it only affects the TLS server.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
if ! command -v nginx >/dev/null 2>&1; then
  echo "SKIP: nginx not installed"
  exit 0
fi
work=$(mktemp -d)
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

state="$work/state"
mkdir -p "$state/distributor/tw/.tmp" "$state/distributor/certs" "$work/logs" "$work/tmp"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=test \
  -keyout "$state/distributor/certs/tls.key" -out "$state/distributor/certs/tls.crt" >/dev/null 2>&1
echo '{"ok":true}' >"$state/distributor/tw/config.json"
echo apk >"$state/distributor/tw/app.apk"
echo partial >"$state/distributor/tw/.tmp/0123.part"
echo temp >"$state/distributor/tw/.config.json.123.tmp"
echo temp >"$state/distributor/tw/.app.apk.456.tmp"

chmod -R a+rX "$work"
port=$((20000 + RANDOM % 20000))
sed -e "s/__AWG_GATEWAY__/127.0.0.1/g" \
  -e "s#/worker-state#$state#g" \
  -e "s/listen 0.0.0.0:8080;/listen 127.0.0.1:$port;/" \
  -e "s/listen 9443 ssl;/listen 127.0.0.1:$((port + 1)) ssl;/" \
  -e "s#http://agent:9090#http://127.0.0.1:9#" \
  -e "/^ *http2 on;/d" \
  "$root/distributor/nginx.conf.template" >"$work/site.conf"
cat >"$work/nginx.conf" <<EOF
worker_processes 1;
pid $work/nginx.pid;
error_log $work/logs/error.log;
events {}
http {
  access_log off;
  client_body_temp_path $work/tmp;
  proxy_temp_path $work/tmp;
  fastcgi_temp_path $work/tmp;
  uwsgi_temp_path $work/tmp;
  scgi_temp_path $work/tmp;
  include $work/site.conf;
}
EOF
nginx -p "$work" -c "$work/nginx.conf" -g 'daemon off;' &
pid=$!
sleep 1

status() {
  if command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port$1"
  else
    wget -S -q -O /dev/null "http://127.0.0.1:$port$1" 2>&1 | awk '/HTTP\//{c=$2} END{print c+0}'
  fi
}

fail=0
expect() {
  local path=$1 want=$2 got
  got=$(status "$path")
  if [ "$got" != "$want" ]; then
    echo "FAIL: $path -> $got, want $want"
    fail=1
  fi
}
expect /tw/config.json 200
expect /tw/app.apk 200
expect /tw/.tmp/0123.part 404
expect /tw/.config.json.123.tmp 404
expect /tw/.app.apk.456.tmp 404
[ "$fail" = 0 ] && echo "distributor nginx: ok"
exit "$fail"
