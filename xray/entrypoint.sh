#!/bin/sh
set -eu

CONFIG=/worker-state/xray/config.json
RESTART_REQUEST=/worker-state/xray/restart-request
API_SOCKET=${XRAY_API_SOCKET:-/run/xray-api/api.sock}

while [ ! -s "$CONFIG" ]; do
  sleep 1
done

request_stamp() {
  cat "$RESTART_REQUEST" 2>/dev/null || true
}

child=""
stop() {
  if [ -n "$child" ]; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  exit 0
}
trap stop TERM INT

# Supervise xray: the agent asks for a restart (for config changes that the
# API cannot apply live) by rewriting the restart-request file, so it needs no
# access to the Docker socket.
while :; do
  rm -f "$API_SOCKET"
  last=$(request_stamp)
  /usr/local/bin/xray run -config "$CONFIG" &
  child=$!
  while kill -0 "$child" 2>/dev/null; do
    sleep 2
    if [ "$(request_stamp)" != "$last" ]; then
      echo "xray restart requested"
      kill "$child" 2>/dev/null || true
      break
    fi
  done
  wait "$child" 2>/dev/null || true
  child=""
  sleep 1
done
