#!/bin/sh
set -eu

while [ ! -s /worker-state/xray/config.json ]; do
  sleep 1
done

exec /usr/local/bin/xray run -config /worker-state/xray/config.json
