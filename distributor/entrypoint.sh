#!/bin/sh
set -eu

AWG_GATEWAY="${AWG_GATEWAY:-10.13.13.1}"

while [ ! -s /worker-state/distributor/certs/tls.crt ] || [ ! -s /worker-state/distributor/certs/tls.key ]; do
  sleep 1
done

for _ in $(seq 1 60); do
  if ip addr | grep -q "${AWG_GATEWAY}/"; then
    break
  fi
  sleep 1
done

sed "s/__AWG_GATEWAY__/${AWG_GATEWAY}/g" \
  /etc/nginx/templates/worker.conf.template \
  >/etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
