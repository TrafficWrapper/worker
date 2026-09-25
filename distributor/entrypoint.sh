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

cert_stamp() {
  stat -c '%Y' /worker-state/distributor/certs/tls.crt /worker-state/distributor/certs/tls.key 2>/dev/null | tr '\n' ' '
}

# The agent renews the certificate in place; reload nginx when it changes.
(
  last=$(cert_stamp)
  while sleep 300; do
    now=$(cert_stamp)
    if [ "$now" != "$last" ]; then
      sleep 5
      nginx -s reload && last=$(cert_stamp)
    fi
  done
) &

nginx -g 'daemon off;' &
nginx_pid=$!
trap 'kill -TERM "$nginx_pid" 2>/dev/null' TERM INT

# This container shares the awg-gw network namespace. When awg-gw restarts it
# gets a new one and this container is left in the old namespace without the
# tunnel. Exit then, so Docker restarts it inside the current one.
missing=0
while kill -0 "$nginx_pid" 2>/dev/null; do
  sleep 10 &
  wait $! 2>/dev/null || true
  if ip addr | grep -q "${AWG_GATEWAY}/"; then
    missing=0
  else
    missing=$((missing + 1))
  fi
  if [ "$missing" -ge 3 ]; then
    echo "tunnel gateway ${AWG_GATEWAY} is gone from this network namespace; restarting" >&2
    kill -TERM "$nginx_pid" 2>/dev/null || true
    wait "$nginx_pid" 2>/dev/null || true
    exit 1
  fi
done
wait "$nginx_pid"
