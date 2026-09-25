#!/bin/sh
set -eu

# Resolver for AWG clients on the tunnel gateway. Queries leave the worker
# only as DNS-over-HTTPS, so the hosting network never sees client lookups.
set -- \
  --listen=0.0.0.0 \
  --port=53 \
  --cache \
  --cache-optimistic \
  --refuse-any \
  --ratelimit="${DNS_RATELIMIT:-100}" \
  --ratelimit-subnet-len-ipv4=32 \
  --bootstrap="${DNS_BOOTSTRAP:-9.9.9.9:53}"

for upstream in ${DNS_UPSTREAMS:-https://dns.quad9.net/dns-query https://cloudflare-dns.com/dns-query}; do
  set -- "$@" --upstream="$upstream"
done

/usr/local/bin/dnsproxy "$@" &
dns_pid=$!
trap 'kill -TERM "$dns_pid" 2>/dev/null' TERM INT

# This container shares the awg-gw network namespace. When awg-gw restarts it
# gets a new one and this container is left in the old namespace without the
# tunnel. Exit then, so Docker restarts it inside the current one.
AWG_GATEWAY="${AWG_GATEWAY:-10.13.13.1}"
missing=0
while kill -0 "$dns_pid" 2>/dev/null; do
  sleep 10 &
  wait $! 2>/dev/null || true
  if ip addr | grep -q "${AWG_GATEWAY}/"; then
    missing=0
  else
    missing=$((missing + 1))
  fi
  if [ "$missing" -ge 3 ]; then
    echo "tunnel gateway ${AWG_GATEWAY} is gone from this network namespace; restarting" >&2
    kill -TERM "$dns_pid" 2>/dev/null || true
    wait "$dns_pid" 2>/dev/null || true
    exit 1
  fi
done
wait "$dns_pid"
