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

exec /usr/local/bin/dnsproxy "$@"
