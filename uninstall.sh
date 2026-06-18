#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE=${COMPOSE:-docker compose}

$COMPOSE down --remove-orphans || true

if command -v nft >/dev/null; then
  nft delete table inet trafficwrapper_worker 2>/dev/null || true
fi

rm -rf worker-state
