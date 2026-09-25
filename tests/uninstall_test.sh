#!/usr/bin/env bash
# Checks uninstall.sh against a stubbed docker: a failed `compose down` stops
# the script with the state untouched; a successful one backs up and removes
# the state; --purge-images asks Compose to remove the worker images and
# volumes.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'SH'
#!/bin/sh
echo "docker $*" >>"$LOG"
exit "${DOCKER_STATUS:-0}"
SH
cat >"$work/bin/nft" <<'SH'
#!/bin/sh
echo "nft $*" >>"$LOG"
SH
chmod +x "$work/bin/docker" "$work/bin/nft"

fail() { echo "$*" >&2; exit 1; }

# run <docker exit status> <uninstall.sh args...>; sets $status.
run() {
  local docker_status=$1
  shift
  rm -rf "$work/w"
  mkdir -p "$work/w/worker-state"
  cp "$root/uninstall.sh" "$work/w/"
  echo secret >"$work/w/worker-state/key"
  echo ORCH_URL=https://orch.example.net >"$work/w/.env"
  : >"$work/log"
  status=0
  (cd "$work/w" && PATH="$work/bin:$PATH" LOG="$work/log" DOCKER_STATUS="$docker_status" \
    bash ./uninstall.sh "$@" >/dev/null 2>"$work/err") || status=$?
}

# compose down fails: non-zero exit, state and .env kept, nothing else run.
run 1 --yes
[ "$status" -ne 0 ] || fail "uninstall.sh succeeded although compose down failed"
[ -f "$work/w/worker-state/key" ] || fail "worker-state deleted although compose down failed"
[ -f "$work/w/.env" ] || fail ".env deleted although compose down failed"
if ls "$work/w"/worker-state-backup-*.tgz >/dev/null 2>&1; then fail "backup written although compose down failed"; fi
if grep -q '^nft' "$work/log"; then fail "firewall touched although compose down failed"; fi
grep -q 'failed' "$work/err" || fail "no error message: $(cat "$work/err")"

# compose down succeeds: state backed up and removed, images kept.
run 0 --yes
[ "$status" -eq 0 ] || fail "uninstall.sh failed: $(cat "$work/err")"
[ ! -e "$work/w/worker-state" ] || fail "worker-state not removed"
ls "$work/w"/worker-state-backup-*.tgz >/dev/null 2>&1 || fail "no backup archive"
grep -qx 'docker compose --profile smoke down --remove-orphans' "$work/log" ||
  fail "unexpected compose call: $(cat "$work/log")"

# --keep-state: containers go, state stays.
run 0 --yes --keep-state
[ "$status" -eq 0 ] || fail "uninstall.sh --keep-state failed: $(cat "$work/err")"
[ -f "$work/w/worker-state/key" ] || fail "worker-state removed with --keep-state"

# --purge-images removes the project's images and volumes.
run 0 --yes --purge-images
[ "$status" -eq 0 ] || fail "uninstall.sh --purge-images failed: $(cat "$work/err")"
grep -qx 'docker compose --profile smoke down --remove-orphans --rmi all -v' "$work/log" ||
  fail "--purge-images does not remove images: $(cat "$work/log")"

# A failed purge also keeps the state.
run 1 --yes --purge-images
[ "$status" -ne 0 ] || fail "uninstall.sh --purge-images succeeded although compose down failed"
[ -f "$work/w/worker-state/key" ] || fail "worker-state deleted although compose down failed"
echo "uninstall tests passed"
