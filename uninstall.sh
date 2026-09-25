#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE=${COMPOSE:-docker compose}

usage() {
  cat <<'USAGE'
Usage: ./uninstall.sh [--yes] [--keep-state] [--purge-images]

  -y, --yes        do not ask for confirmation
  --keep-state     keep ./worker-state (keys, certificates, peers)
  --purge-images   also remove the worker images and named volumes
USAGE
}

assume_yes=0
keep_state=0
purge_images=0
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) assume_yes=1 ;;
    --keep-state) keep_state=1 ;;
    --purge-images) purge_images=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$assume_yes" != "1" ]; then
  if [ ! -t 0 ]; then
    echo "refusing to uninstall non-interactively; pass --yes" >&2
    exit 1
  fi
  if [ "$keep_state" = "1" ]; then
    prompt="Stop the worker and remove its containers? [y/N] "
  else
    prompt="Stop the worker and DELETE ./worker-state (a backup archive is written first)? [y/N] "
  fi
  read -r -p "$prompt" answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "aborted" >&2; exit 1 ;;
  esac
fi

backup_state() {
  local items=() archive
  [ -e worker-state ] && items+=(worker-state)
  [ -e .env ] && items+=(.env)
  [ ${#items[@]} -gt 0 ] || return 0
  archive="worker-state-backup-$(date -u +%Y%m%dT%H%M%SZ).tgz"
  (umask 077 && tar -czf "$archive" "${items[@]}")
  echo "backup written to $PWD/$archive"
}

# The smoke profile is included so its container and image go too. Every
# service image is a worker-* image, so --rmi all removes only the worker's
# own images, whether built locally or pulled from a release.
down_args=(--profile smoke down --remove-orphans)
if [ "$purge_images" = "1" ]; then
  down_args+=(--rmi all -v)
fi
if ! $COMPOSE "${down_args[@]}"; then
  echo "error: '$COMPOSE ${down_args[*]}' failed; the worker may still be running." >&2
  echo "Nothing was deleted: ./worker-state and .env are unchanged. Fix the error and re-run." >&2
  exit 1
fi

if command -v nft >/dev/null; then
  nft delete table inet trafficwrapper_worker 2>/dev/null || true
fi

if [ "$keep_state" != "1" ]; then
  backup_state
  rm -rf worker-state
fi
