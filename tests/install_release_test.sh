#!/usr/bin/env bash
# Checks how install.sh starts the services: from source without a pinned
# release; with WORKER_VERSION pulled, verified with cosign by digest and
# started with --no-build; refused without cosign unless explicitly allowed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/nocosign"
cat >"$work/bin/docker" <<'SH'
#!/bin/sh
echo "docker $*" >>"$LOG"
case "$*" in
  "compose config --images")
    echo "ghcr.io/trafficwrapper/worker-agent:${VERSION}"
    echo "ghcr.io/trafficwrapper/worker-xray:${VERSION}"
    echo "alpine:3" ;;
  "image inspect"*) echo "ghcr.io/trafficwrapper/worker-x@sha256:abc" ;;
esac
exit 0
SH
cat >"$work/bin/cosign" <<'SH'
#!/bin/sh
echo "cosign $*" >>"$LOG"
exit 0
SH
chmod +x "$work/bin/docker" "$work/bin/cosign"
ln -s "$work/bin/docker" "$work/nocosign/docker"
sed -n '1,/^need docker$/p' "$root/install.sh" | sed '$d' >"$work/funcs.sh"

run() {
  local path=$1 version=$2
  : >"$work/log"
  printf 'WORKER_VERSION=%s\n' "$version" >"$work/.env"
  (cd "$work" && PATH="$path:/usr/bin:/bin" LOG="$work/log" VERSION="$version" bash -c '. ./funcs.sh; start_services')
}

run "$work/bin" ""
grep -q 'compose up -d --build' "$work/log" || { echo "source build not used without a release" >&2; exit 1; }
if grep -q 'compose pull' "$work/log"; then echo "pulled without a release" >&2; exit 1; fi

run "$work/bin" v1.2.3
grep -q 'compose pull' "$work/log" || { echo "release not pulled" >&2; exit 1; }
[ "$(grep -c '^cosign verify ghcr.io/trafficwrapper/worker-x@sha256:abc' "$work/log")" = 2 ] || { echo "release images not verified by digest" >&2; cat "$work/log" >&2; exit 1; }
grep -q 'compose up -d --no-build' "$work/log" || { echo "release started with a local build" >&2; exit 1; }
if grep -q -- '--build ' "$work/log"; then echo "release rebuilt locally" >&2; exit 1; fi

if run "$work/nocosign" v1.2.3 2>/dev/null; then echo "release started without cosign" >&2; exit 1; fi
if grep -q 'compose up' "$work/log"; then echo "services started without verification" >&2; exit 1; fi
ALLOW_UNVERIFIED_IMAGES=1 run "$work/nocosign" v1.2.3 2>/dev/null
grep -q 'compose up -d --no-build' "$work/log" || { echo "explicit opt-out not honored" >&2; exit 1; }
echo "install release tests passed"
