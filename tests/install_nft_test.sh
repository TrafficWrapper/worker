#!/usr/bin/env bash
# Checks that the retired APPLY_NFT option is refused rather than ignored:
# install.sh stops before touching .env, containers or the firewall when
# APPLY_NFT=1 comes from the environment or an existing .env, and a leftover
# APPLY_NFT=0 is dropped from the regenerated .env.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cp "$root/install.sh" "$root/.env.example" "$work/"
# Every external command install.sh may reach is logged; none may run.
for cmd in docker ss curl openssl nft; do
  cat >"$work/bin/$cmd" <<SH
#!/bin/sh
echo "$cmd \$*" >>"$work/calls.log"
SH
  chmod +x "$work/bin/$cmd"
done

fail() { echo "$*" >&2; exit 1; }

# install.sh with APPLY_NFT set in the environment and/or in .env.
install() {
  local setting=$1 env_line=$2 status=0
  rm -f "$work/.env" "$work/calls.log" "$work/err.log"
  rm -rf "$work/worker-state"
  if [ -n "$env_line" ]; then printf '%s\n' "$env_line" >"$work/.env"; fi
  (
    cd "$work"
    if [ -n "$setting" ]; then export APPLY_NFT="$setting"; else unset APPLY_NFT; fi
    PATH="$work/bin:$PATH" bash ./install.sh >/dev/null 2>"$work/err.log"
  ) || status=$?
  return "$status"
}

refused() {
  if install "$1" "$2"; then fail "APPLY_NFT='$1' .env='$2': install.sh succeeded, want refusal"; fi
  grep -q 'APPLY_NFT=1 is no longer supported' "$work/err.log" ||
    fail "APPLY_NFT='$1' .env='$2': missing explanation: $(cat "$work/err.log")"
  [ ! -e "$work/calls.log" ] || fail "APPLY_NFT='$1' .env='$2': commands ran: $(cat "$work/calls.log")"
  [ ! -e "$work/worker-state" ] || fail "APPLY_NFT='$1' .env='$2': worker-state created"
  if [ -z "$2" ] && [ -e "$work/.env" ]; then fail "APPLY_NFT='$1': .env written"; fi
}

refused 1 ""
refused "" "APPLY_NFT=1"
refused 1 "APPLY_NFT=0"

# APPLY_NFT unset or 0 passes the check (and fails later only on the stubs).
sed -n '1,/^need docker$/p' "$root/install.sh" | sed '$d' >"$work/funcs.sh"
for setting in "" 0; do
  (cd "$work" && rm -f .env && APPLY_NFT="$setting" bash -c '. ./funcs.sh; refuse_apply_nft') ||
    fail "APPLY_NFT='$setting' refused"
done

# A leftover APPLY_NFT=0 is not carried into the regenerated .env.
printf 'APPLY_NFT=0\nORCH_URL=https://orch.example.net\n' >"$work/.env"
(
  cd "$work"
  PATH="$work/bin:$PATH" XRAY_PORT=2053 AWG_PORT=51888 CAMOUFLAGE_DOMAIN=www.example.net \
    EGRESS_IP=203.0.113.9 bash -c '. ./funcs.sh; refuse_apply_nft; write_env' >/dev/null
)
if grep -q '^APPLY_NFT=' "$work/.env"; then fail "APPLY_NFT kept in the regenerated .env"; fi
grep -q '^ORCH_URL=https://orch.example.net$' "$work/.env" || fail "ORCH_URL not kept in .env"
echo "install nft tests passed"
