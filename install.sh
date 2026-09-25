#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE=${COMPOSE:-docker compose}
# Without explicit pools, REALITY takes 443 when it is free (a TLS site on its
# usual port) and otherwise, like AWG, a random high port, so deployments do
# not share a recognizable default port.
REALITY_PORT_POOL=${REALITY_PORT_POOL:-}
AWG_PORT_POOL=${AWG_PORT_POOL:-}

need() {
  command -v "$1" >/dev/null || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

port_free_tcp() {
  ! ss -tln "sport = :$1" | awk 'NR>1{found=1} END{exit found?0:1}'
}

port_free_udp() {
  ! ss -uln "sport = :$1" | awk 'NR>1{found=1} END{exit found?0:1}'
}

# random_ports prints candidate ports in 20000-59999.
random_ports() {
  python3 -c 'import secrets
for _ in range(64): print(20000 + secrets.randbelow(40000))'
}

pick_tcp_port() {
  pool=${REALITY_PORT_POOL:-"443 $(random_ports | tr '\n' ' ')"}
  for p in $pool; do
    if port_free_tcp "$p"; then echo "$p"; return; fi
  done
  echo "no free REALITY TCP port in pool: $pool" >&2
  exit 1
}

pick_udp_port() {
  pool=${AWG_PORT_POOL:-$(random_ports | tr '\n' ' ')}
  for p in $pool; do
    if port_free_udp "$p"; then echo "$p"; return; fi
  done
  echo "no free AWG UDP port in pool: $pool" >&2
  exit 1
}

detect_ip() {
  if [ -n "${EGRESS_IP:-}" ]; then echo "$EGRESS_IP"; return; fi
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' RETURN
  for url in https://api.ipify.org https://ifconfig.co/ip https://ipinfo.io/ip; do
    curl -4fsS --max-time 4 "$url" >>"$tmp" 2>/dev/null || true
    printf '\n' >>"$tmp"
  done
  ip=$(awk 'NF && $1 ~ /^[0-9.]+$/ {c[$1]++} END{for (i in c) if (c[i] >= 2) {print i; exit}}' "$tmp")
  if [ -n "$ip" ]; then echo "$ip"; return; fi
  if [ -n "${WAN_IF:-}" ]; then
    ip -4 addr show dev "$WAN_IF" | awk '/inet /{sub(/\/.*/, "", $2); print $2; exit}'
    return
  fi
  hostname -I | awk '{print $1}'
}

# detect_ipv6 asks from the host: containers on the default Compose network
# have no IPv6, so the agent cannot find the address itself.
detect_ipv6() {
  v6=$(curl -6fsS --max-time 4 https://api6.ipify.org 2>/dev/null || true)
  if python3 - "$v6" <<'PY'
import ipaddress, sys
try:
    sys.exit(0 if ipaddress.IPv6Address(sys.argv[1].strip()).is_global else 1)
except ValueError:
    sys.exit(1)
PY
  then
    echo "$v6"
  fi
}

first_host() {
  python3 - "$1" <<'PY'
import ipaddress, sys
net=ipaddress.ip_network(sys.argv[1], strict=False)
print(next(net.hosts()))
PY
}

env_value() {
  [ -f "$2" ] || return 0
  awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/, ""); v=$0} END{print v}' "$2"
}

# write_env regenerates .env from .env.example but keeps every value already
# set in an existing .env (orchestrator settings, ports, domain), so re-running
# install.sh on an installed worker is safe.
write_env() {
  previous=""
  if [ -f .env ]; then
    previous=".env.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp .env "$previous"
    chmod 600 "$previous"
  fi
  xr=${XRAY_PORT:-$(env_value XRAY_PORT "$previous")}
  xr=${xr:-$(pick_tcp_port)}
  awg=${AWG_PORT:-$(env_value AWG_PORT "$previous")}
  awg=${awg:-$(pick_udp_port)}
  subnet=${AWG_SUBNET:-$(env_value AWG_SUBNET "$previous")}
  subnet=${subnet:-10.13.13.0/24}
  gateway=${AWG_GATEWAY:-$(env_value AWG_GATEWAY "$previous")}
  gateway=${gateway:-$(first_host "$subnet")}
  egress=${EGRESS_IP:-$(env_value EGRESS_IP "$previous")}
  egress=${egress:-$(detect_ip)}
  camouflage=${CAMOUFLAGE_DOMAIN:-$(env_value CAMOUFLAGE_DOMAIN "$previous")}
  v6=${PUBLIC_ADDRESS_V6:-$(env_value PUBLIC_ADDRESS_V6 "$previous")}
  if [ "$v6" = "auto" ]; then
    v6=$(detect_ipv6)
    if [ -n "$v6" ]; then
      echo "PUBLIC_ADDRESS_V6=auto resolved on the host to $v6"
    else
      echo "WARNING: PUBLIC_ADDRESS_V6=auto: the host has no global IPv6; no IPv6 endpoint will be advertised" >&2
    fi
  fi
  python3 - "$previous" "$xr" "$awg" "$subnet" "$gateway" "$egress" "$camouflage" "$v6" <<'PY'
import sys
previous, xr, awg, subnet, gateway, egress, camouflage, v6 = sys.argv[1:]
kept = {}
retired = {"APPLY_NFT"}
if previous:
    for line in open(previous):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            if v != "" and k.strip() not in retired:
                kept[k.strip()] = v
repl = dict(kept)
repl.update({
    "XRAY_PORT": xr,
    "AWG_PORT": awg,
    "AWG_SUBNET": subnet,
    "AWG_GATEWAY": gateway,
    "EGRESS_IP": egress,
    "CAMOUFLAGE_DOMAIN": camouflage,
    "PUBLIC_ADDRESS_V6": v6,
})
lines = []
seen = set()
for line in open(".env.example"):
    if "=" in line and not line.startswith("#"):
        k = line.split("=", 1)[0]
        if k in repl:
            line = f"{k}={repl[k]}\n"
            seen.add(k)
    lines.append(line)
extra = [k for k in kept if k not in seen]
if extra:
    lines.append("\n# Kept from the previous .env\n")
    lines.extend(f"{k}={kept[k]}\n" for k in extra)
with open(".env", "w") as f:
    f.writelines(lines)
PY
  chmod 600 .env
}

verify_dest_hint() {
  domain=$(awk -F= '$1=="CAMOUFLAGE_DOMAIN"{print $2}' .env | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
  dest=$(awk -F= '$1=="REALITY_DEST"{print $2}' .env | tr -d '[:space:]')
  dest=${dest:-$domain:443}
  case "$domain" in
    ""|example.com|example.org)
      echo "error: refusing placeholder CAMOUFLAGE_DOMAIN; set a real TLS1.3 domain" >&2
      exit 1
      ;;
  esac
  case "$dest" in
    *:443)
      host=${dest%:*}
      echo | openssl s_client -tls1_3 -alpn h2 -servername "$domain" -connect "$host:443" >/dev/null 2>&1 || {
        echo "warning: REALITY_DEST TLS1.3+h2 probe failed for $dest; pick a CAMOUFLAGE_DOMAIN that serves TLS 1.3 with h2" >&2
      }
      ;;
  esac
}

# refuse_apply_nft stops on the retired APPLY_NFT=1 option instead of
# ignoring it: install.sh no longer changes the host firewall. Docker
# publishes the ports itself; restrict them in the DOCKER-USER chain.
refuse_apply_nft() {
  setting=${APPLY_NFT:-$(env_value APPLY_NFT .env)}
  case "$setting" in
    ""|0) return 0 ;;
  esac
  echo "error: APPLY_NFT=$setting is no longer supported: install.sh does not manage firewall rules." >&2
  echo "Docker publishes XRAY_PORT/tcp and AWG_PORT/udp itself; allow them in your host firewall" >&2
  echo "(filter published ports in the DOCKER-USER chain), then unset APPLY_NFT and re-run." >&2
  exit 1
}

# verify_release_images checks the cosign signature of every pulled release
# image by digest, so what runs is exactly what the release workflow signed.
verify_release_images() {
  version=$1
  if ! command -v cosign >/dev/null; then
    if [ "${ALLOW_UNVERIFIED_IMAGES:-0}" = "1" ]; then
      echo "WARNING: cosign not found; running release $version without verifying image signatures" >&2
      return
    fi
    echo "cosign is required to verify release images (https://docs.sigstore.dev/cosign/system_config/installation/);" >&2
    echo "install it, or set ALLOW_UNVERIFIED_IMAGES=1 to skip the check" >&2
    exit 1
  fi
  for image in $($COMPOSE config --images); do
    case "$image" in
      ghcr.io/trafficwrapper/worker-*:"$version") ;;
      *) continue ;;
    esac
    ref=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")
    cosign verify "$ref" \
      --certificate-identity-regexp '^https://github.com/TrafficWrapper/worker/.github/workflows/release.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
    echo "verified $ref"
  done
}

# start_services builds from source unless .env pins a release. A pinned
# release is pulled and verified, never rebuilt locally under its tag.
start_services() {
  version=$(env_value WORKER_VERSION .env)
  if [ -z "$version" ]; then
    $COMPOSE up -d --build --wait --wait-timeout "${WAIT_TIMEOUT:-180}"
    return
  fi
  $COMPOSE pull
  verify_release_images "$version"
  $COMPOSE up -d --no-build --wait --wait-timeout "${WAIT_TIMEOUT:-180}"
}

need_tun() {
  [ -c /dev/net/tun ] || {
    echo "missing /dev/net/tun; load the tun kernel module (modprobe tun) or enable TUN for this VPS" >&2
    exit 1
  }
}

need docker
need ss
need curl
need python3
need openssl
refuse_apply_nft
need_tun

mkdir -p worker-state
write_env
verify_dest_hint
start_services
$COMPOSE ps
