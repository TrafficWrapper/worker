# TrafficWrapper Worker

[![CI](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml/badge.svg)](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml)

[Русский](README.ru.md)

Data-plane node for the TrafficWrapper platform. A worker enrolls into an
orchestrator, materializes approved devices as Xray REALITY clients and
AmneziaWG peers, and exposes the in-tunnel `/tw/` distributor for client config,
APK updates, and opt-in telemetry.

TrafficWrapper is split into three repositories:

- [orchestrator](https://github.com/TrafficWrapper/orchestrator) — the control plane.
- [worker](https://github.com/TrafficWrapper/worker) — this data-plane node.
- [app](https://github.com/TrafficWrapper/app) — Android public client.

The normal workflow is: start the orchestrator, create a worker enrollment token,
start this worker, approve it in the admin UI, then bootstrap devices with the
app.

Architecture and threat-model notes live in [ARCHITECTURE.md](ARCHITECTURE.md)
and [THREAT_MODEL.md](THREAT_MODEL.md).

## Troubleshooting

The canonical end-to-end troubleshooting guide lives in the orchestrator
repository: <https://github.com/TrafficWrapper/orchestrator/blob/master/TROUBLESHOOTING.md>.
For worker-specific failures, start with enrollment values
`ORCH_URL`, `ORCH_STATIC_PUBLIC_KEY`, `ENROLL_TOKEN`, `ORCH_INSECURE_TLS`, and
`CAMOUFLAGE_DOMAIN`.

## Diagnostics

The worker agent exposes `/healthz`, `/self-describe`, and `/metrics` on the
local agent port (`127.0.0.1:9090` through the default Compose mapping). The
Prometheus metrics endpoint is intended for localhost scraping because AWG peer
labels include public keys, allowed IPs, and endpoints.

For optional wire-level AWG stealth checks, use `tools/dpi_probe.py` as root on
the worker host with `tcpdump` installed:

```sh
sudo python3 tools/dpi_probe.py --interface <iface> --dialect /worker-state/awg/awg-gw.json --json
python3 tools/dpi_probe.py --pcap capture.pcap --dialect /worker-state/awg/awg-gw.json --awg-port <udp-port>
```

The probe reads the public worker dialect envelope (`listen_port` + `dialect`)
and reports whether WG magic headers are absent, padded handshakes are visible,
vanilla handshakes are absent, and pre-handshake junk matches the dialect.

## What Is Included

- `agent/` — pulls signed bundles from the orchestrator and applies state.
- `xray/` — REALITY container.
- `awg-gw/` — AmneziaWG gateway and live peer materialization.
- `distributor/` — nginx distributor reachable inside the tunnel.
- `awg-smoke/` — optional smoke test helper.
- `core/awg/...` — embedded Go transport pieces needed by worker binaries.

The Go modules use local `replace` directives, so this repository builds without
the original monorepo.

## Requirements

- Linux server with a public IP.
- Docker and Docker Compose.
- `/dev/net/tun` and `NET_ADMIN` capability for AWG.
- Domain/SNI value for REALITY camouflage.
- Minimum: 1 CPU and 1 GB RAM. Add swap on 1 GB servers; builds and image pulls
  are more reliable with 2 GB+ RAM.

Install Docker on a fresh host:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
```

## Quick Start

```sh
git clone https://github.com/TrafficWrapper/worker.git
cd worker
cp .env.example .env
```

Edit `.env`:

- `ORCH_URL`: orchestrator URL. If the orchestrator runs on the same Docker host,
  use `https://host.docker.internal:9091` and keep `ORCH_INSECURE_TLS=1` for the
  built-in self-signed dev certificate.
- `ORCH_STATIC_PUBLIC_KEY`: output of `orchestrator public-key`.
- `ENROLL_TOKEN`: one-time worker token from the orchestrator admin UI.
- `PUBLIC_ADDRESS`: public DNS name or IP of this worker.
- `CAMOUFLAGE_DOMAIN`: a real TLS 1.3 SNI/fallback domain for REALITY. Empty
  values and `example.com`/`example.org` are refused.
- `WAN_IF`: egress interface if you enable nft NAT automation.
- `APPLY_NFT=1`: only after reviewing the generated NAT/firewall rules.

Start:

```sh
docker compose up -d --build
```

After enrollment, approve the worker in the orchestrator admin UI. The worker
will then receive signed config, generate/materialize REALITY and AWG settings,
and serve `/tw/` inside the tunnel.

## `docker compose up` vs `install.sh`

For a simple same-host or lab deployment, editing `.env`, opening the chosen
TCP/UDP ports manually, and running `docker compose up -d --build` is enough.

`install.sh` is an optional helper for production-style hosts. It can:

- auto-select free ports from `REALITY_PORT_POOL` and `AWG_PORT_POOL`;
- detect the WAN interface and public egress;
- write `.env` values;
- when `APPLY_NFT=1`, install nft accept/NAT rules for the selected ports.

Run it with a real camouflage value, for example:

```sh
CAMOUFLAGE_DOMAIN=www.your-real-tls13-domain.tld ./install.sh
```

Keep `APPLY_NFT=0` until you review the generated firewall/NAT changes.

## Environment Variables

These variables are read by `.env.example`, Compose, install scripts, or worker
binaries:

| Variable | Purpose | Required | Default | Example / how to get it |
| --- | --- | --- | --- | --- |
| `ORCH_URL` | Orchestrator base URL for worker enroll/pull. | Required for platform mode | empty | From your orchestrator deployment, for example `https://orch.example.com`; same-host Docker: `https://host.docker.internal:9091`. |
| `ORCH_STATIC_PUBLIC_KEY` | Pinned orchestrator Noise static public key. | Required for platform mode | empty | Run `orchestrator public-key` on the orchestrator. |
| `ENROLL_TOKEN` | One-time worker enrollment token. | Required for first enroll | empty | Create it in the orchestrator admin UI or CLI. |
| `ORCH_INSECURE_TLS` | Allows insecure TLS to the orchestrator for local dev. Required when ORCH uses the default self-signed `ORCH_TLS=1`. | Required for self-signed ORCH | `0` | Set `1` for test/self-signed ORCH only; keep `0` with real production TLS. |
| `PUBLIC_ADDRESS` | Public DNS name or IP advertised to clients. | Optional | detected egress IP | `worker1.example.com` or a public IPv4. |
| `EGRESS_IP` | Explicit public egress IP advertised to clients and sent in worker ack. Overrides persisted bootstrap state. | Optional | public echo-IP probe, then local route fallback | Set if auto-detection is wrong. |
| `CAPACITY` | Capacity hint reported to the orchestrator. | Optional | `32` | Any positive integer. |
| `XRAY_PORT` | Public TCP port mapped to the REALITY container. | Optional | `2053` | `8444`, `2053`, or another free TCP port. |
| `AWG_PORT` | Public UDP port mapped to AWG. | Optional | `51888` | Any free UDP port. |
| `AGENT_PORT` | Localhost TCP port exposing the worker agent health/API. | Optional | `9090` | `127.0.0.1:9090` by default. |
| `AWG_SUBNET` | Worker AWG subnet for device internal IPs. | Optional | `10.13.13.0/24` | Use a private subnet not colliding with your host. |
| `AWG_GATEWAY` | AWG gateway address inside `AWG_SUBNET`. | Optional | first host in subnet | `10.13.13.1`. |
| `AWG_UAPI_SOCKET` | WireGuard/AmneziaWG UAPI socket path. | Optional | `/var/run/wireguard/awg1.sock` | Usually set by Compose. |
| `XRAY_CONTAINER_NAME` | Docker container name used by the agent to restart/rewrite Xray after approved-device changes. | Optional | `worker-xray-1` | Compose sets a stable `container_name` with this value; override only if you also change the xray service container name. |
| `DOCKER_SOCKET` | Docker socket path used by the agent. | Optional | `/var/run/docker.sock` | Compose mounts the host Docker socket. |
| `DISTRIBUTOR_URL` | Internal URL of the `/tw/` distributor. | Optional | `http://awg-gw:8080/tw` | Keep default for Compose. |
| `WORKER_AGENT_URL` | Public/internal URL override for agent self-reference. | Optional | empty | Set only for custom deployments. |
| `CAMOUFLAGE_DOMAIN` | REALITY serverName/camouflage SNI and fallback identity. | Required for REALITY | empty, refused until set | Use a real TLS 1.3 domain that fits your deployment; `example.com` and `example.org` are rejected. |
| `REALITY_DEST` | REALITY fallback destination. | Optional | `awg-gw:9443` | Keep default for self-steal, or set `host:443`. |
| `WORKER_STATE_DIR` | Worker state directory inside containers. | Optional | `/var/lib/trafficwrapper-worker` in binaries; Compose uses `/worker-state` | Keep Compose default unless running binaries manually. |
| `TW_WORKER_DIALECT_JSON` | Advanced override for the AmneziaWG dialect JSON. | Optional | generated dialect | Use only for controlled testing. |
| `WAN_IF` | Interface used by `install.sh` to detect egress IP. | Optional | auto-detect | `eth0`, `ens3`, etc. |
| `APPLY_NFT` | Enables install-time nft accept rules for selected ports. | Optional | `0` | Set `1` only after reviewing rules. |
| `EGRESS_VIA_WG` | Reserved deployment hint in `.env.example`; not consumed by current binaries. | Optional | empty | Leave empty unless you extend deployment scripts. |
| `COMPOSE` | Compose command used by `install.sh`/`uninstall.sh`. | Optional | `docker compose` | `docker-compose` on older hosts. |
| `REALITY_PORT_POOL` | TCP port pool used by `install.sh` auto-selection. | Optional | `8444 2053 2083` | Quoted space-separated list. |
| `AWG_PORT_POOL` | UDP port pool used by `install.sh` auto-selection. | Optional | `51888 51889 51890 51891` | Quoted space-separated list. |
| `SERVICE_NAME` | `awg-gw` stub/debug service name. | Optional | `awg-gw` | Only for stub/manual runs. |
| `AWG_LISTEN_UDP` | `awg-gw` stub/debug UDP listen value. | Optional | `51821` | Only for stub/manual runs. |
| `AWG_ENDPOINT` | Endpoint used by the `awg-smoke` profile. | Optional | `host.docker.internal:51888` | Set to the worker public endpoint for remote smoke tests. |
| `TW_SMOKE_URL` | HTTP URL probed by `awg-smoke` through AWG. | Optional | `http://10.13.13.1/tw/healthz` | Any URL reachable through the tunnel. |
| `AWG_CLIENT_PRIVATE_KEY` | Overrides smoke client private key. | Optional | generated state value | Secret; use only for smoke debugging. |
| `AWG_CLIENT_PSK` | Overrides smoke client PSK. | Optional | generated state value | Secret; use only for smoke debugging. |
| `AWG_CLIENT_IP` | Overrides smoke client internal IP. | Optional | generated state value | Example `10.13.13.250`. |

## Local Build Checks

```sh
(cd agent && go build ./cmd/agent)
(cd awg-gw && go build ./cmd/awg-gw)
(cd awg-smoke && go build ./cmd/awg-smoke)
```

## Security Notes

- Never commit `.env`, `worker-state/`, generated AWG keys, Xray configs, or APK
  artifacts.
- Use a unique deployment dialect; the worker state is generated locally.
- Keep `APPLY_NFT=0` while testing. Review firewall/NAT rules before enabling it
  on a production server.
- Worker enrollment tokens are one-time secrets; create them in the orchestrator
  and do not store them in Git.

## 💚 Support the project

This project is free and developed in spare time. If it helps you, any support is
appreciated — thank you!

- **Bitcoin (BTC):** `bc1qdlqer9rtej6tpzdjzljdwltj7vxr4h6tv9eucp`
- **Ethereum (ETH):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **USDT (ERC-20):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **TRON (TRX):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`
- **USDT (TRC-20):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`

Thank you for your support! 🙏

## License

MIT. See `LICENSE`.
