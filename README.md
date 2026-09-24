# TrafficWrapper Worker

[![CI](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml/badge.svg)](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml)

[Русский](README.ru.md)

Data-plane node for TrafficWrapper, an open-source self-hosted private transport
platform for small operator deployments and transport-obfuscation research.
A worker enrolls into an orchestrator, materializes approved devices as Xray
REALITY clients and AmneziaWG peers, and exposes the in-tunnel `/tw/`
distributor for client config, APK updates, and opt-in telemetry.

The operator owns the worker host, camouflage domain, dialect, enroll token,
and generated per-device material. This repository is infrastructure code; it
does not contain deployment domains, IP addresses, private keys, or state.

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
labels include public keys, allowed IPs, and endpoints unless
`TW_METRICS_SCRUB_PEER_LABELS=1`. See [Monitoring](#monitoring).

Every service has a Docker healthcheck, so `docker compose ps` shows which one
is not ready. Startup order is `agent` → `awg-gw` → `distributor` → `xray`.

For optional wire-level AWG stealth checks, use `tools/dpi_probe.py` as root on
the worker host with `tcpdump` installed:

```sh
sudo python3 tools/dpi_probe.py --interface <iface> --dialect /worker-state/awg/awg-gw.json --json
python3 tools/dpi_probe.py --pcap capture.pcap --dialect /worker-state/awg/awg-gw.json --awg-port <udp-port>
```

The probe reads the public worker dialect envelope (`listen_port` + `dialect`)
and reports whether WG magic headers are absent, padded handshakes are visible,
vanilla handshakes are absent, and pre-handshake junk matches the dialect.

## Monitoring

`/metrics` is served by the agent on `127.0.0.1:${AGENT_PORT:-9090}`:

```sh
curl -s http://127.0.0.1:9090/metrics | grep '^tw_worker_'
```

The port is bound to localhost only. Run Prometheus (or an agent such as
`vmagent`/Grafana Alloy) on the worker host with host networking, or forward
the port over SSH; do not publish it. Enable
`TW_METRICS_SCRUB_PEER_LABELS=1` before metrics leave the host.

Example scrape config:

```yaml
scrape_configs:
  - job_name: trafficwrapper-worker
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:9090"]
        labels:
          worker: worker1
```

Example alert rules:

```yaml
groups:
  - name: trafficwrapper-worker
    rules:
      - alert: TWWorkerAWGInterfaceDown
        expr: tw_worker_awg_interface_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "AWG interface is down on {{ $labels.worker }}"
      - alert: TWWorkerOrchestratorUnreachable
        expr: time() - tw_worker_orch_last_success_timestamp_seconds > 600
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "No successful orchestrator request for 10m on {{ $labels.worker }}"
      - alert: TWWorkerXrayRestartLoop
        expr: increase(tw_worker_xray_apply_total{mode="restart"}[1h]) > 3
        labels:
          severity: warning
        annotations:
          summary: "Xray restarted more than 3 times in 1h on {{ $labels.worker }}"
      - alert: TWWorkerDistributorCertExpiring
        expr: tw_worker_distributor_cert_expiry_seconds < 7 * 86400
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Distributor TLS certificate expires in less than 7 days on {{ $labels.worker }}"
      - alert: TWWorkerConfigNotApplied
        expr: tw_worker_orch_desired_seq - tw_worker_orch_applied_seq > 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Worker has not applied the latest orchestrator config for 15m on {{ $labels.worker }}"
```

The orchestrator alerts only make sense in platform mode (`ORCH_URL` set).

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
| `ORCH_ACK_INTERVAL` | How often the agent acknowledges the applied config to the orchestrator. | Optional | `90s` | Go duration between `10s` and `1h`. |
| `PUBLIC_ADDRESS` | Public DNS name or IP advertised to clients. | Optional | detected egress IP | `worker1.example.com` or a public IPv4. |
| `EGRESS_IP` | Explicit public egress IP advertised to clients and sent in worker ack. Overrides persisted bootstrap state. | Optional | public echo-IP probe, then local route fallback | Set if auto-detection is wrong. |
| `CAPACITY` | Capacity hint reported to the orchestrator. | Optional | `32` | Any positive integer; invalid values stop the agent. |
| `WORKER_ALLOW_PRIVATE_EGRESS` | Lets VPN clients reach private, loopback, link-local (cloud metadata) and Docker-internal addresses through the worker. | Optional | `0` | Keep `0`: both Xray routing and the `awg-gw` forward filter block those ranges. |
| `WORKER_SMOKE_PEERS` | Built-in smoke credentials (`p0-smoke` REALITY user and AWG smoke peer). | Optional | enabled standalone, disabled with `ORCH_URL` | `1` to keep them on an orchestrated worker for `awg-smoke`, `0` to disable. |
| `XRAY_PORT` | Public TCP port mapped to the REALITY container. | Optional | `2053` | `8444`, `2053`, or another free TCP port. |
| `AWG_PORT` | Public UDP port mapped to AWG. | Optional | `51888` | Any free UDP port. |
| `AGENT_PORT` | Localhost TCP port exposing the worker agent health/API. | Optional | `9090` | `127.0.0.1:9090` by default. |
| `AWG_SUBNET` | Worker AWG subnet for device internal IPs. | Optional | `10.13.13.0/24` | Use a private subnet not colliding with your host. |
| `AWG_GATEWAY` | AWG gateway address inside `AWG_SUBNET`. | Optional | first host in subnet | `10.13.13.1`. |
| `AWG_UAPI_SOCKET` | WireGuard/AmneziaWG UAPI socket path. | Optional | `/var/run/wireguard/awg1.sock` | Usually set by Compose. |
| `AWG_SERVER_KEEPALIVE` | Server-side persistent keepalive policy for every AWG peer. | Optional | `0` | Runtime rollback: set the previous value, then restart both `agent` and `awg-gw`. |
| `XRAY_CONTAINER_NAME` | Docker container the agent uses for Xray user updates. Device changes are applied live through the Xray API; other config changes restart the container. Fallback discovery is limited to the agent's own compose project. | Optional | `worker-xray-1` | Compose sets a stable `container_name` with this value; override only if you also change the xray service container name. |
| `DOCKER_SOCKET` | Docker socket path used by the agent. | Optional | `/var/run/docker.sock` | Compose mounts the host Docker socket. |
| `LOG_LEVEL` | Agent log level. | Optional | `info` | `debug`, `info`, `warn` or `error`. |
| `AWG_LOG_LEVEL` | `awg-gw` (AmneziaWG device) log level. | Optional | `error` | `verbose`, `error` or `silent`. |
| `TW_METRICS_SCRUB_PEER_LABELS` | Replaces AWG peer public keys in `/metrics` labels with salted hashes and drops the `allowed_ip`/`endpoint` labels. | Optional | `0` | Set `1` when metrics leave the host (remote Prometheus, shared dashboards). |
| `TW_METRICS_SCRUB_SALT` | Salt for scrubbed peer labels. | Optional | generated once into `worker-state/metrics_salt` | Set the same value on several workers to correlate peers across them. |
| `DISTRIBUTOR_URL` | Internal URL of the `/tw/` distributor. | Optional | `http://awg-gw:8080/tw` | Keep default for Compose. |
| `WORKER_AGENT_URL` | Public/internal URL override for agent self-reference. | Optional | empty | Set only for custom deployments. |
| `CAMOUFLAGE_DOMAIN` | REALITY serverName/camouflage SNI and fallback identity. | Required for REALITY | empty, refused until set | Use a real TLS 1.3 domain that fits your deployment; `example.com` and `example.org` are rejected. |
| `REALITY_DEST` | REALITY fallback destination for probes without a valid client key. | Optional | `CAMOUFLAGE_DOMAIN:443` | Keep the default so probes see the real site. `awg-gw:9443` is an internal self-signed fallback that active probing can fingerprint; use it only for tests. |
| `XRAY_NETWORK` | Xray REALITY stream network. | Optional | `tcp` | Set `xhttp` only when the operator configures matching XHTTP params on this worker. |
| `XRAY_XHTTP_PATH` | XHTTP path used when `XRAY_NETWORK=xhttp`. | Optional | empty | Operator-chosen path; no public default. |
| `XRAY_XHTTP_MODE` | XHTTP mode used when `XRAY_NETWORK=xhttp`. | Optional | empty | Passed through to Xray `xhttpSettings.mode`. |
| `XRAY_XHTTP_HOST` | XHTTP Host used when `XRAY_NETWORK=xhttp`. | Optional | `CAMOUFLAGE_DOMAIN` | Override only when the operator route config needs a different XHTTP host. |
| `XRAY_XHTTP_EXTRA_JSON` | Extra XHTTP JSON object. | Optional | empty | Advanced passthrough as `xhttpSettings.extra`; keep empty unless you know the Xray field shape. |
| `WORKER_STATE_DIR` | Worker state directory inside containers. | Optional | `/var/lib/trafficwrapper-worker` in binaries; Compose uses `/worker-state` | Keep Compose default unless running binaries manually. |
| `TW_WORKER_DIALECT_JSON` | Advanced override for the AmneziaWG dialect JSON. | Optional | generated dialect | Use only for controlled testing. |
| `WAN_IF` | Interface used by `install.sh` to detect egress IP. | Optional | auto-detect | `eth0`, `ens3`, etc. |
| `APPLY_NFT` | Enables install-time nft accept rules for selected ports. | Optional | `0` | Set `1` only after reviewing rules. |
| `EGRESS_VIA_WG` | Reserved deployment hint in `.env.example`; not consumed by current binaries. | Optional | empty | Leave empty unless you extend deployment scripts. |
| `COMPOSE` | Compose command used by `install.sh`/`uninstall.sh`. | Optional | `docker compose` | `docker-compose` on older hosts. |
| `REALITY_PORT_POOL` | TCP port pool used by `install.sh` auto-selection. | Optional | `8444 2053 2083` | Quoted space-separated list. |
| `AWG_PORT_POOL` | UDP port pool used by `install.sh` auto-selection. | Optional | `51888 51889 51890 51891` | Quoted space-separated list. |
| `WAIT_TIMEOUT` | Seconds `install.sh` waits for all services to become healthy. | Optional | `180` | Raise on slow hosts where the first build takes longer. |
| `SERVICE_NAME` | `awg-gw` stub/debug service name. | Optional | `awg-gw` | Only for stub/manual runs. |
| `AWG_LISTEN_UDP` | `awg-gw` stub/debug UDP listen value. | Optional | `51821` | Only for stub/manual runs. |
| `AWG_ENDPOINT` | Endpoint used by the `awg-smoke` profile. | Optional | `host.docker.internal:51888` | Set to the worker public endpoint for remote smoke tests. |
| `TW_SMOKE_URL` | HTTP URL probed by `awg-smoke` through AWG. | Optional | `http://10.13.13.1:8080/tw/config.json` | Any URL reachable through the tunnel. |
| `AWG_CLIENT_PRIVATE_KEY` | Overrides smoke client private key. | Optional | generated state value | Secret; use only for smoke debugging. |
| `AWG_CLIENT_PSK` | Overrides smoke client PSK. | Optional | generated state value | Secret; use only for smoke debugging. |
| `AWG_CLIENT_IP` | Overrides smoke client internal IP. | Optional | generated state value | Example `10.13.13.250`. |

`agent` and `awg-gw` must be rebuilt and restarted together when deploying a
new peer-policy implementation. The policy value itself is runtime-configured:
edit `AWG_SERVER_KEEPALIVE` in `.env` and restart both services to roll back
without rebuilding. Disabling server keepalive is not proof that idle clients
remain reachable behind carrier NAT; that requires the separate device test and
operator confirmation described by the deployment plan.

## Backup / upgrade / rollback

All worker identity and generated material lives in `./worker-state` (owned by
root, secrets are mode `0600`):

| Path | Contents |
| --- | --- |
| `bootstrap.json` | REALITY key pair, AWG server key, dialect, Noise static key (worker identity towards the orchestrator). |
| `awg/` | `awg-gw.json` (interface + dialect) and `peers.json` (materialized AWG peers). |
| `xray/` | Generated Xray REALITY `config.json`. |
| `distributor/certs/` | Distributor TLS certificate and key; `distributor/tw/` holds published client files. |
| `orch/` | `state.json` (enrollment/sequence state), last signed `worker-config.json` + `.minisig`. |
| `metrics_salt` | Salt for scrubbed metrics labels (created when `TW_METRICS_SCRUB_PEER_LABELS=1` and no salt is set). |

Losing `bootstrap.json` means new REALITY/AWG/Noise keys: every client must be
re-provisioned and the worker re-enrolled. Back up `worker-state/` and `.env`
together, and keep the archive as secret as the keys themselves:

```sh
sudo tar -czf worker-backup-$(date -u +%Y%m%dT%H%M%SZ).tgz worker-state .env
```

`./uninstall.sh` writes the same archive (`worker-state-backup-<UTC>.tgz`)
before deleting state. Flags: `--yes` (no prompt, required without a TTY),
`--keep-state`, `--purge-images` (also removes locally built images and the
`awg-run` volume).

Move a worker to another host: stop it (`docker compose down`), copy the
archive, clone the same release on the new host, extract the archive into the
checkout, update `PUBLIC_ADDRESS`/`EGRESS_IP` if the address changed, then
`docker compose up -d --build --wait`. Never run two workers with the same
`worker-state` at the same time.

Upgrade:

```sh
git pull
docker compose up -d --build --wait
```

`git pull && ./install.sh` also works, but `install.sh` regenerates `.env` from
`.env.example` (the previous file is saved as `.env.bak.<UTC>`) and only carries over
ports, subnet, egress IP and `CAMOUFLAGE_DOMAIN`; merge `ORCH_*` and other
settings back from the backup and run `docker compose up -d` again.

Rollback to a previous release (take a backup first; state written by a newer
version is not guaranteed to be readable by an older one):

```sh
git checkout <tag>
docker compose up -d --build
```

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
- Clients cannot reach private, loopback, link-local or Docker-internal
  addresses through the worker (agent API, `/metrics`, the host, cloud metadata)
  unless `WORKER_ALLOW_PRIVATE_EGRESS=1`.
- Keep `APPLY_NFT=0` while testing. Review firewall/NAT rules before enabling it
  on a production server.
- Worker enrollment tokens are one-time secrets; create them in the orchestrator
  and do not store them in Git.

## 💚 Support the project

This project is free and developed in spare time. If it helps you, any support is
appreciated — thank you!

- **Bitcoin (BTC):** `bc1qd7q4gq2ekm3auplqhnjal4nfyav8xq0apja7et`
- **Ethereum (ETH):** `0x03666a20D495feC59aBBccC4c291786eC5C77F9F`
- **Solana (SOL):** `AdLMjpxAUa94yFGEmTfGNHFyREmAaZzzKhDWjJEhbGC3`
- **TRON (TRX):** `TBtM4zLxZCEDWofPyAQB5ghTEDz1zXY69i`
- **Toncoin (TON):** `UQD_InCvoP55lrzV9F5QoTee3-W5CwDmK6ajwaJOZk5lEIxy`

Thank you for your support! 🙏

## License

MIT. See `LICENSE`.
