# Worker Architecture

[Русский](ARCHITECTURE.ru.md)

Canonical platform architecture lives in the orchestrator repository:
<https://github.com/TrafficWrapper/orchestrator/blob/master/ARCHITECTURE.md>.

This repository implements the data plane:

- `agent/cmd/agent/main.go` reads worker env/state, generates unique local
  REALITY, AWG, Noise, and dialect material, exposes health/self-describe, and
  runs the orchestrator loop.
- `agent/cmd/agent/orch_client.go` performs worker enroll, config pull, nudge,
  ack, and telemetry over the Noise_XK HTTPS envelope pinned by
  `ORCH_STATIC_PUBLIC_KEY`.
- `agent/cmd/agent/materialize.go` verifies signed bundles and materializes
  approved devices into Xray REALITY clients and AmneziaWG peers.
- `xray/` is the REALITY ingress. `CAMOUFLAGE_DOMAIN` must be a real TLS 1.3
  domain; placeholders are refused.
- `awg-gw/` terminates AWG and applies live peer state.
- `distributor/` serves `/tw/` only inside the tunnel for client config, update
  artifacts, and telemetry paths.

The worker is an exit/decryption point. Only use workers that the deployment
owner trusts operationally.

## REALITY profiles, Vision and short ID cohorts

- `reality_profiles` in self-describe lists every REALITY inbound (the base one
  plus `REALITY_INBOUNDS`), with its network and the flows it accepts.
- Vision (`xtls-rprx-vision`) is enabled per device through `reality_flow` in
  the signed worker config. Xray rejects a client whose flow differs from its
  account, so the orchestrator must set it only for clients that use Vision.
  XHTTP profiles never carry a flow.
- Each worker has 16 cohort short IDs (`reality.cohort_short_ids`). The
  orchestrator assigns a device to a cohort; listing a short ID in
  `desired_state.revoked_short_ids` stops accepting it, so a leaked cohort
  can be cut off without rotating the worker key.

## Rotating the AWG dialect

The dialect cannot change in place on a port without breaking every client, so
it is rotated through profiles: add an `AWG_INBOUNDS` profile with
`"own_dialect": true` on a new port and subnet (and its own `awg-gw` service),
let the orchestrator move clients to it using `awg_profiles` in self-describe,
then remove the old profile. `WORKER_DIALECT_WIDE=1` draws junk-packet
parameters (Jc, Jmin, Jmax) from the wider ranges; enable it only after every
client accepts them.

## Per-device AWG rate limits

`desired_state.approved_devices[].limits.download_mbps` / `upload_mbps` are
written into the AWG peer registry. `awg-gw` re-reads the registry every 30s
and, when the limits change, rebuilds `tc` shaping on the tunnel interface: an
HTB class per limited client for download and an ingress policer for upload.
REALITY clients are not rate limited (Xray has no per-user shaping).
