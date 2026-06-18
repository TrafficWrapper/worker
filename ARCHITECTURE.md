# Worker Architecture

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
