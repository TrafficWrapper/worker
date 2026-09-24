# Worker Threat Model

[Русский](THREAT_MODEL.ru.md)

Canonical platform threat model:
<https://github.com/TrafficWrapper/orchestrator/blob/master/THREAT_MODEL.md>.

Worker-specific risks:

- The worker exposes public REALITY TCP and AWG UDP ports and can reveal the
  operator's hosting provider, IP address, timing, and traffic-volume patterns.
- AWG terminates on the worker. The worker can observe decrypted egress traffic
  after tunnel termination, so do not connect devices to untrusted workers.
- `agent` has no Docker socket: it drives Xray over a unix API socket in a
  volume shared only with the xray container, and AWG over UAPI. It still holds
  all worker keys and the enrollment identity. Treat the agent as a
  privileged component and restrict host access accordingly.
- `CAMOUFLAGE_DOMAIN` must be deployment-specific. Empty, `example.com`, and
  `example.org` values are refused by the agent and install script.
- Generated AWG dialects, worker state, Xray config, `.env`, and enroll tokens
  are sensitive and must not be committed or pasted into public issues.
