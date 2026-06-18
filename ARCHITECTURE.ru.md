# Архитектура Worker

[English](ARCHITECTURE.md)

Каноническая architecture платформы находится в репозитории orchestrator:
<https://github.com/TrafficWrapper/orchestrator/blob/master/ARCHITECTURE.md>.

Этот репозиторий реализует data plane:

- `agent/cmd/agent/main.go` читает worker env/state, генерирует уникальные
  локальные REALITY, AWG, Noise и dialect material, открывает
  health/self-describe и запускает orchestrator loop.
- `agent/cmd/agent/orch_client.go` выполняет worker enroll, config pull, nudge,
  ack и telemetry через Noise_XK HTTPS envelope, pinned по
  `ORCH_STATIC_PUBLIC_KEY`.
- `agent/cmd/agent/materialize.go` проверяет signed bundles и материализует
  approved devices в Xray REALITY clients и AmneziaWG peers.
- `xray/` является REALITY ingress. `CAMOUFLAGE_DOMAIN` должен быть реальным
  TLS 1.3 domain; placeholders отклоняются.
- `awg-gw/` завершает AWG и применяет live peer state.
- `distributor/` отдаёт `/tw/` только внутри tunnel для client config, update
  artifacts и telemetry paths.

Worker является exit/decryption point. Используйте только workers, которым
deployment owner операционно доверяет.
