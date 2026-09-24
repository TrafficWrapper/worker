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

## REALITY-профили, Vision и когорты shortId

- `reality_profiles` в self-describe перечисляет все REALITY-inbound'ы
  (базовый и из `REALITY_INBOUNDS`) с сетью и допустимыми flow.
- Vision (`xtls-rprx-vision`) включается для каждого устройства через
  `reality_flow` в подписанном worker config. Xray отвергает клиента, чей flow
  не совпадает с аккаунтом, поэтому оркестратор выставляет его только клиентам
  с поддержкой Vision. У XHTTP-профилей flow не бывает.
- У воркера 16 когортных shortId (`reality.cohort_short_ids`). Оркестратор
  закрепляет устройство за когортой; shortId из
  `desired_state.revoked_short_ids` перестаёт приниматься, так что утёкшую
  когорту можно отрезать без смены ключа воркера.
