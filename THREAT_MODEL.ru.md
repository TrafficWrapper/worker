# Модель угроз Worker

[English](THREAT_MODEL.md)

Каноническая threat model платформы:
<https://github.com/TrafficWrapper/orchestrator/blob/master/THREAT_MODEL.md>.

Worker-specific risks:

- Worker открывает public REALITY TCP и AWG UDP ports и может раскрывать hosting
  provider operator'а, IP address, timing и traffic-volume patterns.
- AWG завершается на worker. Worker может видеть decrypted egress traffic после
  tunnel termination, поэтому не подключайте devices к untrusted workers.
- У `agent` нет доступа к Docker socket: Xray он управляет через unix-сокет API
  в томе, общем только с контейнером xray, а AWG — через UAPI. При этом он хранит
  все ключи воркера и enrollment-идентичность. Считайте
  agent privileged component и соответственно ограничивайте host access.
- `CAMOUFLAGE_DOMAIN` должен быть deployment-specific. Empty, `example.com` и
  `example.org` values отклоняются agent'ом и install script.
- Generated AWG dialects, worker state, Xray config, `.env` и enroll tokens
  являются sensitive и не должны попадать в commits или public issues.
