# TrafficWrapper Worker

[![CI](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml/badge.svg)](https://github.com/TrafficWrapper/worker/actions/workflows/ci.yml)

[English](README.md)

Data-plane узел TrafficWrapper — open-source self-hosted платформы private
transport для небольших operator deployments и transport-obfuscation research.
Worker enroll'ится в orchestrator, материализует approved devices как
Xray REALITY clients и AmneziaWG peers, а также отдаёт in-tunnel `/tw/`
distributor для client-config, APK updates и opt-in telemetry.

Оператор владеет worker host, camouflage domain, dialect, enroll token и
generated per-device material. Этот repository — infrastructure code; он не
содержит deployment domains, IP addresses, private keys или state.

TrafficWrapper разделён на три репозитория:

- [orchestrator](https://github.com/TrafficWrapper/orchestrator) — control plane.
- [worker](https://github.com/TrafficWrapper/worker) — этот data-plane node.
- [app](https://github.com/TrafficWrapper/app) — Android public client.

Обычный workflow: запустить orchestrator, создать worker enrollment token,
запустить этот worker, approve'нуть его в admin UI, затем bootstrap'ить
устройства через app.

Архитектура и threat model описаны в [ARCHITECTURE.md](ARCHITECTURE.ru.md) и
[THREAT_MODEL.md](THREAT_MODEL.ru.md).

## Troubleshooting

Канонический end-to-end troubleshooting guide находится в репозитории
orchestrator:
<https://github.com/TrafficWrapper/orchestrator/blob/master/TROUBLESHOOTING.ru.md>.
Для worker-specific failures начинайте с enrollment values `ORCH_URL`,
`ORCH_STATIC_PUBLIC_KEY`, `ENROLL_TOKEN`, `ORCH_INSECURE_TLS` и
`CAMOUFLAGE_DOMAIN`.

## Diagnostics

Worker agent отдаёт `/healthz`, `/self-describe` и `/metrics` на локальном agent
port (`127.0.0.1:9090` через default Compose mapping). AWG peer labels — salted
hashes без allowed IPs и endpoints, если не задан `TW_METRICS_RAW_PEER_LABELS=1`.
`/self-describe` и `/metrics` отвечают только loopback, шлюзу Docker-сети
(опубликованный порт хоста) и `AGENT_API_ALLOW_CIDRS`; другим контейнерам — 404.
См. [Monitoring](#monitoring).

У каждого сервиса есть Docker healthcheck, поэтому `docker compose ps`
показывает, какой из них не готов. Порядок старта: `agent` → `awg-gw` →
`distributor` → `xray`.

Для optional wire-level AWG stealth checks используйте `tools/dpi_probe.py` под
root на worker host с установленным `tcpdump`:

```sh
sudo python3 tools/dpi_probe.py --interface <iface> --dialect /worker-state/awg/awg-gw.json --json
python3 tools/dpi_probe.py --pcap capture.pcap --dialect /worker-state/awg/awg-gw.json --awg-port <udp-port>
# REALITY: compare what a prober without a client key sees with the real site
# (run from outside the worker, ideally from the censored network).
python3 tools/dpi_probe.py --reality <worker-ip>:<xray-port> --sni <CAMOUFLAGE_DOMAIN>
```

Probe читает public worker dialect envelope (`listen_port` + `dialect`) и
показывает, отсутствуют ли WG magic headers, видны ли padded handshakes,
отсутствуют ли vanilla handshakes и совпадает ли pre-handshake junk с dialect.

## Monitoring

`/metrics` отдаёт agent на `127.0.0.1:${AGENT_PORT:-9090}`:

```sh
curl -s http://127.0.0.1:9090/metrics | grep '^tw_worker_'
```

Порт слушает только localhost. Запускайте Prometheus (или `vmagent`/Grafana
Alloy) на самом worker host с host networking либо пробрасывайте порт через SSH;
не публикуйте его. Если метрики уходят с хоста, оставьте
`TW_METRICS_RAW_PEER_LABELS=0`.

Пример scrape config:

```yaml
scrape_configs:
  - job_name: trafficwrapper-worker
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:9090"]
        labels:
          worker: worker1
```

Пример правил алертов:

```yaml
groups:
  - name: trafficwrapper-worker
    rules:
      - alert: TWWorkerCamouflageProbeFailed
        expr: tw_worker_probe_ok == 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.probe }} probe failed; see self-describe health and agent logs"
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

Алерты про orchestrator имеют смысл только в platform mode (задан `ORCH_URL`).

## Что внутри

- `agent/` — получает signed bundles от orchestrator и применяет state.
- `xray/` — REALITY container.
- `awg-gw/` — AmneziaWG gateway и live peer materialization.
- `distributor/` — nginx distributor, доступный внутри туннеля.
- `awg-smoke/` — optional smoke test helper.
- `core/awg/...` — вложенные Go transport части, нужные worker binaries.

Go modules используют local `replace`, поэтому репозиторий собирается без
исходного монорепо.

## Требования

- Linux server с публичным IP.
- Docker и Docker Compose.
- `/dev/net/tun` и capability `NET_ADMIN` для AWG.
- Domain/SNI для REALITY camouflage.
- Минимум: 1 CPU и 1 GB RAM. На серверах с 1 GB добавьте swap; сборки и pull
  Docker images стабильнее с 2 GB+ RAM.

Установка Docker на чистом host:

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
```

## Быстрый старт

```sh
git clone https://github.com/TrafficWrapper/worker.git
cd worker
cp .env.example .env
```

Заполните `.env`:

- `ORCH_URL`: URL orchestrator. Если orchestrator запущен на том же Docker host,
  используйте `https://host.docker.internal:9091` и оставьте `ORCH_INSECURE_TLS=1`
  для встроенного self-signed dev-сертификата.
- `ORCH_STATIC_PUBLIC_KEY`: вывод `orchestrator public-key`.
- `ENROLL_TOKEN`: одноразовый worker token из admin UI orchestrator.
- `PUBLIC_ADDRESS`: публичный DNS/IP этого worker.
- `CAMOUFLAGE_DOMAIN`: реальный TLS 1.3 SNI/fallback домен для REALITY. Пустое
  значение и `example.com`/`example.org` отклоняются.
- `WAN_IF`: egress interface, из которого `install.sh` берёт публичный IP,
  если внешние сервисы расходятся.

Запуск:

```sh
docker compose up -d --build
```

После enrollment approve'ните worker в web UI orchestrator. Worker получит
signed config, сгенерирует/применит REALITY и AWG settings и начнёт отдавать
`/tw/` внутри туннеля.

## `docker compose up` vs `install.sh`

Для простого same-host или lab deployment достаточно заполнить `.env`, вручную
открыть выбранные TCP/UDP порты и выполнить `docker compose up -d --build`.

`install.sh` — optional helper для production-style hosts. Он может:

- выбрать свободные порты: 443 для REALITY, если свободен, иначе случайные
  (или из `REALITY_PORT_POOL` / `AWG_PORT_POOL`, если заданы);
- определить WAN interface и public egress;
- записать `.env`.

Запускайте его с реальным camouflage value, например:

```sh
CAMOUFLAGE_DOMAIN=www.your-real-tls13-domain.tld ./install.sh
```

`install.sh` не меняет firewall хоста. Docker сам публикует `XRAY_PORT`/tcp и
`AWG_PORT`/udp и делает NAT в обход цепочки `INPUT`, поэтому разрешайте или
ограничивайте эти порты в цепочке Docker `DOCKER-USER` (или в облачном
firewall). Опция `APPLY_NFT` удалена: при `APPLY_NFT=1` `install.sh`
завершается с ошибкой.

## Переменные окружения

Эти переменные читаются `.env.example`, Compose, install scripts или worker
binaries:

| Переменная | Назначение | Обязательна | Дефолт | Пример / как получить |
| --- | --- | --- | --- | --- |
| `ORCH_URL` | Base URL orchestrator для worker enroll/pull. | Обяз. для platform mode | empty | URL вашего orchestrator, например `https://orch.example.com`; same-host Docker: `https://host.docker.internal:9091`. |
| `ORCH_STATIC_PUBLIC_KEY` | Pinned Noise static public key orchestrator. | Обяз. для platform mode | empty | Выполните `orchestrator public-key` на orchestrator. |
| `ENROLL_TOKEN` | Одноразовый worker enrollment token. | Обяз. для первого enroll | empty | Создаётся в admin UI или CLI orchestrator. |
| `ORCH_INSECURE_TLS` | Разрешает insecure TLS к orchestrator для local dev. Обязательно, если ORCH использует дефолтный self-signed `ORCH_TLS=1`. | Обяз. для self-signed ORCH | `0` | Ставьте `1` только для test/self-signed ORCH; с production TLS оставляйте `0`. |
| `ORCH_ACK_INTERVAL` | Как часто agent подтверждает orchestrator применённый config. | Опц. | `90s` | Go duration от `10s` до `1h`. |
| `PUBLIC_ADDRESS` | Public DNS/IP worker, который увидят clients. | Опц. | detected egress IP | `worker1.example.com` или public IPv4. |
| `EGRESS_IP` | Явный public egress IP, который увидят clients и ORCH ack. Переопределяет сохранённый bootstrap state. | Опц. | public echo-IP probe, затем local route fallback | Задайте, если auto-detect ошибся. |
| `CAPACITY` | Capacity hint для orchestrator. | Опц. | `32` | Любое положительное число; невалидное значение останавливает agent. |
| `REALITY_INBOUNDS` | Дополнительные REALITY-inbound'ы в JSON (`name`, `network` tcp/xhttp, `listen_port`, `public_port`, `xhttp_path`, `xhttp_mode`, `xhttp_host`). Клиенты получают их как `reality_profiles` в self-describe для fallback. | Опц. | пусто | Опубликуйте каждый `listen_port` через `docker-compose.override.yml` с `ports: ["<public_port>:<listen_port>/tcp"]` у `xray`. |
| `WORKER_DIALECT_WIDE` | Генерировать новые диалекты AWG с широкими диапазонами junk-пакетов вместо общего отпечатка Jmin=8. | Опц. | `0` | Ставьте `1`, только когда все клиенты принимают Jc 3..16, Jmin 8..64. Ротация диалекта — в ARCHITECTURE. |
| `PUBLIC_ADDRESS_V6` | Глобальный IPv6-адрес, публикуемый как `address_v6`/`endpoint_v6` (или `auto` для автоопределения). Docker публикует порты и на IPv6, нужен только глобальный IPv6 на хосте. | Опц. | пусто | IPv6-эндпоинт часто доступен, когда IPv4-диапазон хостера заблокирован. `auto` разрешает `install.sh` на хосте (в контейнерах нет IPv6); сам агент редко может определить адрес и пишет предупреждение, если не смог. |
| `WORKER_DNS` | Публиковать AWG-клиентам резолвер в туннеле (compose-профиль `dns`). | Опц. | `0` | Запустите `docker compose --profile dns up -d` и задайте `WORKER_DNS=1`. |
| `DNS_UPSTREAMS` / `DNS_BOOTSTRAP` | DoH-апстримы и bootstrap-резолвер для профиля `dns`. | Опц. | Quad9 + Cloudflare DoH / `9.9.9.9:53` | URL через пробел. |
| `WORKER_BLOCK_SMTP` | Блокирует клиентам исходящую почту на порты 25/465/587 (Xray и AWG). | Опц. | `1` | Оставьте `1`: спам с IP воркера приводит к блокировке хоста. |
| `WORKER_BLOCK_BITTORRENT` | Блокирует BitTorrent для REALITY-клиентов (включает sniffing Xray с `routeOnly`). | Опц. | `1` | Оставьте `1`, чтобы хостер не получал DMCA-жалобы. |
| `REALITY_PROBE_ADDR` | Адрес, по которому агент проверяет свой REALITY-листенер как цензор без ключа клиента. | Опц. | `xray:8443` | Оставьте default Compose. |
| `WORKER_ALLOW_PRIVATE_EGRESS` | Разрешает VPN-клиентам доступ к приватным, loopback, link-local (cloud metadata) и внутренним Docker-адресам через воркер. | Опц. | `0` | Оставьте `0`: такие диапазоны блокируют и роутинг Xray, и forward-фильтр `awg-gw`. |
| `WORKER_SMOKE_PEERS` | Встроенные smoke-учётки (`p0-smoke` в REALITY и smoke-пир AWG). | Опц. | включены в standalone, выключены при `ORCH_URL` | `1` — оставить на воркере с оркестратором для `awg-smoke`, `0` — выключить. |
| `XRAY_PORT` | Public TCP port, mapped to REALITY container. | Опц. | выбирает `install.sh` (fallback Compose `2053`) | `install.sh` берёт 443, если свободен, иначе случайный порт 20000-59999, и сохраняет его при повторных запусках. |
| `AWG_PORT` | Public UDP port для AWG. | Опц. | выбирает `install.sh` (fallback Compose `51888`) | Случайный свободный UDP-порт 20000-59999, сохраняется при повторных запусках. |
| `AGENT_PORT` | Localhost TCP port для worker agent health/API. | Опц. | `9090` | По умолчанию `127.0.0.1:9090`. |
| `AGENT_API_ALLOW_CIDRS` | Дополнительные источники (CIDR или IP через запятую), которым можно читать `/self-describe` и `/metrics`. | Опц. | пусто | Только для scraper-контейнера в Compose-сети; loopback и порт хоста работают и без него. |
| `AWG_SUBNET` | Worker AWG subnet для internal IP устройств. | Опц. | `10.13.13.0/24` | Private subnet без конфликтов с host. |
| `AWG_GATEWAY` | AWG gateway address внутри `AWG_SUBNET`. | Опц. | первый host subnet | `10.13.13.1`. |
| `AWG_UAPI_SOCKET` | WireGuard/AmneziaWG UAPI socket path. | Опц. | `/var/run/wireguard/awg1.sock` | Обычно задаёт Compose. |
| `AWG_SERVER_KEEPALIVE` | Политика server-side persistent keepalive для всех AWG peer. | Опц. | `0` | Runtime-откат: вернуть прежнее значение и перезапустить `agent` вместе с `awg-gw`. |
| `XRAY_API_SOCKET` | Unix-сокет Xray API, общий для agent и xray через том `xray-api`. Изменения устройств применяются через него на лету; при прочих изменениях конфига entrypoint xray перезапускает Xray. Доступа к Docker socket у агента нет. | Опц. | `/run/xray-api/api.sock` | Оставьте default Compose. |
| `WORKER_VERSION` | Тег релиза готовых образов; пусто — локальная сборка. | Опц. | пусто | См. «Releases / prebuilt images». |
| `LOG_LEVEL` | Уровень логов agent. | Опц. | `info` | `debug`, `info`, `warn` или `error`. |
| `AWG_LOG_LEVEL` | Уровень логов `awg-gw` (AmneziaWG device). | Опц. | `error` | `verbose`, `error` или `silent`. |
| `TW_METRICS_RAW_PEER_LABELS` | Отдаёт в `/metrics` сырые public keys AWG peers и labels `allowed_ip`/`endpoint` вместо salted hashes. | Опц. | `0` | Оставьте `0`; `1` — только для локальной отладки. Старый `TW_METRICS_SCRUB_PEER_LABELS=0` скраб больше не выключает. |
| `TW_METRICS_SCRUB_SALT` | Salt для scrubbed peer labels. | Опц. | генерируется один раз в `worker-state/metrics_salt` | Одинаковое значение на нескольких воркерах позволяет сопоставлять peers между ними. |
| `DISTRIBUTOR_URL` | Internal URL `/tw/` distributor. | Опц. | `http://awg-gw:8080/tw` | Оставьте default для Compose. |
| `WORKER_AGENT_URL` | Public/internal URL override для agent self-reference. | Опц. | empty | Только для custom deployments. |
| `CAMOUFLAGE_DOMAIN` | REALITY serverName/camouflage SNI и fallback identity. | Обяз. для REALITY | empty, отказ до настройки | Используйте реальный TLS 1.3 домен, подходящий вашему deployment; `example.com` и `example.org` отклоняются. |
| `REALITY_DEST` | REALITY fallback destination для проб без валидного ключа клиента. | Опц. | `CAMOUFLAGE_DOMAIN:443` | Оставьте default, чтобы пробы видели реальный сайт. `awg-gw:9443` — внутренний self-signed fallback, который легко распознать активным зондированием; только для тестов. |
| `XRAY_NETWORK` | Xray REALITY stream network. | Опц. | `tcp` | Ставьте `xhttp` только когда operator настроил matching XHTTP params на этом worker. |
| `XRAY_XHTTP_PATH` | XHTTP path при `XRAY_NETWORK=xhttp`. | Опц. | empty | Operator-chosen path; public default нет. |
| `XRAY_XHTTP_MODE` | XHTTP mode при `XRAY_NETWORK=xhttp`. | Опц. | empty | Передаётся в Xray `xhttpSettings.mode`. |
| `REALITY_MAX_TIME_DIFF` | На сколько секунд время REALITY-хендшейка клиента может отличаться от часов воркера (Xray `maxTimeDiff`). | Опц. | `120` | Отвергает повторно проигранные ClientHello; `0` выключает проверку (клиенты с сильно сбитыми часами). |
| `XRAY_XHTTP_HOST` | XHTTP Host при `XRAY_NETWORK=xhttp`. | Опц. | `CAMOUFLAGE_DOMAIN` | Переопределяйте только если operator route config требует другой XHTTP host. Host, отличный от `CAMOUFLAGE_DOMAIN`, логируется и отражается как `degraded: xhttp_host`: маршруты оркестратора публикуются с доменом камуфляжа. |
| `AWG_INBOUNDS` | AWG-профили в JSON (`name`, `interface`, `listen_port`, `public_port`, `subnet`, `own_dialect`, `min_version_code`, ...). | Опц. | один базовый профиль | `min_version_code` — код, выведенный из имени версии приложения: major*10000+minor*100+patch (0.1.31 → 131), а не Android `versionCode`. Ротация диалекта — в ARCHITECTURE. |
| `XRAY_XHTTP_EXTRA_JSON` | Extra XHTTP JSON object. | Опц. | empty | Advanced passthrough как `xhttpSettings.extra`; оставьте empty, если не знаете Xray field shape. |
| `WORKER_STATE_DIR` | Worker state directory внутри containers. | Опц. | `/var/lib/trafficwrapper-worker` в binaries; Compose использует `/worker-state` | Оставьте Compose default, если не запускаете binaries вручную. |
| `TW_WORKER_DIALECT_JSON` | Advanced override AmneziaWG dialect JSON. | Опц. | generated dialect | Только для controlled testing. |
| `WAN_IF` | Interface для `install.sh` egress IP detection. | Опц. | auto-detect | `eth0`, `ens3` и т.п. |
| `EGRESS_VIA_WG` | Reserved deployment hint из `.env.example`; текущими binaries не используется. | Опц. | empty | Оставьте empty, если не расширяете scripts. |
| `COMPOSE` | Compose command для `install.sh`/`uninstall.sh`. | Опц. | `docker compose` | `docker-compose` на старых hosts. |
| `REALITY_PORT_POOL` | TCP-порты, из которых выбирает `install.sh`. | Опц. | 443, затем случайный | Список через пробел в кавычках, только чтобы зафиксировать выбор. |
| `AWG_PORT_POOL` | UDP-порты, из которых выбирает `install.sh`. | Опц. | случайный | Список через пробел в кавычках, только чтобы зафиксировать выбор. |
| `WAIT_TIMEOUT` | Сколько секунд `install.sh` ждёт, пока все сервисы станут healthy. | Опц. | `180` | Увеличьте на медленных хостах, где первая сборка дольше. |
| `SERVICE_NAME` | `awg-gw` stub/debug service name. | Опц. | `awg-gw` | Только для stub/manual runs. |
| `AWG_LISTEN_UDP` | `awg-gw` stub/debug UDP listen value. | Опц. | `51821` | Только для stub/manual runs. |
| `AWG_ENDPOINT` | Endpoint для профиля `awg-smoke`. | Опц. | `host.docker.internal:51888` | Задайте worker public endpoint для remote smoke tests. |
| `TW_SMOKE_URL` | HTTP URL, который `awg-smoke` проверяет через AWG. | Опц. | `http://10.13.13.1:8080/tw/config.json` | Любой URL, достижимый через туннель. |
| `AWG_CLIENT_PRIVATE_KEY` | Override smoke client private key. | Опц. | generated state value | Secret; только для smoke debugging. |
| `AWG_CLIENT_PSK` | Override smoke client PSK. | Опц. | generated state value | Secret; только для smoke debugging. |
| `AWG_CLIENT_IP` | Override smoke client internal IP. | Опц. | generated state value | Например `10.13.13.250`. |

При выкладке новой реализации peer-policy `agent` и `awg-gw` нужно собирать и
перезапускать вместе. Само значение задаётся во время запуска: для отката без
пересборки измените `AWG_SERVER_KEEPALIVE` в `.env` и перезапустите оба сервиса.
Отключение server keepalive само по себе не доказывает достижимость idle-клиента
за carrier NAT: для этого нужны отдельная device-проба и подтверждение оператора
из плана выкладки.

## Backup / upgrade / rollback

Вся идентичность воркера и сгенерированный материал лежат в `./worker-state`
(владелец root, секреты с mode `0600`):

| Путь | Содержимое |
| --- | --- |
| `bootstrap.json` | REALITY key pair, AWG server key, dialect, Noise static key (идентичность воркера для orchestrator). |
| `awg/` | `awg-gw.json` (интерфейс + dialect) и `peers.json` (материализованные AWG peers). |
| `xray/` | Сгенерированный Xray REALITY `config.json`. |
| `distributor/certs/` | TLS-сертификат и ключ distributor; в `distributor/tw/` лежат опубликованные файлы для клиентов. |
| `orch/` | `state.json` (enrollment/sequence state), последний подписанный `worker-config.json` + `.minisig`. |
| `metrics_salt` | Salt для scrubbed metrics labels (создаётся, если salt не задан и labels скрабятся). |

Потеря `bootstrap.json` означает новые ключи REALITY/AWG/Noise: всех клиентов
придётся перевыпустить, а воркер заново enroll-ить. Бэкапьте `worker-state/` и
`.env` вместе и храните архив так же строго, как сами ключи:

```sh
sudo tar -czf worker-backup-$(date -u +%Y%m%dT%H%M%SZ).tgz worker-state .env
```

`./uninstall.sh` пишет такой же архив (`worker-state-backup-<UTC>.tgz`) перед
удалением state. Флаги: `--yes` (без вопроса; обязателен без TTY),
`--keep-state`, `--purge-images` (дополнительно удаляет образы `worker-*`,
собранные или скачанные, и named volumes). Если `docker compose down` падает,
скрипт завершается с ошибкой и ничего не удаляет.

Перенос воркера на другой хост: остановите его (`docker compose down`),
скопируйте архив, склонируйте тот же релиз на новом хосте, распакуйте архив в
checkout, при смене адреса обновите `PUBLIC_ADDRESS`/`EGRESS_IP`, затем
`docker compose up -d --build --wait`. Никогда не запускайте два воркера с
одним и тем же `worker-state` одновременно.

Обновление:

```sh
git pull
docker compose up -d --build --wait
```

`git pull && ./install.sh` тоже работает, но `install.sh` заново генерирует
`.env` из `.env.example` (старый файл сохраняется как `.env.bak.<UTC>`) и переносит только порты, подсеть,
egress IP и `CAMOUFLAGE_DOMAIN`; `ORCH_*` и остальные настройки перенесите из
бэкапа и снова выполните `docker compose up -d`.

Откат на предыдущий релиз (сначала сделайте бэкап; state, записанный новой
версией, не обязательно читается старой):

```sh
git checkout <tag>
docker compose up -d --build
```

## Releases / prebuilt images

Каждый тег `v*` собирается [`.github/workflows/release.yml`](.github/workflows/release.yml)
в multi-arch (`linux/amd64`, `linux/arm64`) образы в GHCR, по одному на сервис:
`ghcr.io/trafficwrapper/worker-<service>` для `agent`, `awg-gw`, `awg-smoke`,
`distributor`, `xray` и `dns`. Каждый образ получает теги `v1.2.3`, `1.2.3`,
`1.2` и `sha-<short>`, содержит SLSA provenance и SBOM и подписан cosign
keyless (Sigstore, GitHub OIDC). После того как все образы опубликованы и
подписаны, создаётся GitHub Release с автоматически сгенерированными notes.

Запуск релиза без локальной сборки (переключитесь на тот же тег, чтобы
`docker-compose.yml` и скрипты соответствовали образам):

```sh
git fetch --tags && git checkout v1.2.3
# закрепите релиз в .env: WORKER_VERSION=v1.2.3
WORKER_VERSION=v1.2.3 docker compose pull
WORKER_VERSION=v1.2.3 docker compose up -d --no-build --wait
```

Без `WORKER_VERSION` compose использует тег `local`, и
`docker compose up -d --build` собирает из исходников, как раньше.

`install.sh` действует так же: если в `.env` задан `WORKER_VERSION`, он
скачивает релиз, проверяет подпись каждого образа `worker-*` по digest через
cosign (см. ниже) и запускает с `--no-build`; без cosign останавливается,
если не задан `ALLOW_UNVERIFIED_IMAGES=1`. Без `WORKER_VERSION` собирает из
исходников.

Откат на предыдущий тег (сначала сделайте бэкап, см. выше):

```sh
git checkout v1.2.2
WORKER_VERSION=v1.2.2 docker compose pull
WORKER_VERSION=v1.2.2 docker compose up -d --no-build --wait
```

Проверка подписи перед деплоем (нужен
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v2+):

```sh
cosign verify ghcr.io/trafficwrapper/worker-agent:v1.2.3 \
  --certificate-identity-regexp 'https://github.com/TrafficWrapper/worker/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Повторите для каждого скачиваемого образа `worker-<service>`. Provenance и SBOM
можно посмотреть через `docker buildx imagetools inspect <image> --format '{{ json .Provenance }}'`
(или `.SBOM`).

## Локальная проверка сборки

```sh
(cd agent && go build ./cmd/agent)
(cd awg-gw && go build ./cmd/awg-gw)
(cd awg-smoke && go build ./cmd/awg-smoke)
```

## Безопасность

- Не коммитьте `.env`, `worker-state/`, generated AWG keys, Xray configs или APK
  artifacts.
- Используйте уникальный deployment dialect; worker state генерируется локально.
- Клиенты не могут через воркер обращаться к приватным, loopback, link-local
  и внутренним Docker-адресам (API агента, `/metrics`, хост, cloud metadata),
  пока не задан `WORKER_ALLOW_PRIVATE_EGRESS=1`. Xray выбрасывает приватные
  адреса из ответов DNS и подключается к адресу, который сам разрешил (только
  IPv4), поэтому имя не может смениться на приватный адрес между проверкой
  маршрута и подключением.
- Если оркестратор выключает протокол (`desired_state.reality.enabled` или
  `awg.enabled` = false), воркер не раздаёт для него учётные данные устройств.
  При отзыве воркера агент удаляет всех пользователей и peers, перезапускает
  Xray, чтобы оборвать открытые сессии, удаляет опубликованный клиентский
  конфиг и APK и повторяет запрос раз в час.
- Фильтруйте опубликованные порты в цепочке `DOCKER-USER`, а не `INPUT`:
  Docker пробрасывает опубликованные порты раньше, чем их видят правила `INPUT`.
- Worker enrollment tokens одноразовые; создавайте их в orchestrator и не
  храните в Git.

## 💚 Поддержать проект

Проект бесплатный и развивается на энтузиазме. Если он вам помогает — спасибо за
любую поддержку!

- **Bitcoin (BTC):** `bc1qd7q4gq2ekm3auplqhnjal4nfyav8xq0apja7et`
- **Ethereum (ETH):** `0x03666a20D495feC59aBBccC4c291786eC5C77F9F`
- **Solana (SOL):** `AdLMjpxAUa94yFGEmTfGNHFyREmAaZzzKhDWjJEhbGC3`
- **TRON (TRX):** `TBtM4zLxZCEDWofPyAQB5ghTEDz1zXY69i`
- **Toncoin (TON):** `UQD_InCvoP55lrzV9F5QoTee3-W5CwDmK6ajwaJOZk5lEIxy`

С благодарностью за вашу поддержку! 🙏

## Лицензия

MIT. См. `LICENSE`.
