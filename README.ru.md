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
port (`127.0.0.1:9090` через default Compose mapping). Prometheus endpoint
предназначен для localhost scraping, потому что AWG peer labels содержат public
keys, allowed IPs и endpoints.

Для optional wire-level AWG stealth checks используйте `tools/dpi_probe.py` под
root на worker host с установленным `tcpdump`:

```sh
sudo python3 tools/dpi_probe.py --interface <iface> --dialect /worker-state/awg/awg-gw.json --json
python3 tools/dpi_probe.py --pcap capture.pcap --dialect /worker-state/awg/awg-gw.json --awg-port <udp-port>
```

Probe читает public worker dialect envelope (`listen_port` + `dialect`) и
показывает, отсутствуют ли WG magic headers, видны ли padded handshakes,
отсутствуют ли vanilla handshakes и совпадает ли pre-handshake junk с dialect.

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
- `WAN_IF`: egress interface, если включаете nft NAT automation.
- `APPLY_NFT=1`: только после проверки generated NAT/firewall rules.

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

- автоматически выбрать свободные порты из `REALITY_PORT_POOL` и
  `AWG_PORT_POOL`;
- определить WAN interface и public egress;
- записать `.env`;
- при `APPLY_NFT=1` поставить nft accept/NAT rules для выбранных портов.

Запускайте его с реальным camouflage value, например:

```sh
CAMOUFLAGE_DOMAIN=www.your-real-tls13-domain.tld ./install.sh
```

Держите `APPLY_NFT=0`, пока не проверите firewall/NAT changes.

## Переменные окружения

Эти переменные читаются `.env.example`, Compose, install scripts или worker
binaries:

| Переменная | Назначение | Обязательна | Дефолт | Пример / как получить |
| --- | --- | --- | --- | --- |
| `ORCH_URL` | Base URL orchestrator для worker enroll/pull. | Обяз. для platform mode | empty | URL вашего orchestrator, например `https://orch.example.com`; same-host Docker: `https://host.docker.internal:9091`. |
| `ORCH_STATIC_PUBLIC_KEY` | Pinned Noise static public key orchestrator. | Обяз. для platform mode | empty | Выполните `orchestrator public-key` на orchestrator. |
| `ENROLL_TOKEN` | Одноразовый worker enrollment token. | Обяз. для первого enroll | empty | Создаётся в admin UI или CLI orchestrator. |
| `ORCH_INSECURE_TLS` | Разрешает insecure TLS к orchestrator для local dev. Обязательно, если ORCH использует дефолтный self-signed `ORCH_TLS=1`. | Обяз. для self-signed ORCH | `0` | Ставьте `1` только для test/self-signed ORCH; с production TLS оставляйте `0`. |
| `PUBLIC_ADDRESS` | Public DNS/IP worker, который увидят clients. | Опц. | detected egress IP | `worker1.example.com` или public IPv4. |
| `EGRESS_IP` | Явный public egress IP, который увидят clients и ORCH ack. Переопределяет сохранённый bootstrap state. | Опц. | public echo-IP probe, затем local route fallback | Задайте, если auto-detect ошибся. |
| `CAPACITY` | Capacity hint для orchestrator. | Опц. | `32` | Любое положительное число. |
| `XRAY_PORT` | Public TCP port, mapped to REALITY container. | Опц. | `2053` | `8444`, `2053` или другой свободный TCP port. |
| `AWG_PORT` | Public UDP port для AWG. | Опц. | `51888` | Любой свободный UDP port. |
| `AGENT_PORT` | Localhost TCP port для worker agent health/API. | Опц. | `9090` | По умолчанию `127.0.0.1:9090`. |
| `AWG_SUBNET` | Worker AWG subnet для internal IP устройств. | Опц. | `10.13.13.0/24` | Private subnet без конфликтов с host. |
| `AWG_GATEWAY` | AWG gateway address внутри `AWG_SUBNET`. | Опц. | первый host subnet | `10.13.13.1`. |
| `AWG_UAPI_SOCKET` | WireGuard/AmneziaWG UAPI socket path. | Опц. | `/var/run/wireguard/awg1.sock` | Обычно задаёт Compose. |
| `XRAY_CONTAINER_NAME` | Docker container name, который agent перезапускает/переписывает для Xray после изменения approved devices. | Опц. | `worker-xray-1` | Compose задаёт стабильный `container_name` с этим значением; меняйте только вместе с именем xray service container. |
| `DOCKER_SOCKET` | Docker socket path для agent. | Опц. | `/var/run/docker.sock` | Compose монтирует host Docker socket. |
| `DISTRIBUTOR_URL` | Internal URL `/tw/` distributor. | Опц. | `http://awg-gw:8080/tw` | Оставьте default для Compose. |
| `WORKER_AGENT_URL` | Public/internal URL override для agent self-reference. | Опц. | empty | Только для custom deployments. |
| `CAMOUFLAGE_DOMAIN` | REALITY serverName/camouflage SNI и fallback identity. | Обяз. для REALITY | empty, отказ до настройки | Используйте реальный TLS 1.3 домен, подходящий вашему deployment; `example.com` и `example.org` отклоняются. |
| `REALITY_DEST` | REALITY fallback destination. | Опц. | `awg-gw:9443` | Оставьте self-steal default или задайте `host:443`. |
| `XRAY_NETWORK` | Xray REALITY stream network. | Опц. | `tcp` | Ставьте `xhttp` только когда operator настроил matching XHTTP params на этом worker. |
| `XRAY_XHTTP_PATH` | XHTTP path при `XRAY_NETWORK=xhttp`. | Опц. | empty | Operator-chosen path; public default нет. |
| `XRAY_XHTTP_MODE` | XHTTP mode при `XRAY_NETWORK=xhttp`. | Опц. | empty | Передаётся в Xray `xhttpSettings.mode`. |
| `XRAY_XHTTP_HOST` | XHTTP Host при `XRAY_NETWORK=xhttp`. | Опц. | `CAMOUFLAGE_DOMAIN` | Переопределяйте только если operator route config требует другой XHTTP host. |
| `XRAY_XHTTP_EXTRA_JSON` | Extra XHTTP JSON object. | Опц. | empty | Advanced passthrough как `xhttpSettings.extra`; оставьте empty, если не знаете Xray field shape. |
| `WORKER_STATE_DIR` | Worker state directory внутри containers. | Опц. | `/var/lib/trafficwrapper-worker` в binaries; Compose использует `/worker-state` | Оставьте Compose default, если не запускаете binaries вручную. |
| `TW_WORKER_DIALECT_JSON` | Advanced override AmneziaWG dialect JSON. | Опц. | generated dialect | Только для controlled testing. |
| `WAN_IF` | Interface для `install.sh` egress IP detection. | Опц. | auto-detect | `eth0`, `ens3` и т.п. |
| `APPLY_NFT` | Включает install-time nft accept rules для выбранных портов. | Опц. | `0` | `1` только после проверки rules. |
| `EGRESS_VIA_WG` | Reserved deployment hint из `.env.example`; текущими binaries не используется. | Опц. | empty | Оставьте empty, если не расширяете scripts. |
| `COMPOSE` | Compose command для `install.sh`/`uninstall.sh`. | Опц. | `docker compose` | `docker-compose` на старых hosts. |
| `REALITY_PORT_POOL` | TCP port pool для auto-selection в `install.sh`. | Опц. | `8444 2053 2083` | Quoted space-separated list. |
| `AWG_PORT_POOL` | UDP port pool для auto-selection в `install.sh`. | Опц. | `51888 51889 51890 51891` | Quoted space-separated list. |
| `SERVICE_NAME` | `awg-gw` stub/debug service name. | Опц. | `awg-gw` | Только для stub/manual runs. |
| `AWG_LISTEN_UDP` | `awg-gw` stub/debug UDP listen value. | Опц. | `51821` | Только для stub/manual runs. |
| `AWG_ENDPOINT` | Endpoint для профиля `awg-smoke`. | Опц. | `host.docker.internal:51888` | Задайте worker public endpoint для remote smoke tests. |
| `TW_SMOKE_URL` | HTTP URL, который `awg-smoke` проверяет через AWG. | Опц. | `http://10.13.13.1/tw/healthz` | Любой URL, достижимый через туннель. |
| `AWG_CLIENT_PRIVATE_KEY` | Override smoke client private key. | Опц. | generated state value | Secret; только для smoke debugging. |
| `AWG_CLIENT_PSK` | Override smoke client PSK. | Опц. | generated state value | Secret; только для smoke debugging. |
| `AWG_CLIENT_IP` | Override smoke client internal IP. | Опц. | generated state value | Например `10.13.13.250`. |

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
- Держите `APPLY_NFT=0` на тестах. Перед production включением проверьте
  firewall/NAT rules.
- Worker enrollment tokens одноразовые; создавайте их в orchestrator и не
  храните в Git.

## 💚 Поддержать проект

Проект бесплатный и развивается на энтузиазме. Если он вам помогает — спасибо за
любую поддержку!

- **Bitcoin (BTC):** `bc1qdlqer9rtej6tpzdjzljdwltj7vxr4h6tv9eucp`
- **Ethereum (ETH):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **USDT (ERC-20):** `0xbe945043EaB956149ca24793c01d4927E90F878d`
- **TRON (TRX):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`
- **USDT (TRC-20):** `TGo4JyQnwH9Zb4ZZ37T3oaWuboy9qE7siq`

С благодарностью за вашу поддержку! 🙏

## Лицензия

MIT. См. `LICENSE`.
