# TrafficWrapper core

Go-модуль транспортного ядра.

Сборка выполняется только в Docker:

```sh
docker run --rm -v /root/TrafficWrapper:/src -w /src/core golang:1.23-bookworm go build ./...
```

`awg_src` скопирован в `core/awg/device` без правок. Недостающие файлы того же пакета `device` взяты из `github.com/amnezia-vpn/amneziawg-go` tag `v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Импортируемые пакеты `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n`, `rwcancel` подтянуты как зависимость `github.com/amnezia-vpn/amneziawg-go` pseudo-version `v0.2.13-0.20250210181458-c97b5b76158f`, commit `c97b5b76158fd85b1d461c9937ba5ff9186912d9`. Это свежий нетегированный commit до перехода форка на Go 1.24; он требует `go 1.23.6` и собирается в Docker-образе `golang:1.23-bookworm` (`go1.23.12`).
