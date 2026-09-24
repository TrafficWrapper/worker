# TrafficWrapper core

[English](README.md)

Go transport core, используемый worker-side binaries TrafficWrapper.

Собрать и протестировать из этой директории `core/`:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.27-bookworm go test ./...
docker run --rm -v "$PWD":/src -w /src golang:1.27-bookworm go build ./...
```

`awg_src` копируется в `core/awg/device` без правок. Недостающие файлы из того
же package `device` взяты из `github.com/amnezia-vpn/amneziawg-go` tag
`v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Imported packages `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n` и `rwcancel`
идут из dependency `github.com/amnezia-vpn/amneziawg-go` pseudo-version
`v0.2.13-0.20250623202557-6a7c878409f3`, commit
`6a7c878409f32dc39a82bc597766c81304ab9840`. Эта revision удаляет obsolete
`PacketBuffer.IsNil()` call и нативно собирается с gVisor
`v0.0.0-20250503011706-39ed1f5ac29c` на Go 1.27.

## Замечания по клиентскому API

- `ApplyDiscoveredEndpoints` проверяет бандлы только по закреплённому
  rendezvous-ключу. `PublicDeviceEnroll` закрепляет ключ подписанта из ответа
  оркестратора; иначе вызовите `SetRendezvousPublicKey(key)` один раз за процесс
  или передайте `signer_public_key` в `ApplyPublicPlatformConfig`. Отличающийся
  `public_key` в запросе отвергается, `now` старше 10 минут отвергается,
  максимальный принятый `seq` запоминается.
- `socks_listen` должен быть loopback-адресом. Необязательные `socks_username`
  и `socks_password` включают аутентификацию RFC 1929; `socks_max_conns`
  ограничивает число одновременных SOCKS-соединений (по умолчанию 1024).
