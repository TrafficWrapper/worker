# Происхождение package device

[English](UPSTREAM.md)

Файлы `device_*.go` в этой директории являются byte-for-byte копиями repository
root `awg_src/*.go`.

Остальные non-test files скопированы из `github.com/amnezia-vpn/amneziawg-go`
tag `v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`, исключая
upstream originals, заменённые локальными `device_*.go`:

- `constants.go`
- `device.go`
- `magic-header.go`
- `noise-protocol.go`
- `obf.go`
- `receive.go`
- `send.go`
- `uapi.go`
