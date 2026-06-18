# TrafficWrapper core

Go transport core used by TrafficWrapper worker-side binaries.

Build and test from this `core/` directory:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm go test ./...
docker run --rm -v "$PWD":/src -w /src golang:1.23-bookworm go build ./...
```

`awg_src` is copied into `core/awg/device` without edits. Missing files from the
same `device` package are taken from `github.com/amnezia-vpn/amneziawg-go` tag
`v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Imported packages `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n`, and `rwcancel`
come from the dependency `github.com/amnezia-vpn/amneziawg-go` pseudo-version
`v0.2.13-0.20250210181458-c97b5b76158f`, commit
`c97b5b76158fd85b1d461c9937ba5ff9186912d9`. This is the latest untagged commit
before that fork moved to Go 1.24; it requires `go 1.23.6` and builds in the
`golang:1.23-bookworm` image (`go1.23.12`).
