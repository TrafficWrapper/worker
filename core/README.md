# TrafficWrapper core

[Русский](README.ru.md)

Go transport core used by TrafficWrapper worker-side binaries.

Build and test from this `core/` directory:

```sh
docker run --rm -v "$PWD":/src -w /src golang:1.27-bookworm go test ./...
docker run --rm -v "$PWD":/src -w /src golang:1.27-bookworm go build ./...
```

`awg_src` is copied into `core/awg/device` without edits. Missing files from the
same `device` package are taken from `github.com/amnezia-vpn/amneziawg-go` tag
`v0.2.18`, commit `f4f4c999267437c3eb909e8d0e5278fb4596d9a7`.

Imported packages `conn`, `tun`, `ipc`, `ratelimiter`, `tai64n`, and `rwcancel`
come from the dependency `github.com/amnezia-vpn/amneziawg-go` pseudo-version
`v0.2.13-0.20250623202557-6a7c878409f3`, commit
`6a7c878409f32dc39a82bc597766c81304ab9840`. This revision removes the obsolete
`PacketBuffer.IsNil()` call and builds natively with gVisor
`v0.0.0-20250503011706-39ed1f5ac29c` using Go 1.27.

## Client API notes

- `ApplyDiscoveredEndpoints` verifies bundles only against a pinned rendezvous
  key. `PublicDeviceEnroll` pins the orchestrator-provided signer key; otherwise
  call `SetRendezvousPublicKey(key)` once per process or pass
  `signer_public_key` to `ApplyPublicPlatformConfig`. A `public_key` in the
  request that differs from the pin is rejected, `now` more than 10 minutes in
  the past is rejected, and the highest accepted `seq` is remembered.
- `socks_listen` must be a loopback address. Optional `socks_username` and
  `socks_password` enable RFC 1929 authentication; `socks_max_conns` limits
  concurrent SOCKS connections (default 1024).
