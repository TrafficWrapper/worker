module github.com/TrafficWrapper/worker/awg-smoke

go 1.23.6

toolchain go1.23.12

require (
	github.com/amnezia-vpn/amneziawg-go v0.2.13-0.20250210181458-c97b5b76158f
	github.com/TrafficWrapper/worker/core v0.0.0
)

require (
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/TrafficWrapper/worker/core => ../core
