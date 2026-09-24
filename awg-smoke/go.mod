module github.com/TrafficWrapper/worker/awg-smoke

go 1.24.4

require (
	github.com/TrafficWrapper/worker/core v0.0.0
	github.com/amnezia-vpn/amneziawg-go v1.0.4
)

require (
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/TrafficWrapper/worker/core => ../core
