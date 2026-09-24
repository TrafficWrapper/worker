module github.com/TrafficWrapper/worker/awg-gw

go 1.26.0

require (
	github.com/TrafficWrapper/worker/core v0.0.0
	github.com/amnezia-vpn/amneziawg-go v0.2.13-0.20250623202557-6a7c878409f3
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/TrafficWrapper/worker/core => ../core
