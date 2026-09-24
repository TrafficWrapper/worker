module github.com/TrafficWrapper/worker/agent

go 1.26.0

require (
	aead.dev/minisign v0.3.0
	github.com/TrafficWrapper/worker/core v0.0.0
	github.com/flynn/noise v1.1.0
	golang.org/x/crypto v0.57.0
)

require golang.org/x/sys v0.48.0 // indirect

replace github.com/TrafficWrapper/worker/core => ../core
