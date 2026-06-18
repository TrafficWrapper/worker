package transport

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/TrafficWrapper/worker/core/awg/device"
	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

var singleton struct {
	sync.Mutex
	instances map[string]*instance
}

type instance struct {
	cfg      normalizedConfig
	net      *netstacktun.Net
	dev      *device.Device
	socks    *socksServer
	started  time.Time
	stopOnce sync.Once
}

type apiResult struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Status  *status `json:"status,omitempty"`
	Stopped bool    `json:"stopped,omitempty"`
}

type status struct {
	Started              bool   `json:"started"`
	ActiveTransport      string `json:"active_transport,omitempty"`
	SOCKSListen          string `json:"socks_listen,omitempty"`
	InternalIP           string `json:"internal_ip,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	MTU                  int    `json:"mtu,omitempty"`
	TCPMSS               int    `json:"tcp_mss,omitempty"`
	StartedAtUnix        int64  `json:"started_at_unix,omitempty"`
	LastHandshakeTimeSec int64  `json:"last_handshake_time_sec,omitempty"`
	HandshakeAgeSeconds  int64  `json:"handshake_age_seconds,omitempty"`
	HandshakeEstablished bool   `json:"handshake_established"`
	RXBytes              uint64 `json:"rx_bytes,omitempty"`
	TXBytes              uint64 `json:"tx_bytes,omitempty"`
	PeerAllowedIP        string `json:"peer_allowed_ip,omitempty"`
	UAPIReadError        string `json:"uapi_read_error,omitempty"`
}

func Start(configJSON string) string {
	status, err := startNamed(defaultInstanceName, configJSON)
	if err != nil {
		return encodeResult(apiResult{OK: false, Error: err.Error()})
	}
	return encodeResult(apiResult{OK: true, Status: status})
}

func StartNamed(name, configJSON string) string {
	status, err := startNamed(normalizeInstanceName(name), configJSON)
	if err != nil {
		return encodeResult(apiResult{OK: false, Error: err.Error()})
	}
	return encodeResult(apiResult{OK: true, Status: status})
}

func Stop() string {
	return StopNamed(defaultInstanceName)
}

func StopAWGRU() string {
	return StopNamed(awgRUInstanceName)
}

func StopNamed(name string) string {
	name = normalizeInstanceName(name)
	singleton.Lock()
	inst := singleton.instances[name]
	delete(singleton.instances, name)
	singleton.Unlock()

	if inst != nil {
		inst.close()
	}
	return encodeResult(apiResult{OK: true, Stopped: inst != nil})
}

func Stat() string {
	return StatNamed(defaultInstanceName)
}

func StatAWGRU() string {
	return StatNamed(awgRUInstanceName)
}

func StatNamed(name string) string {
	name = normalizeInstanceName(name)
	singleton.Lock()
	inst := singleton.instances[name]
	singleton.Unlock()
	if inst == nil {
		return encodeResult(apiResult{OK: true, Status: &status{Started: false}})
	}
	return encodeResult(apiResult{OK: true, Status: inst.status()})
}

func startNamed(name, configJSON string) (*status, error) {
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}

	singleton.Lock()
	defer singleton.Unlock()
	if singleton.instances == nil {
		singleton.instances = make(map[string]*instance)
	}
	if singleton.instances[name] != nil {
		return nil, fmt.Errorf("transport %s already started", name)
	}

	tunDev, tnet, err := netstacktun.CreateNetTUN([]netip.Addr{cfg.localAddr}, cfg.dnsServers, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}
	if err := tuneNetstack(tnet); err != nil {
		_ = tunDev.Close()
		return nil, err
	}

	logger := device.NewLogger(device.LogLevelError, "transport: ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	inst := &instance{
		cfg:     cfg,
		net:     tnet,
		dev:     dev,
		started: time.Now(),
	}
	if err := configureDevice(dev, cfg); err != nil {
		inst.close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		inst.close()
		return nil, fmt.Errorf("device up: %w", err)
	}
	socks, err := startSOCKSServer(cfg.SOCKSListen, tnet)
	if err != nil {
		inst.close()
		return nil, err
	}
	inst.socks = socks
	singleton.instances[name] = inst
	return inst.status(), nil
}

func configureDevice(dev *device.Device, cfg normalizedConfig) error {
	privateHex, err := base64KeyToHex(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	serverHex, err := base64KeyToHex(cfg.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("server public key: %w", err)
	}
	pskHex, err := base64KeyToHex(cfg.PSK2)
	if err != nil {
		return fmt.Errorf("psk2: %w", err)
	}
	lines := []string{
		"private_key=" + privateHex,
		"replace_peers=true",
	}
	lines = append(lines, awgdialect.UAPILines(cfg.AWGPreset)...)
	lines = append(lines,
		"public_key="+serverHex,
		"preshared_key="+pskHex,
		"endpoint="+cfg.Endpoint,
		"persistent_keepalive_interval=15",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"",
	)
	uapi := strings.Join(lines, "\n")
	if err := dev.IpcSetOperation(strings.NewReader(uapi)); err != nil {
		return fmt.Errorf("apply UAPI: %w", err)
	}
	return nil
}

func (inst *instance) close() {
	inst.stopOnce.Do(func() {
		if inst.socks != nil {
			inst.socks.close()
		}
		if inst.dev != nil {
			inst.dev.Close()
		}
	})
}

func (inst *instance) status() *status {
	status := &status{
		Started:         true,
		ActiveTransport: "awg-netstack",
		InternalIP:      inst.cfg.InternalIP,
		Endpoint:        inst.cfg.Endpoint,
		MTU:             inst.cfg.MTU,
		TCPMSS:          awgdialect.TCPMSSForMTU(inst.cfg.MTU),
		StartedAtUnix:   inst.started.Unix(),
	}
	if inst.socks != nil {
		status.SOCKSListen = inst.socks.addr()
	}
	var raw strings.Builder
	if err := inst.dev.IpcGetOperation(&raw); err != nil {
		status.UAPIReadError = err.Error()
		return status
	}
	parseUAPIStats(raw.String(), status)
	if status.LastHandshakeTimeSec > 0 {
		age := time.Since(time.Unix(status.LastHandshakeTimeSec, 0))
		if age < 0 {
			age = 0
		}
		status.HandshakeAgeSeconds = int64(age.Seconds())
		status.HandshakeEstablished = age < 180*time.Second
	}
	return status
}

func parseUAPIStats(raw string, status *status) {
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			status.LastHandshakeTimeSec, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			status.RXBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			status.TXBytes, _ = strconv.ParseUint(value, 10, 64)
		case "allowed_ip":
			status.PeerAllowedIP = value
		}
	}
}

func encodeResult(result apiResult) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"ok":false,"error":"marshal status"}`
	}
	return string(raw)
}

func normalizeInstanceName(name string) string {
	switch strings.TrimSpace(name) {
	case "", defaultInstanceName:
		return defaultInstanceName
	case awgRUInstanceName, "awgru", "awg-ru":
		return awgRUInstanceName
	default:
		return strings.TrimSpace(name)
	}
}

const (
	defaultInstanceName = "default"
	awgRUInstanceName   = "awg_ru"
)
