package transport

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	awgdialect "github.com/TrafficWrapper/worker/core/awg/dialect"
)

const (
	defaultMTU              = 1420
	defaultSOCKSListen      = "127.0.0.1:18080"
	defaultAWGRUSOCKSListen = "127.0.0.1:18084"
	keySize                 = 32
)

type preset = awgdialect.Dialect

type config struct {
	PrivateKey      string   `json:"private_key"`
	InternalIP      string   `json:"internal_ip"`
	Endpoint        string   `json:"endpoint"`
	ServerPublicKey string   `json:"server_public_key"`
	PSK2            string   `json:"psk2"`
	AWGPreset       preset   `json:"awg_preset"`
	SOCKSListen     string   `json:"socks_listen,omitempty"`
	MTU             int      `json:"mtu,omitempty"`
	DNSServers      []string `json:"dns_servers,omitempty"`
}

type normalizedConfig struct {
	config
	localAddr  netip.Addr
	dnsServers []netip.Addr
}

func parseConfig(configJSON string) (normalizedConfig, error) {
	var cfg config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return normalizedConfig{}, fmt.Errorf("parse config json: %w", err)
	}
	if cfg.MTU == 0 {
		cfg.MTU = defaultMTU
	}
	if cfg.SOCKSListen == "" {
		cfg.SOCKSListen = defaultSOCKSListen
	}
	if cfg.PrivateKey == "" || cfg.InternalIP == "" || cfg.Endpoint == "" || cfg.ServerPublicKey == "" || cfg.PSK2 == "" {
		return normalizedConfig{}, errors.New("config is incomplete")
	}
	endpoint, err := normalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return normalizedConfig{}, err
	}
	cfg.Endpoint = endpoint
	if _, err := base64KeyToHex(cfg.PrivateKey); err != nil {
		return normalizedConfig{}, fmt.Errorf("private_key: %w", err)
	}
	if _, err := base64KeyToHex(cfg.ServerPublicKey); err != nil {
		return normalizedConfig{}, fmt.Errorf("server_public_key: %w", err)
	}
	if _, err := base64KeyToHex(cfg.PSK2); err != nil {
		return normalizedConfig{}, fmt.Errorf("psk2: %w", err)
	}
	if err := validatePreset(cfg.AWGPreset, cfg.MTU); err != nil {
		return normalizedConfig{}, err
	}
	effectiveMTU, err := awgdialect.EffectiveMTU(cfg.MTU, cfg.AWGPreset)
	if err != nil {
		return normalizedConfig{}, err
	}
	cfg.MTU = effectiveMTU
	prefix, err := netip.ParsePrefix(cfg.InternalIP)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("internal_ip: %w", err)
	}
	if !prefix.Addr().Is4() {
		return normalizedConfig{}, fmt.Errorf("internal_ip must be IPv4, got %s", cfg.InternalIP)
	}
	dns := make([]netip.Addr, 0, len(cfg.DNSServers))
	for _, value := range cfg.DNSServers {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("dns server %q: %w", value, err)
		}
		dns = append(dns, addr)
	}
	return normalizedConfig{config: cfg, localAddr: prefix.Addr(), dnsServers: dns}, nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if _, err := netip.ParseAddrPort(endpoint); err == nil {
		return endpoint, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return net.JoinHostPort(ip4.String(), port), nil
		}
	}
	for _, ip := range ips {
		if ip16 := ip.To16(); ip16 != nil {
			return net.JoinHostPort(ip16.String(), port), nil
		}
	}
	return "", fmt.Errorf("resolve endpoint host %q: no IP addresses", host)
}

func validatePreset(p preset, mtu int) error {
	return awgdialect.Validate(p, mtu)
}

func base64KeyToHex(value string) (string, error) {
	raw, err := decodeKeyBase64(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func decodeKeyBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", keySize, len(raw))
	}
	return raw, nil
}
