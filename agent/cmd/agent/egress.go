package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// workerAddresses are the worker's own literal IPs: the egress address and
// the advertised public addresses. Clients must not reach services on the
// host through them, so Xray routing and the awg-gw forward filter block them
// like private destinations. Hostnames are skipped.
func workerAddresses(cfg envConfig) []string {
	var out []string
	seen := map[netip.Addr]bool{}
	for _, value := range []string{cfg.EgressIP, cfg.PublicAddress, cfg.PublicAddressV6} {
		addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(value), "[]"))
		if err != nil || addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr.String())
	}
	return out
}

func outboundIP() string {
	c, err := net.DialTimeout("udp", "1.1.1.1:53", time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

var egressEchoURLs = []string{"https://api.ipify.org", "https://ifconfig.co/ip", "https://ipinfo.io/ip"}

// detectPublicEgressIP asks several echo services in parallel and only trusts
// an address reported by at least two of them, like install.sh does. A lone
// answer is used only when every other service failed.
func detectPublicEgressIP() string {
	answers := make(chan string, len(egressEchoURLs))
	for _, url := range egressEchoURLs {
		url := url
		go func() {
			answers <- fetchEchoIP(url)
		}()
	}
	counts := map[string]int{}
	responded := 0
	lone := ""
	for range egressEchoURLs {
		ip := <-answers
		if ip == "" {
			continue
		}
		responded++
		lone = ip
		counts[ip]++
		if counts[ip] >= 2 {
			return ip
		}
	}
	if responded == 1 {
		slog.Warn("egress IP confirmed by a single echo service only", "egress_ip", lone)
		return lone
	}
	if responded > 1 {
		slog.Warn("egress IP echo services disagree", "counts", counts)
	}
	return ""
}

func fetchEchoIP(url string) string {
	client := http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return ""
	}
	ip := strings.TrimSpace(string(raw))
	if !isPublicIP(ip) {
		return ""
	}
	return ip
}

func isPublicIP(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast()
}
