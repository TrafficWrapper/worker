package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// localAPIPolicy decides who may read /metrics and /self-describe. The agent
// port is also reachable from the other containers on the Compose network
// (the nginx telemetry relay needs it), and those endpoints carry client
// addresses, keys and short IDs. Requests published through the host port
// arrive from the network gateway; loopback covers the healthcheck and exec.
type localAPIPolicy struct {
	allowed []netip.Prefix
}

func newLocalAPIPolicy(extraCIDRs string, routeTable io.Reader) (localAPIPolicy, error) {
	p := localAPIPolicy{allowed: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}}
	if gw, ok := defaultGateway(routeTable); ok {
		p.allowed = append(p.allowed, netip.PrefixFrom(gw, gw.BitLen()))
	} else {
		slog.Warn("agent API: no default gateway found; /metrics and /self-describe answer loopback and AGENT_API_ALLOW_CIDRS only")
	}
	for _, raw := range strings.FieldsFunc(extraCIDRs, func(r rune) bool { return r == ',' || r == ' ' }) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, addrErr := netip.ParseAddr(raw)
			if addrErr != nil {
				return localAPIPolicy{}, fmt.Errorf("AGENT_API_ALLOW_CIDRS: %q is not a CIDR or IP", raw)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		p.allowed = append(p.allowed, prefix.Masked())
	}
	return p, nil
}

func loadLocalAPIPolicy(extraCIDRs string) (localAPIPolicy, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return newLocalAPIPolicy(extraCIDRs, strings.NewReader(""))
	}
	defer f.Close()
	return newLocalAPIPolicy(extraCIDRs, f)
}

func (p localAPIPolicy) allows(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range p.allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p localAPIPolicy) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.allows(r.RemoteAddr) {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// defaultGateway reads the IPv4 default route from /proc/net/route, where
// addresses are little-endian hex.
func defaultGateway(routeTable io.Reader) (netip.Addr, bool) {
	scanner := bufio.NewScanner(routeTable)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], binary.LittleEndian.Uint32(raw))
		gw := netip.AddrFrom4(ip)
		if gw.IsUnspecified() {
			continue
		}
		return gw, true
	}
	return netip.Addr{}, false
}
