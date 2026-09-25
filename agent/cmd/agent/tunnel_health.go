package main

import (
	"encoding/binary"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The distributor and the resolver run in the awg-gw network namespace. If
// awg-gw restarts and they stay in the old namespace, AWG clients lose DNS
// and config downloads while everything else looks fine. The agent checks
// them through the awg-gw address and reports failures in self_check.

const tunnelProbeTimeout = 2 * time.Second

var (
	distributorUnreachable atomic.Bool
	resolverUnreachable    atomic.Bool
)

// tunnelServicesHost is the in-tunnel services host (awg-gw in Compose),
// taken from an internal DISTRIBUTOR_URL; public URLs are not probed.
func tunnelServicesHost(cfg envConfig) string {
	u, err := url.Parse(cfg.DistributorURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, ".") || strings.Contains(host, ":") {
		return ""
	}
	return host
}

func probeTunnelServices(cfg envConfig) {
	host := tunnelServicesHost(cfg)
	if host == "" {
		distributorUnreachable.Store(false)
		resolverUnreachable.Store(false)
		return
	}
	distributorUnreachable.Store(!tcpReachable(net.JoinHostPort(host, strconv.Itoa(distributorTW))))
	resolverUnreachable.Store(cfg.DNSEnabled && !dnsAnswers(net.JoinHostPort(host, "53")))
}

func tcpReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, tunnelProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dnsAnswers sends an ANY query for the root. The resolver refuses ANY
// queries itself, so any answer shows it is up without depending on its
// upstreams.
func dnsAnswers(addr string) bool {
	conn, err := net.DialTimeout("udp", addr, tunnelProbeTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tunnelProbeTimeout))
	id := uint16(time.Now().UnixNano())
	query := make([]byte, 12, 17)
	binary.BigEndian.PutUint16(query[0:], id)
	binary.BigEndian.PutUint16(query[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(query[4:], 1)      // one question
	query = append(query, 0, 0, 255, 0, 1)        // root, type ANY, class IN
	if _, err := conn.Write(query); err != nil {
		return false
	}
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	return err == nil && n >= 12 && binary.BigEndian.Uint16(reply) == id && reply[2]&0x80 != 0
}
