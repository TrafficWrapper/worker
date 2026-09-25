package main

import (
	"net"
	"strings"
	"testing"
)

func TestTunnelServicesHost(t *testing.T) {
	for raw, want := range map[string]string{
		"http://awg-gw:8080/tw":      "awg-gw",
		"https://cdn.example.com/tw": "",
		"http://10.13.13.1:8080/tw":  "",
		"http://[fd00::1]:8080/tw":   "",
		"":                           "",
	} {
		if got := tunnelServicesHost(envConfig{DistributorURL: raw}); got != want {
			t.Fatalf("%q: got %q, want %q", raw, got, want)
		}
	}
}

func TestTunnelProbesDetectLiveAndDeadServices(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if !tcpReachable(ln.Addr().String()) {
		t.Fatal("listening distributor reported unreachable")
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if tcpReachable(addr) {
		t.Fatal("closed port reported reachable")
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		buf[2] |= 0x80 // response
		buf[3] = 5     // REFUSED
		_, _ = pc.WriteTo(buf[:n], from)
	}()
	if !dnsAnswers(pc.LocalAddr().String()) {
		t.Fatal("answering resolver reported down")
	}
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	if dnsAnswers(silent.LocalAddr().String()) {
		t.Fatal("silent resolver reported up")
	}
}

func TestSelfCheckReportsTunnelServices(t *testing.T) {
	t.Cleanup(func() {
		distributorUnreachable.Store(false)
		resolverUnreachable.Store(false)
	})
	distributorUnreachable.Store(true)
	resolverUnreachable.Store(true)
	if s := selfCheckStatus(); !strings.Contains(s, "distributor") || !strings.Contains(s, "dns") {
		t.Fatalf("self_check %q", s)
	}
}
