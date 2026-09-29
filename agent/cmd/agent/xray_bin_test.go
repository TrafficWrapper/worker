package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests run the real Xray binary named by XRAY_BIN and are skipped
// without it, e.g. XRAY_BIN=/usr/local/bin/xray go test -run XrayBinary ./...

func xrayBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN not set")
	}
	return bin
}

func xrayBinaryTestConfig(t *testing.T) (envConfig, stateFile) {
	t.Helper()
	priv, pub, err := x25519RawURLEncoded()
	if err != nil {
		t.Fatal(err)
	}
	cfg := envConfig{
		StateDir:           t.TempDir(),
		XrayPort:           freeTCPPort(t),
		XrayAPISocket:      filepath.Join(t.TempDir(), "api.sock"),
		RealityDest:        "www.example.net:443",
		CamouflageDomain:   "www.example.net",
		EgressIP:           "203.0.113.10",
		PublicAddress:      "worker.example.net",
		PublicAddressV6:    "2001:db8::10",
		BlockSMTP:          true,
		BlockBitTorrent:    true,
		RealityMaxTimeDiff: 2 * time.Minute,
	}
	st := hardeningTestState()
	st.Reality = realityState{PrivateKey: priv, PublicKey: pub, ShortID: "abcd"}
	return cfg, st
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestXrayBinaryAcceptsRenderedConfig(t *testing.T) {
	bin := xrayBinary(t)
	cfg, st := xrayBinaryTestConfig(t)
	raw, err := xrayConfigBytes(cfg, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("xray rejected the rendered config: %v\n%s\n%s", err, out, raw)
	}
}

// The rendered unexpectedIPs must make Xray drop an answer that points at the
// worker's own public address. Xray resolves through a local fake server and
// answers queries through a dns outbound, so the filter is observed directly.
func TestXrayBinaryDNSDropsWorkerOwnAddress(t *testing.T) {
	bin := xrayBinary(t)
	cfg, st := xrayBinaryTestConfig(t)
	answers := map[string]string{"own.test.": cfg.EgressIP, "private.test.": "10.1.2.3", "other.test.": "198.51.100.7"}
	upstream := startFakeDNS(t, answers)

	doc := xrayConfigDocument(cfg, st, nil)
	dns, ok := doc["dns"].(map[string]any)
	if !ok {
		t.Fatal("rendered config has no dns section")
	}
	// Test plumbing only: point the resolver at the fake server, let its
	// queries out, and expose it through a dns outbound. The unexpectedIPs
	// list is the rendered one.
	server := dns["servers"].([]any)[0].(map[string]any)
	server["address"] = "127.0.0.1"
	server["port"] = upstream.Port
	dns["tag"] = "dns-test"
	queryPort := freeUDPPort(t)
	doc["inbounds"] = append(doc["inbounds"].([]any), map[string]any{
		"tag": "dns-in", "listen": "127.0.0.1", "port": queryPort, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": "192.0.2.53", "port": 53, "network": "udp"},
	})
	doc["outbounds"] = append(doc["outbounds"].([]any), map[string]any{"tag": "dns-out", "protocol": "dns"})
	routing := doc["routing"].(map[string]any)
	routing["rules"] = append([]any{
		map[string]any{"type": "field", "inboundTag": []string{"dns-test"}, "outboundTag": "direct"},
		map[string]any{"type": "field", "inboundTag": []string{"dns-in"}, "outboundTag": "dns-out"},
	}, routing["rules"].([]any)...)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	query := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: queryPort}

	// The control name proves the path works before the filtered one is
	// checked; Xray may need a moment to start listening.
	deadline := time.Now().Add(10 * time.Second)
	var got []netip.Addr
	for {
		got, err = queryA(query, "other.test.", time.Second)
		if err == nil && len(got) > 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(got) != 1 || got[0].String() != "198.51.100.7" {
		t.Fatalf("control answer = %v, %v\n%s", got, err, logs.String())
	}
	for _, name := range []string{"private.test.", "own.test."} {
		blocked := answers[name]
		got, _ = queryA(query, name, 3*time.Second)
		for _, addr := range got {
			if addr.String() == blocked {
				t.Fatalf("Xray resolved %s to the filtered address %s", name, addr)
			}
		}
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startFakeDNS answers A queries for the names in answers with one record.
func startFakeDNS(t *testing.T, answers map[string]string) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := fakeDNSResponse(buf[:n], answers); resp != nil {
				_, _ = conn.WriteToUDP(resp, from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func fakeDNSResponse(req []byte, answers map[string]string) []byte {
	if len(req) < 12 || binary.BigEndian.Uint16(req[4:6]) != 1 {
		return nil
	}
	name, end, ok := dnsName(req, 12)
	if !ok || end+4 > len(req) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(req[end : end+2])
	question := req[12 : end+4]
	resp := make([]byte, 12, 64)
	copy(resp, req[:2])
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	resp = append(resp, question...)
	ip, found := answers[strings.ToLower(name)]
	if !found || qtype != 1 {
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], 1)
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(resp, net.ParseIP(ip).To4()...)
}

// dnsName reads an uncompressed name starting at off.
func dnsName(msg []byte, off int) (string, int, bool) {
	var labels []string
	for off < len(msg) {
		l := int(msg[off])
		off++
		if l == 0 {
			return strings.Join(labels, ".") + ".", off, true
		}
		if l&0xc0 != 0 || off+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return "", 0, false
}

// queryA sends one A query and returns the A records of the answer.
func queryA(server *net.UDPAddr, name string, timeout time.Duration) ([]netip.Addr, error) {
	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	req := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		req = append(req, byte(len(label)))
		req = append(req, label...)
	}
	req = append(req, 0, 0, 1, 0, 1)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseAAnswers(buf[:n])
}

func parseAAnswers(msg []byte) ([]netip.Addr, error) {
	if len(msg) < 12 {
		return nil, errors.New("short dns response")
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:6])), int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for range qd {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4
	}
	var out []netip.Addr
	for range an {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, errors.New("short dns answer")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("short dns rdata")
		}
		if rtype == 1 && rdlen == 4 {
			out = append(out, netip.AddrFrom4([4]byte(msg[off:off+4])))
		}
		off += rdlen
	}
	return out, nil
}

func skipDNSName(msg []byte, off int) (int, error) {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		}
		off += 1 + l
	}
	return 0, errors.New("bad dns name")
}
