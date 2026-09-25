package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testRouteTable = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010012AC	0003	0	0	0	00000000	0	0	0
eth0	000012AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`

func TestDefaultGatewayFromRouteTable(t *testing.T) {
	gw, ok := defaultGateway(strings.NewReader(testRouteTable))
	if !ok || gw.String() != "172.18.0.1" {
		t.Fatalf("gateway = %v, %v", gw, ok)
	}
	if _, ok := defaultGateway(strings.NewReader("Iface\tDestination\tGateway\n")); ok {
		t.Fatal("gateway found in a table without a default route")
	}
}

func TestLocalAPIRefusesOtherContainers(t *testing.T) {
	policy, err := newLocalAPIPolicy("10.8.0.0/24, 192.0.2.7", strings.NewReader(testRouteTable))
	if err != nil {
		t.Fatal(err)
	}
	handler := policy.wrap(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) })
	for remote, want := range map[string]int{
		"127.0.0.1:5000":        http.StatusOK,
		"[::1]:5000":            http.StatusOK,
		"172.18.0.1:5000":       http.StatusOK, // host port published by Docker
		"[::ffff:172.18.0.1]:1": http.StatusOK,
		"10.8.0.9:5000":         http.StatusOK,
		"192.0.2.7:5000":        http.StatusOK,
		"172.18.0.5:5000":       http.StatusNotFound, // xray or awg-gw container
		"169.254.169.254:80":    http.StatusNotFound,
		"garbage":               http.StatusNotFound,
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d", remote, rec.Code, want)
		}
		if want != http.StatusOK && strings.Contains(rec.Body.String(), "secret") {
			t.Fatalf("%s: body leaked", remote)
		}
	}
	if _, err := newLocalAPIPolicy("not-a-cidr", strings.NewReader("")); err == nil {
		t.Fatal("invalid AGENT_API_ALLOW_CIDRS accepted")
	}
}

func TestXrayResolvesOnceAndDropsPrivateAnswers(t *testing.T) {
	doc := xrayConfigDocument(envConfig{}, hardeningTestState(), nil)
	direct := doc["outbounds"].([]any)[0].(map[string]any)
	settings, _ := direct["settings"].(map[string]any)
	if direct["protocol"] != "freedom" || settings["domainStrategy"] != "ForceIPv4" {
		t.Fatalf("freedom must dial the address Xray resolved: %#v", direct)
	}
	raw, _ := json.Marshal(doc["dns"])
	for _, want := range []string{`"unexpectedIPs"`, `"169.254.0.0/16"`, `"172.16.0.0/12"`, `"127.0.0.0/8"`, `"fc00::/7"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("dns missing %s: %s", want, raw)
		}
	}

	open := xrayConfigDocument(envConfig{AllowPrivateEgress: true}, hardeningTestState(), nil)
	if _, ok := open["dns"]; ok {
		t.Fatal("private egress opt-out still filters DNS")
	}
	if _, ok := open["outbounds"].([]any)[0].(map[string]any)["settings"]; ok {
		t.Fatal("private egress opt-out still forces IP resolution")
	}
}
