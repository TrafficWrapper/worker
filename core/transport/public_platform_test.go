package transport

import (
	"encoding/json"
	"testing"
)

func TestPublicAWGConfigJSONPinsHostnameEndpointWithExpectedEgressIP(t *testing.T) {
	route := &publicRouteSpec{
		Endpoint:  "worker.example:51888",
		EgressIP:  "198.51.100.44",
		PublicKey: testKey(2),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	raw, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "198.51.100.44:51888" {
		t.Fatalf("endpoint=%q want pinned IP endpoint", cfg.Endpoint)
	}
}

func TestPublicAWGConfigJSONRejectsHostnameEndpointWithoutPinnedIP(t *testing.T) {
	route := &publicRouteSpec{
		Endpoint:  "worker.example:51888",
		PublicKey: testKey(2),
	}
	req := publicApplyAPIRequest{
		AWGPrivateKey:   testKey(1),
		InternalIP:      "10.13.13.42/32",
		PSK2:            testKey(3),
		ServerAWGPublic: testKey(2),
		MTU:             1420,
	}
	if _, err := publicAWGConfigJSON(route, req, "127.0.0.1:18080"); err == nil {
		t.Fatal("hostname endpoint without expected_egress_ip was accepted")
	}
}
