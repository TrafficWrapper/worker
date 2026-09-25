package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

var selfDescribeTopLevelKeys = map[string]struct{}{
	"schema": {}, "hostname": {}, "egress_ip": {}, "orch_url": {}, "agent_url": {},
	"distributor_url": {}, "standalone": {}, "dialect_id": {}, "capacity": {},
	"protocols": {}, "reality": {}, "reality_profiles": {}, "awg": {},
	"awg_profiles": {}, "health": {}, "orchestrator": {}, "distributed_apk": {},
	"capabilities": {},
}

// maxSelfDescribeConfig builds a configuration with the given number of
// REALITY and AWG profiles and long strings everywhere.
func maxSelfDescribeConfig(t *testing.T, profiles int) (envConfig, stateFile) {
	t.Helper()
	stateDir := t.TempDir()
	twDir := filepath.Join(stateDir, "distributor", "tw")
	if err := os.MkdirAll(twDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"ns":"apk-update-v1","seq":42,"version_code":131,"version_name":"0.1.31","apk_sha256":"` + strings.Repeat("A", 64) + `","apk_name":"` + strings.Repeat("n", 200) + `.apk"}`
	if err := os.WriteFile(filepath.Join(twDir, "update-manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 60)
	host := long + "." + long + "." + long + ".example"
	cfg := envConfig{
		StateDir:         stateDir,
		PublicAddress:    host,
		PublicAddressV6:  "2a01:4f8:c0c:1234::1",
		EgressIP:         "198.51.100.8",
		OrchURL:          "https://" + host + "/",
		WorkerAgentURL:   "https://" + host + "/",
		DistributorURL:   "https://" + host + "/tw",
		CamouflageDomain: host,
		RealityDest:      host + ":443",
		XrayPort:         2053,
		XrayNetwork:      "xhttp",
		XHTTPPath:        "/" + strings.Repeat("p", 200),
		XHTTPMode:        "auto",
		XHTTPHost:        host,
		DNSEnabled:       true,
	}
	for i := 0; i < profiles-1; i++ {
		cfg.RealityProfiles = append(cfg.RealityProfiles, realityProfile{
			Name: fmt.Sprintf("r%02d-%s", i, strings.Repeat("x", 40)), Network: "xhttp", ListenPort: 20000 + i, PublicPort: 30000 + i,
			XHTTPPath: "/" + strings.Repeat("q", 200), XHTTPMode: "auto", XHTTPHost: host,
		})
	}
	for i := 0; i < profiles; i++ {
		name := "awg"
		if i > 0 {
			name = fmt.Sprintf("a%02d-%s", i, strings.Repeat("y", 40))
		}
		cfg.AWGProfiles = append(cfg.AWGProfiles, awgInboundProfile{
			Name: name, Interface: fmt.Sprintf("awg%d", i+1), ListenPort: 40000 + i, PublicPort: 50000 + i,
			Subnet: fmt.Sprintf("10.%d.0.0/24", i+1), Gateway: fmt.Sprintf("10.%d.0.1", i+1), MinVersionCode: 131,
		})
	}
	if err := validateSelfDescribeEnv(cfg); err != nil {
		t.Fatalf("max config rejected: %v", err)
	}
	st := stateFile{
		Hostname:  "worker-" + strings.Repeat("h", 40),
		DialectID: strings.Repeat("d", 64),
		Reality:   realityState{PrivateKey: "priv", PublicKey: strings.Repeat("k", 43), ShortID: strings.Repeat("s", 16)},
		AWG:       awgState{PublicKey: strings.Repeat("K", 44)},
		Dialect:   dialect.Compat(),
	}
	ensureRealityCohorts(&st)
	return cfg, st
}

func TestSelfDescribeMeetsContract(t *testing.T) {
	cfg, st := maxSelfDescribeConfig(t, 16)
	longErr := probeError(fmt.Errorf("dial: %s", strings.Repeat("e", 1000)))
	currentHealth.Store(&healthState{
		Camouflage: &probeReport{Target: cfg.RealityDest, Error: longErr},
		Reality:    &probeReport{Target: defaultRealityAddr, Error: longErr},
	})
	t.Cleanup(func() { currentHealth.Store(nil) })

	if err := checkSelfDescribe(cfg, st); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(selfDescribe(cfg, st))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > selfDescribeMaxBytes {
		t.Fatalf("self_describe is %d bytes, contract limit %d", len(raw), selfDescribeMaxBytes)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for key := range doc {
		if _, ok := selfDescribeTopLevelKeys[key]; !ok {
			t.Fatalf("top-level key %q is not in the contract", key)
		}
	}
	if err := checkSelfDescribeContract(doc, "self_describe"); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["orchestrator"].(map[string]any)["max_seen_seq"]; ok {
		t.Fatal("constant max_seen_seq must not be published")
	}
	caps, _ := doc["capabilities"].([]any)
	if len(caps) == 0 || caps[0] != "reality_flow" {
		t.Fatalf("capabilities = %v", doc["capabilities"])
	}
	reality := doc["reality"].(map[string]any)
	if reality["address_v6"] != cfg.PublicAddressV6 || reality["fingerprint"] != "chrome" {
		t.Fatalf("legacy reality must carry address_v6 and keep fingerprint: %v", reality)
	}
	apk := doc["distributed_apk"].(map[string]any)
	if apk["seq"] != float64(42) || apk["apk_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("distributed_apk = %v", apk)
	}
}

func TestCheckSelfDescribeRejectsOversizedDocument(t *testing.T) {
	cfg, st := maxSelfDescribeConfig(t, selfDescribeMaxProfiles)
	if err := checkSelfDescribe(cfg, st); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized self_describe accepted: %v", err)
	}
}

func TestCheckSelfDescribeContractRejectsViolations(t *testing.T) {
	for name, doc := range map[string]any{
		"forbidden nested":  map[string]any{"awg": map[string]any{"Private_Key": "x"}},
		"forbidden in list": map[string]any{"awg_profiles": []any{map[string]any{"psk2": "x"}}},
		"long string":       map[string]any{"hostname": strings.Repeat("h", selfDescribeMaxString+1)},
		"too many profiles": map[string]any{"reality_profiles": make([]any, selfDescribeMaxProfiles+1)},
	} {
		if err := checkSelfDescribeContract(doc, "self_describe"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestValidateSelfDescribeEnvRejectsBadSettings(t *testing.T) {
	base := envConfig{PublicAddress: "worker.example.net", CamouflageDomain: "www.example.net"}
	if err := validateSelfDescribeEnv(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*envConfig){
		"address with path":  func(c *envConfig) { c.PublicAddress = "worker.example.net/x" },
		"address with space": func(c *envConfig) { c.PublicAddress = "worker example" },
		"address too long":   func(c *envConfig) { c.PublicAddress = strings.Repeat("a", 254) },
		"bad camouflage":     func(c *envConfig) { c.CamouflageDomain = "https://www.example.net" },
		"bad distributor":    func(c *envConfig) { c.DistributorURL = "ftp://awg-gw/tw" },
		"long xhttp path":    func(c *envConfig) { c.XHTTPPath = "/" + strings.Repeat("p", selfDescribeMaxString) },
		"too many reality":   func(c *envConfig) { c.RealityProfiles = make([]realityProfile, selfDescribeMaxProfiles) },
		"too many awg":       func(c *envConfig) { c.AWGProfiles = make([]awgInboundProfile, selfDescribeMaxProfiles+1) },
	} {
		cfg := base
		mutate(&cfg)
		if err := validateSelfDescribeEnv(cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for _, ok := range []string{"198.51.100.7", "2a01:4f8::1", "[2a01:4f8::1]", "worker-1.example.net"} {
		cfg := base
		cfg.PublicAddress = ok
		if err := validateSelfDescribeEnv(cfg); err != nil {
			t.Fatalf("%s rejected: %v", ok, err)
		}
	}
}

func TestPullRequestCarriesWorkerCapabilities(t *testing.T) {
	raw, _ := json.Marshal(orchPullRequest{WorkerID: "w", HaveSeq: 1, WorkerCapabilities: workerCapabilities})
	if !strings.Contains(string(raw), `"worker_capabilities":["reality_flow",`) {
		t.Fatalf("pull request: %s", raw)
	}
}
