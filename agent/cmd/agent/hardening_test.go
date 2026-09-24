package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func hardeningTestState() stateFile {
	return stateFile{
		SmokeRealityUUID: "14526b0e-6de3-4407-bf8f-d8c688160ce6",
		Reality:          realityState{PrivateKey: "priv", ShortID: "abcd", PublicKey: "pub"},
	}
}

func realityDevice(id, uuid string) approvedDevice {
	return approvedDevice{DeviceID: id, RealityUUID: uuid, Status: "approved"}
}

func TestDiffXrayUsersOnlyForClientListChanges(t *testing.T) {
	cfg := envConfig{RealityDest: "example.com:443", CamouflageDomain: "example.com"}
	st := hardeningTestState()
	a := realityDevice("device-a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")
	b := realityDevice("device-b", "4fad2182-6de3-4407-bf8f-d8c688160ce7")
	bRotated := realityDevice("device-b", "4fad2182-6de3-4407-bf8f-d8c688160ce8")
	oldRaw, err := xrayConfigBytes(cfg, st, []approvedDevice{a, b})
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := xrayConfigBytes(cfg, st, []approvedDevice{bRotated, realityDevice("device-c", "4fad2182-6de3-4407-bf8f-d8c688160ce9")})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := diffXrayUsers(oldRaw, newRaw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(diff.Remove, ",") != "device-a,device-b" {
		t.Fatalf("remove=%v", diff.Remove)
	}
	if len(diff.Add) != 2 || diff.Add[0]["email"] != "device-b" || diff.Add[0]["id"] != bRotated.RealityUUID || diff.Add[1]["email"] != "device-c" {
		t.Fatalf("add=%v", diff.Add)
	}

	changedDest := cfg
	changedDest.RealityDest = "other.example:443"
	otherRaw, err := xrayConfigBytes(changedDest, st, []approvedDevice{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := diffXrayUsers(oldRaw, otherRaw); err != errXrayNeedsRestart {
		t.Fatalf("non-client change must need restart, got %v", err)
	}
	legacy := strings.Replace(string(oldRaw), `"HandlerService",`, "", 1)
	if _, err := diffXrayUsers([]byte(legacy), newRaw); err != errXrayNeedsRestart {
		t.Fatalf("running config without HandlerService must need restart, got %v", err)
	}
	if _, err := diffXrayUsers(nil, newRaw); err != errXrayNeedsRestart {
		t.Fatalf("missing old config must need restart, got %v", err)
	}
}

type fakeDocker struct {
	mu        sync.Mutex
	commands  [][]string
	restarts  int
	addOutput string
}

func startFakeDocker(t *testing.T, fd *fakeDocker) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var lastCmd []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fd.mu.Lock()
		defer fd.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/containers/worker-xray-1/exec":
			var request struct {
				Cmd []string `json:"Cmd"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			lastCmd = request.Cmd
			fd.commands = append(fd.commands, request.Cmd)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"exec-1"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/exec/exec-1/start":
			out := ""
			switch {
			case containsString(lastCmd, "rmu"):
				out = "Removed 1 user(s) in total.\n"
			case containsString(lastCmd, "adu"):
				out = fd.addOutput
				if out == "" {
					out = "Added 1 user(s) in total.\n"
				}
			}
			_, _ = w.Write(dockerStreamFrame(1, []byte(out)))
		case r.Method == http.MethodGet && r.URL.Path == "/exec/exec-1/json":
			_, _ = io.WriteString(w, `{"Running":false,"ExitCode":0}`)
		case r.Method == http.MethodPost && r.URL.Path == "/containers/worker-xray-1/restart":
			fd.restarts++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	return socketPath
}

func TestApplyXrayConfigUpdatesUsersWithoutRestart(t *testing.T) {
	fd := &fakeDocker{}
	cfg := envConfig{
		StateDir:         t.TempDir(),
		RealityDest:      "example.com:443",
		CamouflageDomain: "example.com",
		XrayContainer:    "worker-xray-1",
		DockerSocket:     startFakeDocker(t, fd),
	}
	st := hardeningTestState()
	a := realityDevice("device-a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")
	b := realityDevice("device-b", "4fad2182-6de3-4407-bf8f-d8c688160ce7")
	first, _ := xrayConfigBytes(cfg, st, []approvedDevice{a})
	if err := writeXrayConfigBytes(cfg, first); err != nil {
		t.Fatal(err)
	}
	second, _ := xrayConfigBytes(cfg, st, []approvedDevice{b})
	if err := applyXrayConfig(cfg, second, 1); err != nil {
		t.Fatal(err)
	}
	if fd.restarts != 0 {
		t.Fatalf("client-only change restarted xray %d times", fd.restarts)
	}
	if len(fd.commands) != 2 || !containsString(fd.commands[0], "rmu") || !containsString(fd.commands[0], "device-a") || !containsString(fd.commands[1], "adu") {
		t.Fatalf("unexpected docker exec commands: %v", fd.commands)
	}
	if xrayRestartPending(cfg) {
		t.Fatal("restart marker left after successful live update")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "xray", "users-add.json")); !os.IsNotExist(err) {
		t.Fatalf("temporary users file left behind: %v", err)
	}
	raw, _ := os.ReadFile(xrayConfigPath(cfg))
	if string(raw) != string(second) {
		t.Fatal("xray config on disk not updated")
	}
	addDoc, _ := json.Marshal(xrayUserAddDocument([]map[string]any{{"id": b.RealityUUID, "email": b.DeviceID}}))
	if !strings.Contains(string(addDoc), `"port":8443`) || !strings.Contains(string(addDoc), `"tag":"reality-in"`) {
		t.Fatalf("adu document is not buildable by xray: %s", addDoc)
	}
}

func TestApplyXrayConfigFallsBackToRestartWhenLiveUpdateFails(t *testing.T) {
	fd := &fakeDocker{addOutput: "failed to add user\nAdded 0 user(s) in total.\n"}
	cfg := envConfig{
		StateDir:         t.TempDir(),
		RealityDest:      "example.com:443",
		CamouflageDomain: "example.com",
		XrayContainer:    "worker-xray-1",
		DockerSocket:     startFakeDocker(t, fd),
	}
	st := hardeningTestState()
	first, _ := xrayConfigBytes(cfg, st, nil)
	if err := writeXrayConfigBytes(cfg, first); err != nil {
		t.Fatal(err)
	}
	second, _ := xrayConfigBytes(cfg, st, []approvedDevice{realityDevice("device-a", "4fad2182-6de3-4407-bf8f-d8c688160ce6")})
	if err := applyXrayConfig(cfg, second, 1); err != nil {
		t.Fatal(err)
	}
	if fd.restarts != 1 {
		t.Fatalf("failed live update must fall back to one restart, got %d", fd.restarts)
	}
	if xrayRestartPending(cfg) {
		t.Fatal("restart marker left after restart")
	}
}

func TestXrayRoutingBlocksPrivateDestinationsByDefault(t *testing.T) {
	routing := xrayRouting(envConfig{})
	raw, _ := json.Marshal(routing)
	for _, want := range []string{`"domainStrategy":"IPIfNonMatch"`, `169.254.0.0/16`, `172.16.0.0/12`, `regexp:^[^.]*$`, `"outboundTag":"block"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("routing missing %s: %s", want, raw)
		}
	}
	rules := routing["rules"].([]any)
	if first := rules[0].(map[string]any); first["outboundTag"] != "api" {
		t.Fatalf("api rule must stay first: %#v", first)
	}
	open, _ := json.Marshal(xrayRouting(envConfig{AllowPrivateEgress: true}))
	if strings.Contains(string(open), "block") {
		t.Fatalf("private egress opt-out still blocks: %s", open)
	}
}

func TestXrayConfigOmitsSmokeUserWhenDisabledAndDedupesEmails(t *testing.T) {
	cfg := envConfig{RealityDest: "example.com:443", CamouflageDomain: "example.com", DisableSmokePeers: true}
	doc := xrayConfigDocument(cfg, hardeningTestState(), []approvedDevice{
		realityDevice("dup", "4fad2182-6de3-4407-bf8f-d8c688160ce6"),
		realityDevice("dup", "4fad2182-6de3-4407-bf8f-d8c688160ce7"),
		realityDevice("", "4fad2182-6de3-4407-bf8f-d8c688160ce8"),
	})
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "p0-smoke") {
		t.Fatalf("smoke user present while disabled: %s", raw)
	}
	clients := doc["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("duplicate email not skipped: %v", clients)
	}
	if clients[1].(map[string]any)["email"] != "device-4fad2182-6de3-4407-bf8f-d8c688160ce8" {
		t.Fatalf("empty device id must get a unique email: %v", clients[1])
	}
}

func TestRealityDestDefaultsToCamouflageDomain(t *testing.T) {
	if got := realityDest("", "www.example.net"); got != "www.example.net:443" {
		t.Fatalf("default dest=%q", got)
	}
	if got := realityDest(" awg-gw:9443 ", "www.example.net"); got != "awg-gw:9443" {
		t.Fatalf("explicit dest=%q", got)
	}
	if !isSelfStealDest("awg-gw:9443") || isSelfStealDest("www.example.net:443") {
		t.Fatal("self-steal detection is wrong")
	}
}

func TestDistributorCertIsRenewedBeforeExpiryAndOnNameChange(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir(), CamouflageDomain: "www.example.net"}
	if err := ensureDistributorCert(cfg); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(cfg.StateDir, "distributor", "certs", "tls.crt")
	now := time.Now()
	if distributorCertNeedsRenewal(certPath, cfg.CamouflageDomain, now) {
		t.Fatal("fresh certificate flagged for renewal")
	}
	if !distributorCertNeedsRenewal(certPath, cfg.CamouflageDomain, now.Add(340*24*time.Hour)) {
		t.Fatal("certificate close to expiry not flagged")
	}
	if !distributorCertNeedsRenewal(certPath, "other.example.net", now) {
		t.Fatal("certificate for another name not flagged")
	}
}

func TestFirstHostUsesMaskedSubnet(t *testing.T) {
	got, err := firstHost("10.13.13.5/24")
	if err != nil || got != "10.13.13.1" {
		t.Fatalf("firstHost=%q err=%v", got, err)
	}
	if got := secondHostCIDR("10.13.13.5/24"); got != "10.13.13.2/32" {
		t.Fatalf("secondHostCIDR=%q", got)
	}
	if _, err := firstHost("10.0.0.1/32"); err == nil {
		t.Fatal("subnet without hosts accepted")
	}
}

func TestReadEnvRejectsInvalidValues(t *testing.T) {
	base := map[string]string{
		"WORKER_STATE_DIR":  t.TempDir(),
		"EGRESS_IP":         "203.0.113.10",
		"CAMOUFLAGE_DOMAIN": "www.example.net",
	}
	cases := map[string]map[string]string{
		"capacity":    {"CAPACITY": "abc"},
		"xray port":   {"XRAY_PORT": "70000"},
		"orch key":    {"ORCH_URL": "https://orch.example:9091"},
		"smoke flag":  {"WORKER_SMOKE_PEERS": "yes"},
		"placeholder": {"CAMOUFLAGE_DOMAIN": "example.com"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range overrides {
				t.Setenv(k, v)
			}
			if _, err := readEnv(); err == nil {
				t.Fatalf("readEnv accepted %v", overrides)
			}
		})
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	t.Setenv("ORCH_URL", "https://orch.example:9091")
	t.Setenv("ORCH_STATIC_PUBLIC_KEY", "key")
	cfg, err := readEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableSmokePeers || cfg.RealityDest != "www.example.net:443" {
		t.Fatalf("orchestrated defaults wrong: smoke_disabled=%t dest=%q", cfg.DisableSmokePeers, cfg.RealityDest)
	}
}

func TestBootstrapIsNotOverwrittenByConcurrentRun(t *testing.T) {
	cfg := envConfig{
		StateDir:         t.TempDir(),
		AWGSubnet:        "10.13.13.0/24",
		AWGGateway:       "10.13.13.1",
		CamouflageDomain: "www.example.net",
		RealityDest:      "www.example.net:443",
		EgressIP:         "203.0.113.10",
		PublicAddress:    "203.0.113.10",
	}
	var wg sync.WaitGroup
	results := make([]stateFile, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = bootstrap(cfg)
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if results[i].AWG.PrivateKey != results[0].AWG.PrivateKey {
			t.Fatal("concurrent bootstraps produced different key material")
		}
	}
	onDisk, err := loadBootstrapState(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.AWG.PrivateKey != results[0].AWG.PrivateKey {
		t.Fatal("bootstrap.json does not match the in-memory state")
	}
}

func TestWriteFileLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	for i := 0; i < 3; i++ {
		if err := writeFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("unexpected files: %v", entries)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode().Perm())
	}
}

func TestDetectPublicEgressIPNeedsAgreement(t *testing.T) {
	serve := func(ip string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, ip)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	old := egressEchoURLs
	defer func() { egressEchoURLs = old }()

	egressEchoURLs = []string{serve("203.0.113.10"), serve("198.51.100.7"), serve("203.0.113.10")}
	if got := detectPublicEgressIP(); got != "203.0.113.10" {
		t.Fatalf("majority ip=%q", got)
	}
	egressEchoURLs = []string{serve("203.0.113.10"), serve("198.51.100.7")}
	if got := detectPublicEgressIP(); got != "" {
		t.Fatalf("disagreeing services must not pick an ip, got %q", got)
	}
}

func TestTelemetryHandlerReusesClient(t *testing.T) {
	stateDir := t.TempDir()
	if err := saveOrchState(stateDir, orchState{WorkerID: "worker-a"}); err != nil {
		t.Fatal(err)
	}
	created := 0
	oldFactory := newTelemetryClient
	newTelemetryClient = func(envConfig, stateFile) (telemetryClient, error) {
		created++
		return fakeTelemetryClient{}, nil
	}
	defer func() { newTelemetryClient = oldFactory }()
	handler := telemetryHandler(envConfig{StateDir: stateDir}, stateFile{})
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodPost, "/orchestrator/telemetry", strings.NewReader(`{"ok":true}`)))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status=%d", rec.Code)
		}
	}
	if created != 1 {
		t.Fatalf("telemetry client created %d times", created)
	}
}

func TestWriteUpdateArtifactRequiresManifestHash(t *testing.T) {
	cfg := envConfig{StateDir: t.TempDir()}
	apk := []byte("apk-bytes")
	sha := sha256HexBytes(apk)
	update := func(manifest string) *orchUpdateArtifact {
		return &orchUpdateArtifact{
			ManifestJSON:    manifest,
			ManifestMinisig: "sig",
			APKName:         "app.apk",
			APKBase64:       "YXBrLWJ5dGVz",
		}
	}
	if err := writeUpdateArtifact(cfg, update(`{"apk_sha256":"`+strings.Repeat("0", 64)+`"}`)); err == nil {
		t.Fatal("apk not matching the manifest accepted")
	}
	if err := writeUpdateArtifact(cfg, update(`{"version_code":3}`)); err == nil {
		t.Fatal("manifest without apk hash accepted")
	}
	if err := writeUpdateArtifact(cfg, update(`{"distributed_apk":{"apk_sha256":"`+sha+`"}}`)); err != nil {
		t.Fatal(err)
	}
}
