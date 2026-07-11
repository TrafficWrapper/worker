package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestBuildRealityUsageReportsMapsPerUserStats(t *testing.T) {
	raw := []byte(`{
  "stat": [
    {"name":"user>>>device-a>>>traffic>>>uplink","value":"60"},
    {"name":"user>>>device-a>>>traffic>>>downlink","value":40},
    {"name":"user>>>p0-smoke>>>traffic>>>uplink","value":"999"}
  ]
}`)
	reports, err := buildRealityUsageReports([]approvedDevice{{
		DeviceID:    "device-a",
		RealityUUID: "uuid-a",
		Status:      "approved",
	}, {
		DeviceID:    "device-b",
		RealityUUID: "uuid-b",
		Status:      "approved",
	}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("reports=%d want 2: %+v", len(reports), reports)
	}
	if reports[0].DeviceID != "device-a" || reports[0].Source != realityUsageSource || reports[0].RxBytes != 60 || reports[0].TxBytes != 40 {
		t.Fatalf("bad device-a report: %+v", reports[0])
	}
	if reports[1].DeviceID != "device-b" || reports[1].RxBytes != 0 || reports[1].TxBytes != 0 {
		t.Fatalf("zero baseline missing for device-b: %+v", reports[1])
	}
}

func TestCollectWorkerUsageReportsKeepsAWGWhenXrayStatsUnavailable(t *testing.T) {
	pub := keyB64(9)
	pubHex, err := base64KeyToHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, _ := startFakeUAPIServer(t, []string{
		"public_key=" + pubHex,
		"rx_bytes=10",
		"tx_bytes=20",
		"errno=0",
		"",
		"",
	})
	cfg := envConfig{
		StateDir:      t.TempDir(),
		AWGUAPISocket: socketPath,
	}
	reports := collectWorkerUsageReports(cfg, []approvedDevice{{
		DeviceID:     "device-a",
		RealityUUID:  "uuid-a",
		AWGPublicKey: pub,
		Status:       "approved",
	}})
	if len(reports) != 1 || reports[0].AWGPublicKey != pub || reports[0].RxBytes != 10 || reports[0].TxBytes != 20 {
		t.Fatalf("AWG usage lost when Xray stats unavailable: %+v", reports)
	}
}

func TestQueryXrayStatsViaDockerExec(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var command []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/containers/worker-xray-1/exec":
			var request struct {
				Cmd []string `json:"Cmd"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			mu.Lock()
			command = append([]string(nil), request.Cmd...)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"exec-1"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/exec/exec-1/start":
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			_, _ = w.Write(dockerStreamFrame(1, []byte(`{"stat":[]}`)))
		case r.Method == http.MethodGet && r.URL.Path == "/exec/exec-1/json":
			_, _ = io.WriteString(w, `{"Running":false,"ExitCode":0}`)
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
	raw, err := queryXrayStatsViaDocker(envConfig{
		DockerSocket:  socketPath,
		XrayContainer: "worker-xray-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"stat":[]}` {
		t.Fatalf("stats output=%q", raw)
	}
	mu.Lock()
	joined := strings.Join(command, " ")
	mu.Unlock()
	if !strings.Contains(joined, "statsquery") || !strings.Contains(joined, "127.0.0.1:10085") || !strings.Contains(joined, "-reset=false") {
		t.Fatalf("unexpected xray command: %q", joined)
	}
}

func dockerStreamFrame(stream byte, payload []byte) []byte {
	frame := make([]byte, 8+len(payload))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[8:], payload)
	return frame
}
