package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	stateDirDefault       = "/worker-state"
	xrayInPort            = 8443
	xrayAPIInPort         = 10085
	awgInPort             = 51821
	distributorTLS        = 9443
	distributorTW         = 8080
	telemetryMaxBodyBytes = 64 << 10
	defaultXrayAPISocket  = "/run/xray-api/api.sock"
)

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "healthcheck" {
		if err := runHealthcheck(getenv("AGENT_HEALTH_URL", "http://127.0.0.1:9090/healthz")); err != nil {
			fatal(err)
		}
		return
	}
	cfg, err := readEnv()
	if err != nil {
		fatal(err)
	}
	switch cmd {
	case "run":
		if err := run(cfg); err != nil {
			fatal(err)
		}
	case "bootstrap":
		_, err := bootstrap(cfg)
		if err != nil {
			fatal(err)
		}
	case "self-describe":
		st, err := loadBootstrapState(cfg.StateDir)
		if err != nil {
			fatal(err)
		}
		_ = encodeJSON(os.Stdout, selfDescribe(cfg, st))
	case "check-dialect":
		if err := checkDialectFromEnv(); err != nil {
			fatal(err)
		}
	case "show-awg-peers":
		_ = encodeJSON(os.Stdout, collectAWGProfilePeerSnapshots(cfg))
	default:
		fatal(fmt.Errorf("unknown command %q", cmd))
	}
}

func runHealthcheck(url string) error {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck %s: http %d", url, resp.StatusCode)
	}
	return nil
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func int64FromAny(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		out, _ := v.Int64()
		return out
	default:
		return 0
	}
}

func fatal(err error) {
	slog.Error("worker-agent failed", "err", err)
	os.Exit(1)
}
