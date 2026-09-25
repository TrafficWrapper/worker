package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func run(cfg envConfig) error {
	st, err := bootstrap(cfg)
	if err != nil {
		return err
	}
	if err := checkSelfDescribe(cfg, st); err != nil {
		return err
	}
	var orch *orchClient
	if cfg.OrchURL != "" {
		if orch, err = prepareOrchestrator(cfg, st); err != nil {
			return err
		}
	}
	if cfg.OrchURL == "" {
		slog.Info("awg reconcile standalone mode: startup pass is best-effort and no periodic orchestrator pass will run")
	}
	if err := reconcileAWGPeers(cfg, st); err != nil {
		slog.Warn("awg startup reconcile incomplete", "err", err)
	}
	localAPI, err := loadLocalAPIPolicy(cfg.AgentAPIAllowCIDRs)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/self-describe", localAPI.wrap(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, selfDescribe(cfg, st))
	}))
	mux.HandleFunc("/enroll", standaloneStub("enroll", cfg))
	mux.HandleFunc("/pull", standaloneStub("pull", cfg))
	mux.HandleFunc("/nudge", standaloneStub("nudge", cfg))
	mux.HandleFunc("/ack", standaloneStub("ack", cfg))
	mux.HandleFunc("/orchestrator/telemetry", telemetryHandler(cfg, st))
	// Compose publishes the agent port on host loopback only, and other
	// containers are refused: peer labels expose public keys and endpoints.
	mux.HandleFunc("/metrics", localAPI.wrap(metricsHandler(cfg, time.Now())))

	srv := &http.Server{
		Addr:              ":9090",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var workers sync.WaitGroup
	goWorker := func(fn func()) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			fn()
		}()
	}
	goWorker(func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	})
	goWorker(func() { runDistributorCertRenewal(ctx, cfg) })
	goWorker(func() { runHealthProbes(ctx, cfg) })
	if cfg.OrchURL != "" {
		goWorker(func() { runOrchestratorLoop(ctx, cfg, st, orch) })
	}
	slog.Info("worker-agent started", "standalone", cfg.OrchURL == "", "self_describe", ":9090/self-describe", "orch_url", cfg.OrchURL)
	err = srv.ListenAndServe()
	// ListenAndServe also returns on a startup error; stop the workers either way.
	stop()
	if !waitTimeout(&workers, shutdownGracePeriod) {
		slog.Warn("shutdown: background workers did not stop in time", "timeout", shutdownGracePeriod)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

const shutdownGracePeriod = 10 * time.Second

// waitTimeout reports whether wg finished within d.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

func telemetryHandler(cfg envConfig, st stateFile) http.HandlerFunc {
	limiter := newRelayLimiter()
	// One client for the handler's lifetime keeps the HTTPS connection to the
	// orchestrator alive between telemetry posts.
	var (
		clientMu sync.Mutex
		cached   telemetryClient
	)
	getClient := func() (telemetryClient, error) {
		clientMu.Lock()
		defer clientMu.Unlock()
		if cached != nil {
			return cached, nil
		}
		client, err := newTelemetryClient(cfg, st)
		if err != nil {
			return nil, err
		}
		cached = client
		return cached, nil
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// Clients sign X-TW-Ts with this offset instead of trusting their
		// own clock.
		w.Header().Set("X-TW-Server-Time", strconv.FormatInt(platformNow().UnixMilli(), 10))
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		release, wait := limiter.acquire(r.Header.Get("X-TW-Device"))
		if release == nil {
			telemetryRelayLimitedTotal.Add(1)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
			writeTelemetryError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		defer release()
		raw, err := io.ReadAll(io.LimitReader(r.Body, telemetryMaxBodyBytes+1))
		if err != nil || len(raw) == 0 || len(raw) > telemetryMaxBodyBytes || !json.Valid(raw) {
			writeTelemetryError(w, http.StatusUnprocessableEntity, "invalid_payload")
			return
		}
		state := loadOrchState(cfg.StateDir)
		switch {
		case state.Status == orchStatusRevoked:
			writeTelemetryError(w, http.StatusServiceUnavailable, "worker_revoked")
			return
		case state.WorkerID == "":
			writeTelemetryError(w, http.StatusServiceUnavailable, "worker_pending")
			return
		}
		client, err := getClient()
		if err != nil {
			slog.Warn("telemetry relay unavailable", "err", err)
			writeTelemetryError(w, http.StatusServiceUnavailable, "orchestrator_unavailable")
			return
		}
		headers := telemetryHeadersFromRequest(r)
		if err := client.telemetry(r.Context(), state.WorkerID, raw, headers); err != nil {
			status, code := telemetryRelayResponse(err)
			if status == http.StatusForbidden {
				slog.Warn("telemetry forward rejected: device is not approved")
				writeDeviceNotApprovedResponse(w)
				return
			}
			slog.Warn("telemetry forward failed", "status", status, "code", code, "err", err)
			if status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "5")
			}
			writeTelemetryError(w, status, code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type telemetryClient interface {
	telemetry(ctx context.Context, workerID string, payload []byte, headers map[string]string) error
}

var newTelemetryClient = func(cfg envConfig, st stateFile) (telemetryClient, error) {
	return newOrchClient(cfg, st)
}

// Telemetry rejection codes the orchestrator sends, and what the relay
// answers for them. Clients drop 422, reauthenticate only on 403 with
// device_not_approved, and retry 429 and 5xx.
var telemetryCodeStatus = map[string]int{
	"device_not_approved": http.StatusForbidden,
	"stale_timestamp":     http.StatusUnprocessableEntity,
	"replay":              http.StatusUnprocessableEntity,
	"bad_signature":       http.StatusUnprocessableEntity,
	"unknown_device":      http.StatusUnprocessableEntity,
	"invalid_payload":     http.StatusUnprocessableEntity,
	"worker_revoked":      http.StatusServiceUnavailable,
	"worker_pending":      http.StatusServiceUnavailable,
	"rate_limited":        http.StatusTooManyRequests,
}

// telemetryRelayResponse maps a failed forward to the relay's HTTP status
// and error code. Orchestrators without structured codes are mapped by
// their error texts; an unrecognized rejection is not retried.
func telemetryRelayResponse(err error) (int, string) {
	if strings.Contains(strings.ToLower(err.Error()), "device is not approved") {
		return http.StatusForbidden, "device_not_approved"
	}
	var rejected *orchRejectedError
	if errors.As(err, &rejected) {
		if status, ok := telemetryCodeStatus[rejected.code]; ok {
			return status, rejected.code
		}
		if rejected.code != "" {
			return http.StatusUnprocessableEntity, "rejected"
		}
		code := legacyTelemetryCode(rejected.status, rejected.message)
		return telemetryCodeStatus[code], code
	}
	var unavailable *orchUnavailableError
	if errors.As(err, &unavailable) {
		if unavailable.httpStatus == http.StatusTooManyRequests {
			return http.StatusTooManyRequests, "rate_limited"
		}
		return http.StatusServiceUnavailable, "orchestrator_unavailable"
	}
	return http.StatusBadGateway, "orchestrator_unreachable"
}

func legacyTelemetryCode(status, message string) string {
	msg := strings.ToLower(strings.TrimSpace(message))
	switch {
	case strings.Contains(msg, "device is not approved"):
		return "device_not_approved"
	case status == orchStatusRevoked:
		return "worker_revoked"
	case status == "pending":
		return "worker_pending"
	case strings.Contains(msg, "freshness window"), strings.Contains(msg, "timestamp"):
		return "stale_timestamp"
	case strings.Contains(msg, "replay"):
		return "replay"
	case strings.Contains(msg, "signature"):
		return "bad_signature"
	case strings.HasPrefix(msg, "unknown device"):
		return "unknown_device"
	default:
		// "invalid telemetry payload", other "telemetry ..." texts, "worker
		// identity mismatch" and anything unknown.
		return "invalid_payload"
	}
}

// writeTelemetryError answers with the structured {error: code} body clients
// classify by.
func writeTelemetryError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

func writeDeviceNotApprovedResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"device_not_approved"}`))
}

func telemetryHeadersFromRequest(r *http.Request) map[string]string {
	headers := map[string]string{}
	for _, name := range []string{
		"X-TW-Device",
		"X-TW-Pub",
		"X-TW-KeyType",
		"X-TW-Ts",
		"X-TW-Nonce",
		"X-TW-Sig",
	} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			headers[name] = value
		}
	}
	return headers
}

func standaloneStub(action string, cfg envConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		status := map[string]any{"ok": true, "action": action, "standalone": cfg.OrchURL == ""}
		if cfg.OrchURL == "" {
			status["message"] = "ORCH_URL is empty; P0 standalone mode"
		}
		writeJSON(w, status)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("content-type", "application/json")
	_ = encodeJSON(w, value)
}

func encodeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
