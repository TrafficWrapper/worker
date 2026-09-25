package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func resetPlatformClock(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		platformOffsetMillis.Store(0)
		platformOffsetKnown.Store(false)
		platformSkewReported.Store(false)
	})
}

func TestTelemetryRelayResponseFollowsContract(t *testing.T) {
	for _, tc := range []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		// Structured codes.
		{&orchRejectedError{code: "device_not_approved", message: "device is not approved"}, 403, "device_not_approved"},
		{&orchRejectedError{code: "stale_timestamp", message: "x"}, 422, "stale_timestamp"},
		{&orchRejectedError{code: "replay"}, 422, "replay"},
		{&orchRejectedError{code: "bad_signature"}, 422, "bad_signature"},
		{&orchRejectedError{code: "unknown_device"}, 422, "unknown_device"},
		{&orchRejectedError{code: "invalid_payload"}, 422, "invalid_payload"},
		{&orchRejectedError{code: "worker_revoked", status: "revoked"}, 503, "worker_revoked"},
		{&orchRejectedError{code: "worker_pending", status: "pending"}, 503, "worker_pending"},
		{&orchRejectedError{code: "rate_limited"}, 429, "rate_limited"},
		{&orchRejectedError{code: "something_new"}, 422, "rejected"},
		// Orchestrators without codes, by their texts.
		{&orchRejectedError{message: "device is not approved"}, 403, "device_not_approved"},
		{&orchRejectedError{message: "telemetry timestamp outside freshness window"}, 422, "stale_timestamp"},
		{&orchRejectedError{message: "telemetry replay detected"}, 422, "replay"},
		{&orchRejectedError{message: "telemetry signature invalid"}, 422, "bad_signature"},
		{&orchRejectedError{message: "unknown device"}, 422, "unknown_device"},
		{&orchRejectedError{message: "invalid telemetry payload"}, 422, "invalid_payload"},
		{&orchRejectedError{message: "telemetry headers missing"}, 422, "invalid_payload"},
		{&orchRejectedError{message: "worker identity mismatch"}, 422, "invalid_payload"},
		{&orchRejectedError{message: "something else"}, 422, "invalid_payload"},
		{&orchRejectedError{status: "revoked", message: "worker revoked"}, 503, "worker_revoked"},
		// Before the orchestrator looked at the request.
		{&orchUnavailableError{httpStatus: 429, message: "http 429"}, 429, "rate_limited"},
		{&orchUnavailableError{httpStatus: 500, message: "http 500"}, 503, "orchestrator_unavailable"},
		{&orchUnavailableError{message: "too many pending handshakes"}, 503, "orchestrator_unavailable"},
		{errors.New("dial tcp: connection refused"), 502, "orchestrator_unreachable"},
	} {
		status, code := telemetryRelayResponse(tc.err)
		if status != tc.wantStatus || code != tc.wantCode {
			t.Fatalf("%T %q: got %d %s, want %d %s", tc.err, tc.err.Error(), status, code, tc.wantStatus, tc.wantCode)
		}
		if status != 403 && strings.Contains(code, "device_not_approved") {
			t.Fatalf("%q: deauth marker outside 403", tc.err.Error())
		}
	}
}

func TestTelemetryHandlerMapsForwardErrors(t *testing.T) {
	resetPlatformClock(t)
	for _, tc := range []struct {
		err        error
		wantStatus int
		wantBody   string
	}{
		{&orchRejectedError{code: "stale_timestamp", message: "telemetry timestamp outside freshness window"}, 422, `{"error":"stale_timestamp"}`},
		{&orchRejectedError{code: "rate_limited"}, 429, `{"error":"rate_limited"}`},
		{&orchRejectedError{code: "worker_pending", status: "pending"}, 503, `{"error":"worker_pending"}`},
	} {
		rec := runTelemetryHandlerWithForwardError(t, tc.err)
		if rec.Code != tc.wantStatus || strings.TrimSpace(rec.Body.String()) != tc.wantBody {
			t.Fatalf("%v: %d %s", tc.err, rec.Code, rec.Body.String())
		}
		if tc.wantStatus == 429 && rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
		if rec.Header().Get("X-TW-Server-Time") == "" {
			t.Fatal("response without X-TW-Server-Time")
		}
	}
}

func TestTelemetryHandlerRejectsInvalidPayloadAs422(t *testing.T) {
	handler := telemetryHandler(envConfig{StateDir: t.TempDir()}, stateFile{})
	req := httptest.NewRequest(http.MethodPost, "/orchestrator/telemetry", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "invalid_payload") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/orchestrator/telemetry", strings.NewReader(`{}`))
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "worker_pending") {
		t.Fatalf("not enrolled: %d %s", rec.Code, rec.Body.String())
	}
}

func TestServerTimeSetsPlatformClockAndHeader(t *testing.T) {
	resetPlatformClock(t)
	ahead := time.Now().Add(2 * time.Hour)
	f := newFakeOrchestrator(t, func(string, json.RawMessage) any {
		return map[string]any{"ok": true, "status": "active", "server_time": ahead.UnixMilli()}
	})
	if _, err := f.client(envConfig{}).pull(t.Context(), "w1", 0); err != nil {
		t.Fatal(err)
	}
	if skew := platformNow().Sub(ahead); skew < -5*time.Second || skew > 5*time.Second {
		t.Fatalf("platform time off by %v", skew)
	}
	if !platformClockSkewed() || !strings.Contains(selfCheckStatus(), "clock") {
		t.Fatalf("2h skew not reported: %q", selfCheckStatus())
	}
	rec := runTelemetryHandlerWithForwardError(t, nil)
	header, err := strconv.ParseInt(rec.Header().Get("X-TW-Server-Time"), 10, 64)
	if err != nil || time.UnixMilli(header).Sub(ahead).Abs() > 5*time.Second {
		t.Fatalf("X-TW-Server-Time %q does not follow orchestrator time", rec.Header().Get("X-TW-Server-Time"))
	}
}

func TestDeviceExpiryUsesOrchestratorTime(t *testing.T) {
	resetPlatformClock(t)
	expires := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	ds := desiredState{realityEnabled: true, awgEnabled: true, devices: []approvedDevice{{DeviceID: "d", ExpiresAt: expires}}}
	if len(ds.realityDevices(platformNow())) != 1 {
		t.Fatal("device expired by the local clock")
	}
	observeServerTime(time.Now().Add(time.Hour).UnixMilli(), time.Now())
	if len(ds.realityDevices(platformNow())) != 0 {
		t.Fatal("device still served after it expired by orchestrator time")
	}
}

func TestEnrollRejectionIsAnError(t *testing.T) {
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		return map[string]any{"ok": false, "error": "enrollment token invalid", "code": "bad_token"}
	})
	cfg := envConfig{StateDir: t.TempDir(), EnrollToken: "tok"}
	client := f.client(cfg)
	if _, err := client.enroll(t.Context(), "tok", nil); err == nil {
		t.Fatal("ok:false enroll returned no error")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	runOrchestratorLoop(ctx, cfg, hardeningTestState(), client)
	if got := loadOrchState(cfg.StateDir); got.WorkerID != "" {
		t.Fatalf("rejected enroll saved state %+v", got)
	}
	if n := len(f.requestsTo("/w/v1/config/pull")); n != 0 {
		t.Fatalf("worker pulled %d times without a worker id", n)
	}
}

func TestNudgeRejectionBacksOff(t *testing.T) {
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		if strings.HasSuffix(path, "/nudge/wait") {
			return map[string]any{"ok": false, "status": "pending", "code": "worker_pending", "error": "worker pending"}
		}
		return map[string]any{"ok": true, "status": "active", "not_modified": true}
	})
	cfg := envConfig{StateDir: t.TempDir()}
	if err := saveOrchState(cfg.StateDir, orchState{WorkerID: "w1", AppliedSeq: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	runOrchestratorLoop(ctx, cfg, hardeningTestState(), f.client(cfg))
	// A rejected nudge is an error: the worker re-pulls after a backoff
	// instead of treating it as a heartbeat.
	if n := len(f.requestsTo("/w/v1/nudge/wait")); n == 0 || n > 4 {
		t.Fatalf("%d nudges in 1.5s", n)
	}
	if n := len(f.requestsTo("/w/v1/config/pull")); n < 2 {
		t.Fatalf("rejected nudge did not lead to a new pull (%d pulls)", n)
	}
}
