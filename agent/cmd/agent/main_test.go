package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeTelemetryClient struct {
	err error
}

func (c fakeTelemetryClient) telemetry(string, []byte, map[string]string) error {
	return c.err
}

func TestTelemetryHandlerReturnsDeviceNotApprovedMarker(t *testing.T) {
	rec := runTelemetryHandlerWithForwardError(t, errors.New("device is not approved"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusForbidden)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"device_not_approved"}` {
		t.Fatalf("body=%q", body)
	}
}

func TestTelemetryHandlerKeepsTransientErrorsAsBadGateway(t *testing.T) {
	rec := runTelemetryHandlerWithForwardError(t, errors.New("temporary orchestrator timeout"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusBadGateway)
	}
	if strings.Contains(rec.Body.String(), "device_not_approved") {
		t.Fatalf("transient error leaked deauth marker: %q", rec.Body.String())
	}
}

func TestTelemetryHandlerAcceptsApprovedForward(t *testing.T) {
	rec := runTelemetryHandlerWithForwardError(t, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAWGServerKeepaliveEnvDefaultsAndValidates(t *testing.T) {
	t.Setenv("AWG_SERVER_KEEPALIVE", "")
	got, err := getenvIntInRange("AWG_SERVER_KEEPALIVE", 0, 0, 65535)
	if err != nil || got != 0 {
		t.Fatalf("default keepalive=%d err=%v, want 0", got, err)
	}
	t.Setenv("AWG_SERVER_KEEPALIVE", "17")
	got, err = getenvIntInRange("AWG_SERVER_KEEPALIVE", 0, 0, 65535)
	if err != nil || got != 17 {
		t.Fatalf("configured keepalive=%d err=%v, want 17", got, err)
	}
	for _, value := range []string{"invalid", "-1", "65536"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AWG_SERVER_KEEPALIVE", value)
			if _, err := getenvIntInRange("AWG_SERVER_KEEPALIVE", 0, 0, 65535); err == nil {
				t.Fatalf("invalid keepalive %q accepted", value)
			}
		})
	}
}

func runTelemetryHandlerWithForwardError(t *testing.T, forwardErr error) *httptest.ResponseRecorder {
	t.Helper()
	stateDir := t.TempDir()
	if err := saveOrchState(stateDir, orchState{WorkerID: "worker-a"}); err != nil {
		t.Fatalf("save orch state: %v", err)
	}
	oldFactory := newTelemetryClient
	newTelemetryClient = func(envConfig, stateFile) (telemetryClient, error) {
		return fakeTelemetryClient{err: forwardErr}, nil
	}
	defer func() { newTelemetryClient = oldFactory }()

	req := httptest.NewRequest(http.MethodPost, "/orchestrator/telemetry", strings.NewReader(`{"ok":true}`))
	rec := httptest.NewRecorder()
	telemetryHandler(envConfig{StateDir: stateDir}, stateFile{})(rec, req)
	return rec
}
