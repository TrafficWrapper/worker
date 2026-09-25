package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSuperviseRestartsAfterPanic(t *testing.T) {
	old := supervisePanicDelay
	supervisePanicDelay = time.Millisecond
	t.Cleanup(func() { supervisePanicDelay = old })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervise(ctx, "test", func() {
			if runs.Add(1) < 3 {
				panic("boom")
			}
			cancel()
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervise did not return")
	}
	if runs.Load() != 3 {
		t.Fatalf("runs %d, want 3 (two panics, then a clean run)", runs.Load())
	}
}

func TestSuperviseStopsWhenLoopReturns(t *testing.T) {
	calls := 0
	supervise(t.Context(), "test", func() { calls++ })
	if calls != 1 {
		t.Fatalf("a loop that returned normally ran %d times", calls)
	}
}

// FuzzParseDesiredState checks that no worker config, however malformed,
// makes the parser or the checks run on it panic.
func FuzzParseDesiredState(f *testing.F) {
	f.Add(`{"desired_state":{"approved_devices":[]}}`)
	f.Add(`{"schema":1,"worker_id":"w","desired_state":{"approved_devices":[` + testDeviceJSON(1) + `],"reality":{"enabled":false}}}`)
	f.Add(`{"schema":"x","desired_state":{"approved_devices":[{"status":"approved","awg_profiles":{"a":{}}}]}}`)
	f.Add(`{"desired_state":{"approved_devices":[{"status":"approved","expires_at":"2026-99-99"}]}}`)
	f.Add(strings.Repeat("[", 1000))
	f.Fuzz(func(t *testing.T, raw string) {
		ds, err := parseDesiredState(raw)
		_ = checkWorkerConfigIdentity(raw, "w")
		if err != nil {
			return
		}
		_ = ds.checkRejections()
		now := time.Now()
		_ = ds.realityDevices(now)
		_ = ds.awgDevices(now)
	})
}
