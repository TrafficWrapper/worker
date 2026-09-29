package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeClockLimiter() (*relayLimiter, *time.Time) {
	l := newRelayLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestRelayLimiterPerDeviceBurstAndRefill(t *testing.T) {
	l, now := fakeClockLimiter()
	for i := 0; i < relayDeviceBurst; i++ {
		release, _ := l.acquire("dev-a")
		if release == nil {
			t.Fatalf("post %d within the burst refused", i)
		}
		release()
		*now = now.Add(time.Second) // keep the global bucket topped up
	}
	release, wait := l.acquire("dev-a")
	if release != nil || wait <= 0 {
		t.Fatalf("burst exceeded but admitted (wait %v)", wait)
	}
	// Another device is not affected by dev-a.
	if release, _ := l.acquire("dev-b"); release == nil {
		t.Fatal("second device refused")
	} else {
		release()
	}
	*now = now.Add(7 * time.Second)
	if release, _ := l.acquire("dev-a"); release == nil {
		t.Fatal("device not admitted after refill")
	}
}

func TestRelayLimiterGlobalRateAndConcurrency(t *testing.T) {
	l, now := fakeClockLimiter()
	var releases []func()
	for i := 0; i < relayMaxConcurrent; i++ {
		release, _ := l.acquire("dev-" + strconv.Itoa(i))
		if release == nil {
			t.Fatalf("forward %d refused", i)
		}
		releases = append(releases, release)
	}
	if release, _ := l.acquire("dev-extra"); release != nil {
		t.Fatal("more concurrent forwards than slots")
	}
	for _, release := range releases {
		release()
	}
	// The global bucket is spent by now: many devices cannot exceed it.
	admitted := 0
	for i := 0; i < 50; i++ {
		if release, _ := l.acquire("many-" + strconv.Itoa(i)); release != nil {
			admitted++
			release()
		}
	}
	if admitted > relayGlobalBurst {
		t.Fatalf("%d posts admitted in one instant across devices", admitted)
	}
	*now = now.Add(10 * time.Second)
	if release, _ := l.acquire("later"); release == nil {
		t.Fatal("global budget did not refill")
	}
}

func TestRelayLimiterBoundsDeviceTable(t *testing.T) {
	l, now := fakeClockLimiter()
	for i := 0; i < relayMaxDevices+100; i++ {
		*now = now.Add(time.Second)
		if release, _ := l.acquire(strings.Repeat("x", 300) + strconv.Itoa(i)); release != nil {
			release()
		}
	}
	if len(l.devices) > relayMaxDevices+1 {
		t.Fatalf("device table grew to %d", len(l.devices))
	}
}

func TestTelemetryHandlerAnswers429WithRetryAfter(t *testing.T) {
	handler := telemetryHandler(envConfig{StateDir: t.TempDir()}, stateFile{})
	var last *httptest.ResponseRecorder
	for i := 0; i <= relayDeviceBurst; i++ {
		req := httptest.NewRequest(http.MethodPost, "/orchestrator/telemetry", strings.NewReader(`{}`))
		req.Header.Set("X-TW-Device", "flooder")
		last = httptest.NewRecorder()
		handler(last, req)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", last.Code)
	}
	if ra, err := strconv.Atoi(last.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("Retry-After %q", last.Header().Get("Retry-After"))
	}
	if strings.Contains(last.Body.String(), "device_not_approved") || !strings.Contains(last.Body.String(), `"rate_limited"`) {
		t.Fatalf("body %s", last.Body.String())
	}
}

func TestRelayUnknownDeviceIDsCannotSpendApprovedBudget(t *testing.T) {
	l, now := fakeClockLimiter()
	l.known = func(id string) bool { return id == "dev-approved" }
	// A client rotating X-TW-Device through made-up IDs.
	for i := 0; i < 200; i++ {
		if release, _ := l.acquire("rotating-" + strconv.Itoa(i)); release != nil {
			release()
		}
		*now = now.Add(100 * time.Millisecond)
	}
	release, wait := l.acquire("dev-approved")
	if release == nil {
		t.Fatalf("approved device starved by rotating unknown IDs (wait %v)", wait)
	}
	release()
}

func TestApprovedDeviceIDsReadsCachedConfig(t *testing.T) {
	stateDir := t.TempDir()
	writeCachedApprovedDevicesForTest(t, stateDir, []approvedDevice{{DeviceID: "dev-1", RealityUUID: "11111111-1111-4111-8111-111111111111", AWGPublicKey: keyB64(3), PSK2: keyB64(4), InternalIP: "10.13.13.10/32", Status: "approved"}}, 1)
	known := approvedDeviceIDs(stateDir)
	if !known("dev-1") {
		t.Fatal("approved device not known")
	}
	if known("dev-2") || known("") {
		t.Fatal("unknown device reported as approved")
	}
}
