package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/agent/internal/protocol"
)

func pullOK(path string, _ json.RawMessage) any {
	return map[string]any{"ok": true, "status": "active", "desired_seq": 1}
}

// startCookie returns the cookie field of the i-th handshake start, and
// whether the field was present at all.
func startCookie(t *testing.T, f *fakeOrchestrator, i int) (string, bool) {
	t.Helper()
	starts := f.startRequests()
	if len(starts) <= i {
		t.Fatalf("only %d handshake starts", len(starts))
	}
	var body map[string]any
	if err := json.Unmarshal(starts[i], &body); err != nil {
		t.Fatal(err)
	}
	v, ok := body["cookie"]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

func TestHandshakeCookieIsSentOnNextHandshake(t *testing.T) {
	f := newFakeOrchestrator(t, pullOK)
	cookie := fmt.Sprintf("v1.w1.%d.mac", time.Now().Add(time.Hour).Unix())
	f.setCookie(cookie)
	c := f.client(envConfig{})
	for range 2 {
		if _, err := c.pull(t.Context(), "w1", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := startCookie(t, f, 0); ok {
		t.Fatal("first handshake sent a cookie before one was issued")
	}
	if got, _ := startCookie(t, f, 1); got != cookie {
		t.Fatalf("second handshake cookie=%q want %q", got, cookie)
	}
	// A fresh client for the same orchestrator (telemetry builds one per
	// request) uses the same cookie.
	c2, err := newOrchClient(c.cfg, stateFileFor(c))
	if err != nil {
		t.Fatal(err)
	}
	if got := c2.currentHandshakeCookie(); got != cookie {
		t.Fatalf("new client cookie=%q want %q", got, cookie)
	}
}

func stateFileFor(c *orchClient) stateFile {
	kp := protocol.NewKeyPairFile(c.staticKey)
	var st stateFile
	st.NoiseStatic.PrivateKey = kp.PrivateKey
	st.NoiseStatic.PublicKey = kp.PublicKey
	return st
}

func TestHandshakeCookieWithoutOrchestratorSupport(t *testing.T) {
	f := newFakeOrchestrator(t, pullOK)
	c := f.client(envConfig{})
	for range 2 {
		if _, err := c.pull(t.Context(), "w1", 0); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if _, ok := startCookie(t, f, i); ok {
			t.Fatalf("handshake %d sent a cookie field to an orchestrator that issues none", i)
		}
	}
}

func TestHandshakeCookieExpiredOrInvalidIsNotSent(t *testing.T) {
	for name, cookie := range map[string]string{
		"expired":   fmt.Sprintf("v1.w1.%d.mac", time.Now().Add(-time.Minute).Unix()),
		"space":     "v1.w1 x",
		"quote":     `v1."x"`,
		"control":   "v1.\n",
		"too long":  "v1." + strings.Repeat("a", maxHandshakeCookieLen),
		"non-ascii": "v1.ключ",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeOrchestrator(t, pullOK)
			f.setCookie(cookie)
			c := f.client(envConfig{})
			for range 2 {
				if _, err := c.pull(t.Context(), "w1", 0); err != nil {
					t.Fatal(err)
				}
			}
			if got, ok := startCookie(t, f, 1); ok {
				t.Fatalf("sent cookie %q", got)
			}
		})
	}
}

func TestHandshakeCookieExpiresInMemory(t *testing.T) {
	f := newFakeOrchestrator(t, pullOK)
	c := f.client(envConfig{})
	c.rememberHandshakeCookie(fmt.Sprintf("v1.w1.%d.mac", time.Now().Add(2*time.Second).Unix()))
	if c.currentHandshakeCookie() == "" {
		t.Fatal("fresh cookie not kept")
	}
	handshakeCookies.mu.Lock()
	hc := handshakeCookies.m[handshakeCookieKey(c)]
	hc.expires = time.Now().Add(-time.Second)
	handshakeCookies.m[handshakeCookieKey(c)] = hc
	handshakeCookies.mu.Unlock()
	if got := c.currentHandshakeCookie(); got != "" {
		t.Fatalf("expired cookie still sent: %q", got)
	}
}

func TestHandshakeCookieExpiryIsCapped(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	if got := handshakeCookieExpiry(fmt.Sprintf("v1.w.%d.m", now.Add(48*time.Hour).Unix()), now); !got.Equal(now.Add(handshakeCookieTTL)) {
		t.Fatalf("far expiry not capped: %v", got)
	}
	if got := handshakeCookieExpiry("opaque", now); !got.Equal(now.Add(handshakeCookieTTL)) {
		t.Fatalf("opaque cookie expiry %v", got)
	}
	if got := handshakeCookieExpiry(fmt.Sprintf("v1.w.%d.m", now.Add(time.Minute).Unix()), now); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("v1 expiry %v", got)
	}
}
