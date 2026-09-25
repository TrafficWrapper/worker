package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// The orchestrator may return a handshake cookie in the outer envelope of an
// authenticated /w/ response ("v1.<worker_id>.<expiry_unix>.<mac>"). The
// worker sends the latest one with its next handshake start, which puts the
// handshake into the orchestrator's per-worker budget instead of the shared
// one. The cookie is opaque to the worker: a missing, expired or rejected
// cookie only means the shared budget, as with an orchestrator that does not
// send one. It is kept in memory only.

const maxHandshakeCookieLen = 512

// handshakeCookieTTL bounds how long a cookie without a readable expiry is
// sent; the orchestrator issues cookies for an hour.
const handshakeCookieTTL = time.Hour

type handshakeCookie struct {
	value   string
	expires time.Time
}

var handshakeCookies = struct {
	mu sync.Mutex
	m  map[string]handshakeCookie
}{m: map[string]handshakeCookie{}}

// handshakeCookieKey scopes a cookie to one orchestrator identity.
func handshakeCookieKey(c *orchClient) string {
	return strings.TrimRight(c.cfg.OrchURL, "/") + "|" + c.cfg.OrchStaticPublic
}

// validHandshakeCookie accepts only short printable ASCII, so an unexpected
// value is never echoed into a request.
func validHandshakeCookie(v string) bool {
	if v == "" || len(v) > maxHandshakeCookieLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' || v[i] == '"' || v[i] == '\\' {
			return false
		}
	}
	return true
}

// handshakeCookieExpiry reads the expiry of a v1 cookie; for any other form
// it falls back to the receive time plus handshakeCookieTTL.
func handshakeCookieExpiry(v string, now time.Time) time.Time {
	fallback := now.Add(handshakeCookieTTL)
	parts := strings.Split(v, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return fallback
	}
	unix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || unix <= 0 {
		return fallback
	}
	exp := time.Unix(unix, 0)
	if exp.After(fallback) {
		return fallback
	}
	return exp
}

func (c *orchClient) rememberHandshakeCookie(v string) {
	if !validHandshakeCookie(v) {
		return
	}
	now := platformNow()
	exp := handshakeCookieExpiry(v, now)
	if !exp.After(now) {
		return
	}
	handshakeCookies.mu.Lock()
	handshakeCookies.m[handshakeCookieKey(c)] = handshakeCookie{value: v, expires: exp}
	handshakeCookies.mu.Unlock()
}

// currentHandshakeCookie returns the cookie to send, or "" when there is none
// or it has expired.
func (c *orchClient) currentHandshakeCookie() string {
	key := handshakeCookieKey(c)
	handshakeCookies.mu.Lock()
	defer handshakeCookies.mu.Unlock()
	hc, ok := handshakeCookies.m[key]
	if !ok {
		return ""
	}
	if !platformNow().Before(hc.expires) {
		delete(handshakeCookies.m, key)
		return ""
	}
	return hc.value
}
