package main

import (
	"math"
	"strings"
	"sync"
	"time"
)

// Every telemetry post is relayed to the orchestrator as a full Noise
// handshake, and the orchestrator budgets handshakes per worker address
// together with the worker's own pull, nudge and ack. The relay therefore
// keeps well inside that budget: a per-device rate, a worker-wide rate and a
// cap on concurrent forwards.
const (
	relayDeviceRate     = 1.0 / 6 // tokens per second: 10 posts a minute
	relayDeviceBurst    = 5
	relayGlobalRate     = 1.0 // posts per second for the whole worker
	relayGlobalBurst    = 5
	relayMaxConcurrent  = 4
	relayMaxDevices     = 4096
	relayDeviceIdleTTL  = 10 * time.Minute
	relayMaxDeviceIDLen = 128
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// take refills the bucket and spends one token; otherwise it returns how
// long until a token is available.
func (b *tokenBucket) take(now time.Time, rate float64, burst int) (bool, time.Duration) {
	if b.last.IsZero() {
		b.tokens = float64(burst)
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(float64(burst), b.tokens+elapsed*rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
}

type relayLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	global  tokenBucket
	devices map[string]*tokenBucket
	slots   chan struct{}
}

func newRelayLimiter() *relayLimiter {
	return &relayLimiter{
		now:     time.Now,
		devices: map[string]*tokenBucket{},
		slots:   make(chan struct{}, relayMaxConcurrent),
	}
}

// acquire admits one relay for the device and returns a release function, or
// the delay a client should wait before retrying.
func (l *relayLimiter) acquire(deviceID string) (func(), time.Duration) {
	key := relayDeviceKey(deviceID)
	l.mu.Lock()
	now := l.now()
	bucket := l.deviceBucket(key, now)
	// Check the device first so one noisy device cannot spend the shared
	// budget, and only spend its token when the global budget allows it too.
	probe := *bucket
	if ok, wait := probe.take(now, relayDeviceRate, relayDeviceBurst); !ok {
		*bucket = probe
		l.mu.Unlock()
		return nil, wait
	}
	if ok, wait := l.global.take(now, relayGlobalRate, relayGlobalBurst); !ok {
		l.mu.Unlock()
		return nil, wait
	}
	*bucket = probe
	l.mu.Unlock()
	select {
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, 0
	default:
		return nil, time.Second
	}
}

func (l *relayLimiter) deviceBucket(key string, now time.Time) *tokenBucket {
	if b, ok := l.devices[key]; ok {
		return b
	}
	if len(l.devices) >= relayMaxDevices {
		for k, b := range l.devices {
			if now.Sub(b.last) > relayDeviceIdleTTL {
				delete(l.devices, k)
			}
		}
	}
	if len(l.devices) >= relayMaxDevices {
		// Too many distinct IDs at once: they share one bucket instead of
		// growing the table.
		key = ""
		if b, ok := l.devices[key]; ok {
			return b
		}
	}
	b := &tokenBucket{}
	l.devices[key] = b
	return b
}

// relayDeviceKey bounds the header used as a map key. Posts without a device
// ID share one bucket.
func relayDeviceKey(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if len(deviceID) > relayMaxDeviceIDLen {
		deviceID = deviceID[:relayMaxDeviceIDLen]
	}
	return deviceID
}

// retryAfterSeconds rounds a wait up to whole seconds for Retry-After.
func retryAfterSeconds(wait time.Duration) int {
	s := int(math.Ceil(wait.Seconds()))
	if s < 1 {
		return 1
	}
	return s
}
