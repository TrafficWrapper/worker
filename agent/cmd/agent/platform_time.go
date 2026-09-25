package main

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// The orchestrator puts server_time (unix ms) in its Noise responses. The
// worker keeps the offset of its own clock from it and uses the corrected
// time for expiry decisions and for the X-TW-Server-Time header clients sign
// with, so a VPS with a wrong clock does not drop devices or break telemetry.
// Without server_time the worker's own clock is used, as before.

// platformClockSkewLimit is the offset above which the worker reports its
// clock as degraded.
const platformClockSkewLimit = time.Minute

var (
	platformOffsetMillis atomic.Int64
	platformOffsetKnown  atomic.Bool
	platformSkewReported atomic.Bool
)

// observeServerTime records the orchestrator time from a response received
// at local time receivedAt.
func observeServerTime(serverUnixMillis int64, receivedAt time.Time) {
	if serverUnixMillis <= 0 {
		return
	}
	offset := serverUnixMillis - receivedAt.UnixMilli()
	platformOffsetMillis.Store(offset)
	platformOffsetKnown.Store(true)
	skewed := time.Duration(abs64(offset))*time.Millisecond > platformClockSkewLimit
	if skewed != platformSkewReported.Swap(skewed) {
		if skewed {
			slog.Warn("worker clock differs from the orchestrator; using orchestrator time for expiry and telemetry", "offset", time.Duration(offset)*time.Millisecond)
		} else {
			slog.Info("worker clock is back in sync with the orchestrator")
		}
	}
}

// platformNow is the current time corrected by the last known offset.
func platformNow() time.Time {
	now := time.Now().UTC()
	if !platformOffsetKnown.Load() {
		return now
	}
	return now.Add(time.Duration(platformOffsetMillis.Load()) * time.Millisecond)
}

// platformClockSkewed reports whether the worker clock is off by more than
// platformClockSkewLimit.
func platformClockSkewed() bool {
	return platformOffsetKnown.Load() && time.Duration(abs64(platformOffsetMillis.Load()))*time.Millisecond > platformClockSkewLimit
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
