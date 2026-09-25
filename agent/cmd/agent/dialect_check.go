package main

import (
	"log/slog"
	"sync/atomic"

	"github.com/TrafficWrapper/worker/core/awg/dialect"
)

// dialectSizeCollision is set when a stored AWG dialect has padding sizes
// that let transport packets be taken for handshake messages. Stored
// dialects are never changed in place (every client would break); the
// operator rotates to a new profile, whose dialect is generated without it.
var dialectSizeCollision atomic.Bool

func checkDialectSizes(cfg envConfig, st stateFile) {
	found := false
	for _, profile := range awgProfiles(cfg) {
		if collisions := dialect.SizeCollisions(profileDialect(st, profile)); len(collisions) > 0 {
			found = true
			slog.Warn("AWG dialect padding lets transport packets of some sizes be dropped as handshakes; rotate to a new profile (see ARCHITECTURE)", "profile", profile.Name, "collisions", collisions)
		}
	}
	dialectSizeCollision.Store(found)
}
