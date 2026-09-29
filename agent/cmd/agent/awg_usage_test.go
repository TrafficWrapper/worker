package main

import (
	"strings"
	"testing"
	"time"

	"github.com/TrafficWrapper/worker/core/awg/serverpeer"
)

func TestBuildAWGUsageReportsAccumulatesAndHandlesCounterReset(t *testing.T) {
	pub := keyB64(9)
	pubHex, err := serverpeer.KeyB64ToHex(pub)
	if err != nil {
		t.Fatal(err)
	}
	devices := []approvedDevice{{
		DeviceID:     "device-a",
		AWGPublicKey: pub,
	}}
	now := time.Now().UTC()
	reports, state := buildAWGUsageReports(devices, []awgPeerConfig{{
		PublicKeyHex: pubHex,
		RxBytes:      100,
		TxBytes:      50,
	}}, nil, now)
	if len(reports) != 1 || reports[0].RxBytes != 100 || reports[0].TxBytes != 50 {
		t.Fatalf("bad first usage report: %+v", reports)
	}
	reports, state = buildAWGUsageReports(devices, []awgPeerConfig{{
		PublicKeyHex: pubHex,
		RxBytes:      25,
		TxBytes:      10,
	}}, state, now.Add(time.Minute))
	if len(reports) != 1 || reports[0].RxBytes != 125 || reports[0].TxBytes != 60 {
		t.Fatalf("counter reset was not accumulated: reports=%+v state=%+v", reports, state)
	}
}

func TestBuildAWGUsageReportsSkipsMissingPeer(t *testing.T) {
	reports, state := buildAWGUsageReports([]approvedDevice{{
		DeviceID:     "device-a",
		AWGPublicKey: keyB64(9),
	}}, nil, awgUsageState{}, time.Now().UTC())
	if len(reports) != 0 || len(state) != 0 {
		t.Fatalf("missing peer should not produce reports: reports=%+v state=%+v", reports, state)
	}
}

// altKeyText writes the same AWG key with an unused trailing bit set: a
// different base64 text for the same 32 bytes.
func altKeyText(t *testing.T, key string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(key) != 44 || key[43] != '=' {
		t.Fatalf("unexpected key text %q", key)
	}
	i := strings.IndexByte(alphabet, key[42])
	alt := key[:42] + string(alphabet[i^1]) + "="
	if a, _ := serverpeer.KeyB64ToHex(alt); a == "" {
		t.Fatalf("alt key %q does not decode", alt)
	}
	return alt
}

func TestAWGUsageCountsOneKeyOnceWhateverItsText(t *testing.T) {
	pub := keyB64(9)
	alt := altKeyText(t, pub)
	pubHex, _ := serverpeer.KeyB64ToHex(pub)
	peers := []awgPeerConfig{{PublicKeyHex: pubHex, RxBytes: 100, TxBytes: 50, Profile: "awg"}}
	now := time.Now().UTC()

	// One device naming its key twice, in two texts.
	one := []approvedDevice{{
		DeviceID:     "device-a",
		AWGPublicKey: pub,
		AWGProfiles:  map[string]approvedDeviceAWGProfile{"awg": {AWGPublicKey: alt}},
	}}
	reports, _ := buildAWGUsageReports(one, peers, nil, now)
	if len(reports) != 1 || reports[0].RxBytes != 100 || reports[0].TxBytes != 50 {
		t.Fatalf("one key in two texts counted more than once: %+v", reports)
	}

	// Two devices with the same key bytes: the registry gives the peer to the
	// first one only (awgKeyIdentity), so only it is charged.
	two := []approvedDevice{
		{DeviceID: "device-a", AWGPublicKey: pub},
		{DeviceID: "device-b", AWGPublicKey: alt},
	}
	reports, _ = buildAWGUsageReports(two, peers, nil, now)
	if len(reports) != 1 || reports[0].DeviceID != "device-a" || reports[0].RxBytes != 100 {
		t.Fatalf("traffic of one peer charged to several devices: %+v", reports)
	}
}
