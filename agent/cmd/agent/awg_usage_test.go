package main

import (
	"testing"
	"time"
)

func TestBuildAWGUsageReportsAccumulatesAndHandlesCounterReset(t *testing.T) {
	pub := keyB64(9)
	pubHex, err := base64KeyToHex(pub)
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
