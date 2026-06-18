package dialect

import "testing"

func TestGenerateValidProductionDialect(t *testing.T) {
	for i := 0; i < 100; i++ {
		d, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(d, DefaultMTU); err != nil {
			t.Fatalf("generated invalid dialect %s: %v", Summary(d), err)
		}
	}
}

func TestValidateRejectsBadPaddingInvariant(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	d.S2 = d.S1 + 56
	if err := Validate(d, DefaultMTU); err == nil {
		t.Fatal("expected invalid s1+56==s2 to be rejected")
	}
}

func TestValidateRejectsOverlappingHeaders(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	d.H2 = d.H1
	if err := Validate(d, DefaultMTU); err == nil {
		t.Fatal("expected overlapping h ranges to be rejected")
	}
}

func TestValidateRejectsSingleProductionHeaders(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	d.H1 = "102030405"
	if err := Validate(d, DefaultMTU); err == nil {
		t.Fatal("expected single production h value to be rejected")
	}
}

func TestCompatProfile(t *testing.T) {
	d := Compat()
	if err := Validate(d, DefaultMTU); err != nil {
		t.Fatalf("compat profile rejected: %v", err)
	}
	if got := UAPILines(d); contains(got, "jc=0") {
		t.Fatalf("compat UAPI must not set invalid jc=0: %v", got)
	}
}

func TestEffectiveMTUUsesMobileSafeOuterPath(t *testing.T) {
	d := Dialect{
		Jc: 4, Jmin: 8, Jmax: 40,
		S1: 15, S2: 16, S3: 0, S4: 22,
		H1: "10-10000000",
		H2: "20000000-30000000",
		H3: "40000000-50000000",
		H4: "60000000-70000000",
	}
	mtu, err := EffectiveMTU(DefaultMTU, d)
	if err != nil {
		t.Fatal(err)
	}
	if want := MobileSafeOuterMTU - MaxOuterIPUDPOverhead - WireGuardDataOverhead - d.S4; mtu != want {
		t.Fatalf("effective mtu = %d, want %d", mtu, want)
	}
	if want := 1138; TCPMSSForMTU(mtu) != want {
		t.Fatalf("tcp mss = %d, want %d", TCPMSSForMTU(mtu), want)
	}
}

func TestEffectiveMTUWorstCaseS4FitsOuter1280(t *testing.T) {
	d := Dialect{
		Jc: 4, Jmin: 8, Jmax: 40,
		S1: 15, S2: 16, S3: 0, S4: 32,
		H1: "10-10000000",
		H2: "20000000-30000000",
		H3: "40000000-50000000",
		H4: "60000000-70000000",
	}
	mtu, err := EffectiveMTU(DefaultMTU, d)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1168; mtu != want {
		t.Fatalf("effective mtu = %d, want %d", mtu, want)
	}
}

func TestEffectiveMTUCompatStillClampsForMobilePath(t *testing.T) {
	mtu, err := EffectiveMTU(DefaultMTU, Compat())
	if err != nil {
		t.Fatal(err)
	}
	if want := 1200; mtu != want {
		t.Fatalf("compat effective mtu = %d, want %d", mtu, want)
	}
}

func contains(lines []string, needle string) bool {
	for _, line := range lines {
		if line == needle {
			return true
		}
	}
	return false
}
