package dialect

import (
	"strings"
	"testing"
)

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

func TestValidateRejectsHeaderWhitespaceAndControl(t *testing.T) {
	base, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{" ", "\n", "\r", "\t", "\x00", " "} {
		for _, pos := range []string{"prefix", "suffix", "middle"} {
			d := base
			switch pos {
			case "prefix":
				d.H3 = bad + d.H3
			case "suffix":
				d.H3 = d.H3 + bad
			default:
				d.H3 = d.H3[:3] + bad + d.H3[3:]
			}
			if err := Validate(d, DefaultMTU); err == nil {
				t.Fatalf("expected h3=%q to be rejected", d.H3)
			}
		}
	}
	compat := Compat()
	compat.H1 = "1\n"
	if err := Validate(compat, DefaultMTU); err == nil {
		t.Fatal("expected non-canonical compat header to be rejected")
	}
}

func TestUAPILinesNeverContainNewlines(t *testing.T) {
	d, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	h1 := d.H1
	d.H1 = h1 + "\n\nprivate_key=00"
	d.H4 = " " + d.H4 + "\r"
	for _, line := range UAPILines(d) {
		if strings.ContainsAny(line, "\r\n \t") {
			t.Fatalf("UAPI line contains whitespace: %q", line)
		}
	}
	lines := UAPILines(Compat())
	if !contains(lines, "h1=1") || !contains(lines, "h4=4") {
		t.Fatalf("compat headers changed: %v", lines)
	}
	d.H1 = "00" + h1
	if got := UAPILines(d); !contains(got, "h1="+h1) {
		t.Fatalf("expected canonical h1=%s, got %v", h1, got)
	}
}

func TestGenerateWideStaysValidAndVaries(t *testing.T) {
	seen := map[int]struct{}{}
	for i := 0; i < 50; i++ {
		d, err := GenerateWide()
		if err != nil {
			t.Fatal(err)
		}
		if d.Jmin < minJmin || d.Jmin > maxJmin || d.Jmax <= d.Jmin || d.Jc < minJc || d.Jc > maxJc {
			t.Fatalf("out of range: %+v", d)
		}
		seen[d.Jmin] = struct{}{}
	}
	if len(seen) < 5 {
		t.Fatalf("jmin barely varies: %v", seen)
	}
}

func TestValidateAcceptsLegacyAndRejectsOutOfRangeJunk(t *testing.T) {
	legacy, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Jmin != 8 || legacy.Jc < 4 || legacy.Jc > 12 || legacy.Jmax < 40 || legacy.Jmax > 80 {
		t.Fatalf("legacy generator left its compatible ranges: %+v", legacy)
	}
	for _, mutate := range []func(*Dialect){
		func(d *Dialect) { d.Jc = 2 },
		func(d *Dialect) { d.Jc = 17 },
		func(d *Dialect) { d.Jmin = 7 },
		func(d *Dialect) { d.Jmin = 65 },
		func(d *Dialect) { d.Jmax = d.Jmin },
		func(d *Dialect) { d.Jmax = 265 },
	} {
		d := legacy
		mutate(&d)
		if err := ValidateProduction(d, DefaultMTU); err == nil {
			t.Fatalf("accepted %+v", d)
		}
	}
}

func TestSizeCollisionsFlagsReceiverOffset(t *testing.T) {
	d := Dialect{S1: 30, S2: 24, S3: 10, S4: 20} // S2 == S4+4
	if got := SizeCollisions(d); len(got) != 1 || got[0] != "s2/response" {
		t.Fatalf("collisions %v", got)
	}
	if got := SizeCollisions(Dialect{S1: 30, S2: 40, S3: 10, S4: 20}); len(got) != 0 {
		t.Fatalf("false collision %v", got)
	}
	if got := SizeCollisions(Compat()); len(got) != 0 {
		t.Fatalf("compat flagged: %v", got)
	}
}

func TestGeneratedDialectsAvoidCollisionsAndFixedWindows(t *testing.T) {
	oldWindows := [][2]uint32{
		{100_000_000, 450_000_000},
		{600_000_000, 950_000_000},
		{1_100_000_000, 1_450_000_000},
		{1_600_000_000, 2_050_000_000},
	}
	outsideOld := false
	for i := 0; i < 500; i++ {
		d, err := GenerateWide()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateProduction(d, DefaultMTU); err != nil {
			t.Fatalf("generated dialect invalid: %v (%s)", err, Summary(d))
		}
		if c := SizeCollisions(d); len(c) != 0 {
			t.Fatalf("generated dialect has size collisions %v: %s", c, Summary(d))
		}
		if d.Jmin < 8 || d.Jmin > 64 || d.Jmax < d.Jmin+32 || d.Jmax > d.Jmin+200 {
			t.Fatalf("junk bounds: %s", Summary(d))
		}
		headers, err := HeaderRanges(d)
		if err != nil {
			t.Fatal(err)
		}
		for j, h := range headers {
			if width := h.End - h.Start; width < minHeaderSpan || width > maxHeaderSpan {
				t.Fatalf("h%d width %d out of bounds", j+1, width)
			}
			if h.Start < oldWindows[j][0] || h.End > oldWindows[j][1] {
				outsideOld = true
			}
		}
	}
	if !outsideOld {
		t.Fatal("headers still come from the fixed windows")
	}
}
