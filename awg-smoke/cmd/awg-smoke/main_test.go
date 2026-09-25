package main

import "testing"

func TestParseSmokeIPAcceptsBareAndSingleHost(t *testing.T) {
	cases := map[string]string{
		"10.13.13.2":      "10.13.13.2/32",
		" 10.13.13.2 ":    "10.13.13.2/32",
		"10.13.13.2/32":   "10.13.13.2/32",
		"10.13.13.250":    "10.13.13.250/32",
		"fd00:13::2":      "fd00:13::2/128",
		"fd00:13::2/128":  "fd00:13::2/128",
		"::ffff:10.0.0.1": "::ffff:10.0.0.1/128",
	}
	for in, want := range cases {
		got, err := parseSmokeIP(in)
		if err != nil {
			t.Errorf("parseSmokeIP(%q) error: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("parseSmokeIP(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseSmokeIPRejectsNonSingleHost(t *testing.T) {
	for _, in := range []string{
		"",
		"10.13.13.2/24",
		"10.13.13.0/31",
		"fd00:13::2/64",
		"fe80::1%eth0",
		"not-an-ip",
		"10.13.13.2/33",
	} {
		if got, err := parseSmokeIP(in); err == nil {
			t.Errorf("parseSmokeIP(%q) = %s, want error", in, got)
		}
	}
}

func TestSmokeInterfacePrefix(t *testing.T) {
	for _, in := range []string{"10.13.13.2", "10.13.13.2/32"} {
		got, err := smokeInterfacePrefix(in)
		if err != nil {
			t.Fatalf("smokeInterfacePrefix(%q) error: %v", in, err)
		}
		if got != "10.13.13.2/24" {
			t.Fatalf("smokeInterfacePrefix(%q) = %q, want 10.13.13.2/24", in, got)
		}
	}
	for _, in := range []string{"10.13.13.2/24", "fd00:13::2", "fd00:13::2/128"} {
		if _, err := smokeInterfacePrefix(in); err == nil {
			t.Fatalf("smokeInterfacePrefix(%q) succeeded, want error", in)
		}
	}
}
