package serverpeer

import "testing"

func TestParseBoolAcceptsCommonSpellings(t *testing.T) {
	cases := map[string]bool{
		"1": true, "true": true, "TRUE": true, " yes ": true, "On": true,
		"0": false, "false": false, "False": false, "no": false, "OFF": false,
	}
	for value, want := range cases {
		for _, fallback := range []bool{true, false} {
			got, err := ParseBool("X", value, fallback)
			if err != nil || got != want {
				t.Fatalf("ParseBool(%q, fallback=%t)=%t,%v want %t", value, fallback, got, err, want)
			}
		}
	}
}

func TestParseBoolEmptyUsesFallback(t *testing.T) {
	for _, value := range []string{"", "  "} {
		if got, err := ParseBool("X", value, true); err != nil || !got {
			t.Fatalf("ParseBool(%q, true)=%t,%v", value, got, err)
		}
		if got, err := ParseBool("X", value, false); err != nil || got {
			t.Fatalf("ParseBool(%q, false)=%t,%v", value, got, err)
		}
	}
}

func TestParseBoolRejectsUnknownValues(t *testing.T) {
	for _, value := range []string{"2", "y", "enable", "tru", "-1"} {
		if _, err := ParseBool("WORKER_BLOCK_SMTP", value, true); err == nil {
			t.Fatalf("ParseBool(%q) accepted", value)
		}
	}
}

func TestEnvBoolReadsEnvironment(t *testing.T) {
	t.Setenv("TW_TEST_BOOL", "off")
	if got, err := EnvBool("TW_TEST_BOOL", true); err != nil || got {
		t.Fatalf("EnvBool=%t,%v want false", got, err)
	}
}
