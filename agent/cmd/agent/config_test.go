package main

import (
	"strings"
	"testing"
)

func TestValidateCamouflageDomainRejectsPlaceholders(t *testing.T) {
	for _, value := range []string{"", "example.com", "EXAMPLE.ORG", "  example.com  "} {
		if err := validateCamouflageDomain(value); err == nil {
			t.Fatalf("placeholder CAMOUFLAGE_DOMAIN %q accepted", value)
		}
	}
	if err := validateCamouflageDomain("www.cloudflare.com"); err != nil {
		t.Fatalf("real-looking CAMOUFLAGE_DOMAIN rejected: %v", err)
	}
	err := validateCamouflageDomain("example.org")
	if err == nil || !strings.Contains(err.Error(), "refusing placeholder CAMOUFLAGE_DOMAIN") {
		t.Fatalf("unexpected placeholder error: %v", err)
	}
}
