package serverpeer

import (
	"reflect"
	"testing"
)

func TestPeerUAPILinesUsesFixedServerPeerOrder(t *testing.T) {
	got := PeerUAPILines("public", "psk", "10.13.13.10/32", 0)
	want := []string{
		"public_key=public",
		"preshared_key=psk",
		"persistent_keepalive_interval=0",
		"replace_allowed_ips=true",
		"allowed_ip=10.13.13.10/32",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PeerUAPILines()=%q want %q", got, want)
	}
}
