package device

import (
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

func newTestDevice(t *testing.T) *Device {
	t.Helper()
	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], NewLogger(LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return dev
}

func ipcSet(dev *Device, lines ...string) error {
	return dev.IpcSet(strings.Join(lines, "\n") + "\n")
}

func TestIpcSetAppliesAWGParamsAtomically(t *testing.T) {
	dev := newTestDevice(t)
	if err := ipcSet(dev, "jc=4", "jmin=10", "jmax=50", "s1=20", "s2=40", "h1=100-200", "h2=300", "h3=400", "h4=500-600"); err != nil {
		t.Fatal(err)
	}
	before := dev.awgParams()
	for name, set := range map[string][]string{
		"jmax below jmin":     {"jmin=60", "jmax=50"},
		"overlapping headers": {"s1=99", "h2=150-160"},
		"padding too large":   {"jc=5", "s4=100000"},
		"junk count too big":  {"jc=100000"},
		"bad obf length":      {"s3=7", "i1=<r -5>"},
	} {
		if err := ipcSet(dev, set...); err == nil {
			t.Fatalf("%s accepted", name)
		}
		if dev.awgParams() != before {
			t.Fatalf("%s: a rejected set changed the device", name)
		}
	}
	after := dev.awgParams()
	if after.junk.count != 4 || after.junk.min != 10 || after.junk.max != 50 || after.paddings.init != 20 || after.headers.response.start != 300 {
		t.Fatalf("valid parameters lost: %+v", after)
	}
	get, err := dev.IpcGet()
	if err != nil || !strings.Contains(get, "jmax=50") || !strings.Contains(get, "h4=500-600") {
		t.Fatalf("get: %v\n%s", err, get)
	}
}

func TestIpcSetKeepsParamsOnUnrelatedSets(t *testing.T) {
	dev := newTestDevice(t)
	if err := ipcSet(dev, "jc=3", "jmin=8", "jmax=40"); err != nil {
		t.Fatal(err)
	}
	params := dev.awgParams()
	if err := ipcSet(dev, "listen_port=0"); err != nil {
		t.Fatal(err)
	}
	if dev.awgParams() != params {
		t.Fatal("a set without AWG keys replaced the parameters")
	}
}

func TestMagicHeaderFullRangeDoesNotPanic(t *testing.T) {
	h := &magicHeader{start: 0, end: ^uint32(0)}
	for i := 0; i < 100; i++ {
		_ = h.Generate()
	}
	single := &magicHeader{start: 7, end: 7}
	if single.Generate() != 7 {
		t.Fatal("single-value header")
	}
}

func TestObfLengthsAreBounded(t *testing.T) {
	for _, spec := range []string{"<r -1>", "<rc -3>", "<rd -2>", "<dz -1>", "<r 999999>"} {
		if _, err := newObfChain(spec); err == nil {
			t.Fatalf("%s accepted", spec)
		}
	}
	chain, err := newObfChain("<b 0xf6ab3267fa><r 16><rc 4><rd 3>")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, nil)
}

func TestHandshakeJunkWithEqualMinMax(t *testing.T) {
	dev := newTestDevice(t)
	if err := ipcSet(dev, "jc=2", "jmin=30", "jmax=30"); err != nil {
		t.Fatalf("jmin == jmax must be accepted: %v", err)
	}
}
