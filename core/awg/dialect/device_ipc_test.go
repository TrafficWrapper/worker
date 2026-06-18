package dialect

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun"

	"github.com/TrafficWrapper/worker/core/awg/device"
)

type fakeTUN struct {
	events chan tun.Event
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{events: make(chan tun.Event)}
}

func (t *fakeTUN) File() *os.File { return nil }

func (t *fakeTUN) Read(_ [][]byte, _ []int, _ int) (int, error) {
	return 0, io.ErrClosedPipe
}

func (t *fakeTUN) Write(bufs [][]byte, _ int) (int, error) {
	return len(bufs), nil
}

func (t *fakeTUN) MTU() (int, error) { return DefaultMTU, nil }

func (t *fakeTUN) Name() (string, error) { return "fake0", nil }

func (t *fakeTUN) Events() <-chan tun.Event { return t.events }

func (t *fakeTUN) Close() error {
	select {
	case <-t.events:
	default:
		close(t.events)
	}
	return nil
}

func (t *fakeTUN) BatchSize() int { return 1 }

func TestGeneratedDialectsApplyThroughDeviceIpcSet(t *testing.T) {
	for i := 0; i < 500; i++ {
		d, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(d, DefaultMTU); err != nil {
			t.Fatalf("generated invalid dialect: %v", err)
		}
		tunDevice := newFakeTUN()
		dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "test: "))
		uapi := strings.Join(UAPILines(d), "\n") + "\n"
		if err := dev.IpcSetOperation(strings.NewReader(uapi)); err != nil {
			dev.Close()
			t.Fatalf("IpcSet rejected generated dialect %s: %v", Summary(d), err)
		}
		dev.Close()
	}
}
