package transport

import (
	"fmt"
	"strings"
	"unsafe"

	netstacktun "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	tcpBufferMin     = 64 * 1024
	tcpBufferDefault = 4 * 1024 * 1024
	tcpBufferMax     = 16 * 1024 * 1024
)

type netstackTUNView struct {
	ep    *channel.Endpoint
	stack *stack.Stack
}

func tuneNetstack(tnet *netstacktun.Net) error {
	if tnet == nil {
		return nil
	}
	st := (*netstackTUNView)(unsafe.Pointer(tnet)).stack
	if st == nil {
		return fmt.Errorf("netstack stack is nil")
	}
	var errs []string
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpBufferMin,
		Default: tcpBufferDefault,
		Max:     tcpBufferMax,
	}
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		errs = append(errs, fmt.Sprintf("send_buffer=%s", err))
	}
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpBufferMin,
		Default: tcpBufferDefault,
		Max:     tcpBufferMax,
	}
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		errs = append(errs, fmt.Sprintf("receive_buffer=%s", err))
	}
	moderateReceive := tcpip.TCPModerateReceiveBufferOption(true)
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &moderateReceive); err != nil {
		errs = append(errs, fmt.Sprintf("moderate_receive=%s", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("tune netstack tcp: %s", strings.Join(errs, "; "))
	}
	return nil
}
