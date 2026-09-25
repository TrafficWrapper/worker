package device

import (
	"errors"
	"fmt"
)

// awgParams holds the AmneziaWG obfuscation parameters. It is never changed
// after it is published: a UAPI set builds a new copy, validates it as a
// whole and swaps the pointer, so packet paths always read one consistent
// set and a rejected set leaves the device untouched.
type awgParams struct {
	junk struct {
		min   int
		max   int
		count int
	}

	headers struct {
		init      *magicHeader
		cookie    *magicHeader
		response  *magicHeader
		transport *magicHeader
	}

	paddings struct {
		init      int
		response  int
		cookie    int
		transport int
	}

	ipackets [5]*obfChain
}

// Bounds that keep every accepted value from panicking or allocating without
// limit in the packet paths. Real dialects stay far below them.
const (
	maxJunkCount  = 128
	maxJunkSize   = MaxSegmentSize
	maxPaddingLen = 1024
)

func defaultAWGParams() *awgParams {
	p := &awgParams{}
	p.headers.init = &magicHeader{start: MessageInitiationType, end: MessageInitiationType}
	p.headers.response = &magicHeader{start: MessageResponseType, end: MessageResponseType}
	p.headers.cookie = &magicHeader{start: MessageCookieReplyType, end: MessageCookieReplyType}
	p.headers.transport = &magicHeader{start: MessageTransportType, end: MessageTransportType}
	return p
}

// awgParams returns the current parameter set; callers must not modify it.
func (device *Device) awgParams() *awgParams {
	return device.awg.Load()
}

func (p *awgParams) validate() error {
	if p.junk.count < 0 || p.junk.count > maxJunkCount {
		return fmt.Errorf("jc must be in [0,%d]", maxJunkCount)
	}
	if p.junk.count > 0 {
		if p.junk.min <= 0 || p.junk.max <= 0 {
			return errors.New("jmin and jmax must be positive when jc is set")
		}
		if p.junk.min > p.junk.max {
			return fmt.Errorf("jmin (%d) must not exceed jmax (%d)", p.junk.min, p.junk.max)
		}
		if p.junk.max > maxJunkSize {
			return fmt.Errorf("jmax must not exceed %d", maxJunkSize)
		}
	}
	for _, padding := range []int{p.paddings.init, p.paddings.response, p.paddings.cookie, p.paddings.transport} {
		if padding < 0 || padding > maxPaddingLen {
			return fmt.Errorf("s1..s4 must be in [0,%d]", maxPaddingLen)
		}
	}
	headers := []*magicHeader{p.headers.init, p.headers.response, p.headers.cookie, p.headers.transport}
	for i, left := range headers {
		if left == nil {
			return errors.New("missing magic header")
		}
		for _, right := range headers[i+1:] {
			if right != nil && left.start <= right.end && right.start <= left.end {
				return errors.New("headers must not overlap")
			}
		}
	}
	return nil
}
