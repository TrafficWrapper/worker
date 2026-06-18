package dialect

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

const (
	DefaultMTU = 1420

	// MinTunnelMTU is intentionally below IPv6's 1280-byte link MTU. This is
	// the inner IPv4 netstack MTU; the outer UDP packet must also carry IP/UDP,
	// WireGuard transport overhead, and AWG S4 padding on narrow mobile paths.
	MinTunnelMTU = 1000

	// MobileSafeOuterMTU is the conservative outer path target for LTE,
	// PPPoE, and nested VPN networks where PMTUD/ICMP frag-needed is unreliable.
	MobileSafeOuterMTU    = 1280
	MaxOuterIPUDPOverhead = 48 // IPv6 header + UDP header.
	WireGuardDataOverhead = 32 // transport data header + authentication tag.
	InnerIPv4TCPOverhead  = 40 // IPv4 + TCP without options, used for MSS.
	minHeader             = uint32(5)
	maxHeader             = uint32(1<<31 - 1)
	minHeaderSpan         = uint32(8 * 1024 * 1024)
	maxHeaderSpan         = uint32(32 * 1024 * 1024)
)

type Dialect struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
}

type HeaderRange struct {
	Start uint32
	End   uint32
}

func Generate() (Dialect, error) {
	return GenerateWithReader(rand.Reader)
}

func GenerateWithReader(r io.Reader) (Dialect, error) {
	jc, err := randInt(r, 4, 12)
	if err != nil {
		return Dialect{}, err
	}
	jmax, err := randInt(r, 40, 80)
	if err != nil {
		return Dialect{}, err
	}
	s1, err := randInt(r, 15, 150)
	if err != nil {
		return Dialect{}, err
	}
	var s2 int
	for {
		s2, err = randInt(r, 15, 150)
		if err != nil {
			return Dialect{}, err
		}
		if s1+56 != s2 {
			break
		}
	}
	s3, err := randInt(r, 0, 64)
	if err != nil {
		return Dialect{}, err
	}
	s4, err := randInt(r, 0, 32)
	if err != nil {
		return Dialect{}, err
	}
	headers, err := generateHeaders(r)
	if err != nil {
		return Dialect{}, err
	}
	d := Dialect{
		Jc: jc, Jmin: 8, Jmax: jmax,
		S1: s1, S2: s2, S3: s3, S4: s4,
		H1: headers[0].String(),
		H2: headers[1].String(),
		H3: headers[2].String(),
		H4: headers[3].String(),
	}
	if err := Validate(d, DefaultMTU); err != nil {
		return Dialect{}, err
	}
	return d, nil
}

func Compat() Dialect {
	return Dialect{
		Jc: 0, Jmin: 0, Jmax: 0,
		S1: 0, S2: 0, S3: 0, S4: 0,
		H1: "1", H2: "2", H3: "3", H4: "4",
	}
}

func Validate(d Dialect, mtu int) error {
	if IsCompat(d) {
		return nil
	}
	return ValidateProduction(d, mtu)
}

func EffectiveMTU(baseMTU int, d Dialect) (int, error) {
	if baseMTU == 0 {
		baseMTU = DefaultMTU
	}
	if baseMTU < MinTunnelMTU {
		return 0, fmt.Errorf("base mtu must be >= %d, got %d", MinTunnelMTU, baseMTU)
	}
	padding := transportPadding(d)
	mtu := baseMTU - padding
	fragmentSafe := MobileSafeOuterMTU - MaxOuterIPUDPOverhead - WireGuardDataOverhead - padding
	if fragmentSafe < mtu {
		mtu = fragmentSafe
	}
	if mtu < MinTunnelMTU {
		return 0, fmt.Errorf("effective mtu must be >= %d, got %d", MinTunnelMTU, mtu)
	}
	return mtu, nil
}

func TCPMSSForMTU(mtu int) int {
	if mtu <= InnerIPv4TCPOverhead {
		return 0
	}
	return mtu - InnerIPv4TCPOverhead
}

func transportPadding(d Dialect) int {
	if IsCompat(d) {
		return 0
	}
	return d.S4
}

func ValidateProduction(d Dialect, mtu int) error {
	if mtu <= 0 {
		return errors.New("mtu must be positive")
	}
	if d.Jc < 4 || d.Jc > 12 {
		return fmt.Errorf("jc must be in [4,12], got %d", d.Jc)
	}
	if d.Jmin != 8 {
		return fmt.Errorf("jmin must be 8, got %d", d.Jmin)
	}
	if d.Jmax < 40 || d.Jmax > 80 || d.Jmax >= mtu {
		return fmt.Errorf("jmax must be in [40,80] and < mtu(%d), got %d", mtu, d.Jmax)
	}
	if d.Jmin >= d.Jmax {
		return fmt.Errorf("jmin must be < jmax, got jmin=%d jmax=%d", d.Jmin, d.Jmax)
	}
	if d.S1 < 15 || d.S1 > 150 || d.S2 < 15 || d.S2 > 150 {
		return fmt.Errorf("s1 and s2 must be in [15,150], got s1=%d s2=%d", d.S1, d.S2)
	}
	if d.S1+56 == d.S2 {
		return fmt.Errorf("invalid padding invariant: s1+56 == s2 (%d)", d.S2)
	}
	if d.S3 < 0 || d.S3 > 64 || d.S4 < 0 || d.S4 > 32 {
		return fmt.Errorf("s3 must be in [0,64] and s4 in [0,32], got s3=%d s4=%d", d.S3, d.S4)
	}
	headers, err := HeaderRanges(d)
	if err != nil {
		return err
	}
	for i, h := range headers {
		if h.Start < minHeader || h.End > maxHeader {
			return fmt.Errorf("h%d must be within [5, 2^31-1], got %s", i+1, h)
		}
		if h.Start >= h.End {
			return fmt.Errorf("h%d must be a range with start<end, got %s", i+1, h)
		}
		for j := i + 1; j < len(headers); j++ {
			if h.Overlaps(headers[j]) {
				return fmt.Errorf("h%d overlaps h%d: %s vs %s", i+1, j+1, h, headers[j])
			}
		}
	}
	return nil
}

func IsCompat(d Dialect) bool {
	return d.Jc == 0 &&
		d.Jmin == 0 &&
		d.Jmax == 0 &&
		d.S1 == 0 &&
		d.S2 == 0 &&
		d.S3 == 0 &&
		d.S4 == 0 &&
		d.H1 == "1" &&
		d.H2 == "2" &&
		d.H3 == "3" &&
		d.H4 == "4"
}

func HeaderRanges(d Dialect) ([4]HeaderRange, error) {
	specs := []string{d.H1, d.H2, d.H3, d.H4}
	var out [4]HeaderRange
	for i, spec := range specs {
		parsed, err := ParseHeaderRange(spec)
		if err != nil {
			return out, fmt.Errorf("h%d invalid: %w", i+1, err)
		}
		out[i] = parsed
	}
	return out, nil
}

func ParseHeaderRange(spec string) (HeaderRange, error) {
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return HeaderRange{}, errors.New("bad header range format")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return HeaderRange{}, err
	}
	end := start
	if len(parts) == 2 {
		if parts[1] == "" {
			return HeaderRange{}, errors.New("empty range end")
		}
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return HeaderRange{}, err
		}
	}
	if end < start {
		return HeaderRange{}, errors.New("range end is smaller than start")
	}
	return HeaderRange{Start: uint32(start), End: uint32(end)}, nil
}

func (h HeaderRange) Overlaps(other HeaderRange) bool {
	return h.Start <= other.End && other.Start <= h.End
}

func (h HeaderRange) String() string {
	if h.Start == h.End {
		return strconv.FormatUint(uint64(h.Start), 10)
	}
	return fmt.Sprintf("%d-%d", h.Start, h.End)
}

func UAPILines(d Dialect) []string {
	lines := make([]string, 0, 11)
	if !IsCompat(d) {
		lines = append(lines,
			"jc="+strconv.Itoa(d.Jc),
			"jmin="+strconv.Itoa(d.Jmin),
			"jmax="+strconv.Itoa(d.Jmax),
		)
	}
	lines = append(lines,
		"s1="+strconv.Itoa(d.S1),
		"s2="+strconv.Itoa(d.S2),
		"s3="+strconv.Itoa(d.S3),
		"s4="+strconv.Itoa(d.S4),
		"h1="+d.H1,
		"h2="+d.H2,
		"h3="+d.H3,
		"h4="+d.H4,
	)
	return lines
}

func Summary(d Dialect) string {
	return fmt.Sprintf(
		"jc=%d jmin=%d jmax=%d s1=%d s2=%d s3=%d s4=%d h1=%s h2=%s h3=%s h4=%s",
		d.Jc, d.Jmin, d.Jmax, d.S1, d.S2, d.S3, d.S4, d.H1, d.H2, d.H3, d.H4,
	)
}

func generateHeaders(r io.Reader) ([4]HeaderRange, error) {
	buckets := [][2]uint32{
		{100_000_000, 450_000_000},
		{600_000_000, 950_000_000},
		{1_100_000_000, 1_450_000_000},
		{1_600_000_000, 2_050_000_000},
	}
	var out [4]HeaderRange
	for i, bucket := range buckets {
		width, err := randUint32(r, minHeaderSpan, maxHeaderSpan)
		if err != nil {
			return out, err
		}
		maxStart := bucket[1] - width
		start, err := randUint32(r, bucket[0], maxStart)
		if err != nil {
			return out, err
		}
		out[i] = HeaderRange{Start: start, End: start + width}
	}
	return out, nil
}

func randInt(r io.Reader, min, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("invalid int range [%d,%d]", min, max)
	}
	n, err := randBig(r, int64(max-min+1))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func randUint32(r io.Reader, min, max uint32) (uint32, error) {
	if min > max {
		return 0, fmt.Errorf("invalid uint32 range [%d,%d]", min, max)
	}
	n, err := randBig(r, int64(max-min+1))
	if err != nil {
		return 0, err
	}
	return min + uint32(n.Int64()), nil
}

func randBig(r io.Reader, high int64) (*big.Int, error) {
	if high <= 0 {
		return nil, fmt.Errorf("invalid random upper bound %d", high)
	}
	return rand.Int(r, big.NewInt(high))
}
