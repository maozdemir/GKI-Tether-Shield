//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// tcActUnspec is TC_ACT_UNSPEC (-1) as the program's return value.
const tcActUnspec = 0xffffffff

// loadTestPrograms loads the program or skips when this process may not
// load BPF (not root / no CAP_BPF).
func loadTestPrograms(t *testing.T, target uint8) *ttlProgSet {
	t.Helper()
	p, err := loadTTLPrograms(target)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF not available here (run as root): %v", err)
		}
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// testIPv4 builds an IPv4/UDP packet with a valid header checksum. ihl is
// the header length in 32-bit words (5 = no options).
func testIPv4(ttl uint8, ihl int, src [4]byte) []byte {
	hlen := ihl * 4
	p := make([]byte, hlen+8+4)
	p[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = ttl
	p[9] = 17 // UDP
	copy(p[12:16], src[:])
	copy(p[16:20], []byte{198, 51, 100, 7})
	for i := 20; i < hlen; i++ {
		p[i] = 1 // NOP options
	}
	binary.BigEndian.PutUint16(p[10:], ipv4Checksum(p[:hlen]))
	return p
}

func testIPv6(hlim uint8, src [16]byte) []byte {
	p := make([]byte, 40+8)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], 8)
	p[6] = 17
	p[7] = hlim
	copy(p[8:24], src[:])
	p[39] = 1
	return p
}

func ethFrame(ethertype uint16, payload []byte) []byte {
	f := make([]byte, ethHeaderLen, ethHeaderLen+len(payload))
	copy(f[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(f[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(f[12:], ethertype)
	return append(f, payload...)
}

// run executes prog on data and returns the (possibly rewritten) packet.
func run(t *testing.T, prog *ebpf.Program, data []byte) []byte {
	t.Helper()
	out := make([]byte, len(data)+256)
	opts := &ebpf.RunOptions{Data: data, DataOut: out}
	ret, err := prog.Run(opts)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if ret != tcActUnspec {
		t.Fatalf("returned %#x, want TC_ACT_UNSPEC so other filters still run", ret)
	}
	return opts.DataOut
}

func checkIPv4(t *testing.T, ip []byte, wantTTL uint8) {
	t.Helper()
	if ip[8] != wantTTL {
		t.Fatalf("TTL = %d, want %d", ip[8], wantTTL)
	}
	hlen := int(ip[0]&0x0f) * 4
	if c := ipv4Checksum(ip[:hlen]); c != 0 {
		t.Fatalf("IPv4 header checksum invalid (residual %#04x)", c)
	}
}

var testSrc4 = [4]byte{192, 0, 2, 10}

func TestEBPFRewritesIPv4OnEthernet(t *testing.T) {
	p := loadTestPrograms(t, 64)
	for _, tc := range []struct {
		name string
		ttl  uint8
		ihl  int
	}{
		{"forwarded from Linux/macOS", 63, 5},
		{"forwarded from Windows", 127, 5},
		{"with IP options", 63, 6},
		{"TTL 255", 255, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := run(t, p.eth, ethFrame(0x0800, testIPv4(tc.ttl, tc.ihl, testSrc4)))
			checkIPv4(t, out[ethHeaderLen:], 64)
		})
	}
}

func TestEBPFLeavesCorrectTTLAlone(t *testing.T) {
	p := loadTestPrograms(t, 64)
	in := ethFrame(0x0800, testIPv4(64, 5, testSrc4))
	before, _ := p.counters()
	out := run(t, p.eth, in)
	if !bytes.Equal(out, in) {
		t.Fatal("a packet already at the target TTL was modified")
	}
	after, _ := p.counters()
	if after.IPv4Rewritten != before.IPv4Rewritten || after.IPv4Seen != before.IPv4Seen+1 {
		t.Fatalf("counters %+v -> %+v, want one more seen and no rewrite", before, after)
	}
}

func TestEBPFRewritesIPv6HopLimit(t *testing.T) {
	p := loadTestPrograms(t, 64)
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	before, _ := p.counters()
	out := run(t, p.eth, ethFrame(0x86dd, testIPv6(63, src)))
	if hl := out[ethHeaderLen+7]; hl != 64 {
		t.Fatalf("hop limit = %d, want 64", hl)
	}
	after, _ := p.counters()
	if after.IPv6Rewritten != before.IPv6Rewritten+1 {
		t.Fatalf("IPv6 rewrite not counted: %+v -> %+v", before, after)
	}
}

func TestEBPFTargetChangesLive(t *testing.T) {
	p := loadTestPrograms(t, 64)
	if err := p.setTarget(100); err != nil {
		t.Fatal(err)
	}
	out := run(t, p.eth, ethFrame(0x0800, testIPv4(63, 5, testSrc4)))
	checkIPv4(t, out[ethHeaderLen:], 100)
}

func TestEBPFIgnoresOtherAndBrokenPackets(t *testing.T) {
	p := loadTestPrograms(t, 64)
	ipv4 := testIPv4(63, 5, testSrc4)
	for name, frame := range map[string][]byte{
		"ARP":                  ethFrame(0x0806, make([]byte, 28)),
		"truncated IPv4":       ethFrame(0x0800, ipv4[:6]),
		"IPv4 type, not v4":    ethFrame(0x0800, append([]byte{0x60}, ipv4[1:]...)),
		"IPv6 type, not v6":    ethFrame(0x86dd, ipv4),
		"Ethernet header only": ethFrame(0x0800, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if out := run(t, p.eth, frame); !bytes.Equal(out, frame) {
				t.Fatal("packet was modified")
			}
		})
	}
}

// On raw-IP links (cellular) the IP header starts at offset 0. The kernel's
// test runner always parses an Ethernet header to set skb->protocol, so the
// source address is chosen to make bytes 12-13 read as the right EtherType.
func TestEBPFRewritesRawIPPackets(t *testing.T) {
	p := loadTestPrograms(t, 64)

	ipv4 := testIPv4(63, 5, [4]byte{0x08, 0x00, 0, 1}) // src 8.0.0.1 -> 0x0800
	checkIPv4(t, run(t, p.raw, ipv4), 64)

	src6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x86, 0xdd} // bytes 12-13 -> 0x86dd
	if hl := run(t, p.raw, testIPv6(63, src6))[7]; hl != 64 {
		t.Fatalf("raw IPv6 hop limit = %d, want 64", hl)
	}
}

func TestDownstreamIfacePatternsMatchServiceScript(t *testing.T) {
	data, err := os.ReadFile("service.sh")
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for _, line := range bytes.Split(data, []byte("\n")) {
		if v, ok := bytes.CutPrefix(line, []byte("DOWNSTREAM_IFACES=")); ok {
			want = string(bytes.Trim(v, `"`))
		}
	}
	if got := joinWords(downstreamIfacePatterns); got != want {
		t.Fatalf("downstreamIfacePatterns = %q, service.sh DOWNSTREAM_IFACES = %q", got, want)
	}
}

func joinWords(w []string) string {
	var b bytes.Buffer
	for i, s := range w {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s)
	}
	return b.String()
}

func TestIsDownstreamIface(t *testing.T) {
	for name, want := range map[string]bool{
		"lo": true, "wlan0": true, "swlan0": true, "ap0": true, "rndis0": true, "ncm0": true,
		"bt-pan": true, "eth0": true, "rmnet_data0": false, "ccmni1": false, "v4-rmnet_data0": false,
		"tun0": false, "seth_lte0": false, "lox": false,
	} {
		if got := isDownstreamIface(name); got != want {
			t.Errorf("isDownstreamIface(%q) = %v, want %v", name, got, want)
		}
	}
}
