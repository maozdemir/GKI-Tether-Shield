//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

// buildIPv4TCP returns an IPv4/TCP packet with a 20-byte IP header, the given
// TCP data offset (in 32-bit words), destination port and TCP payload.
func buildIPv4TCP(dataOffsetWords int, dstPort uint16, tcpPayload []byte) []byte {
	tcpHdrLen := dataOffsetWords * 4
	if tcpHdrLen < 20 {
		tcpHdrLen = 20 // always allocate a minimal header so fields can be written
	}
	pkt := make([]byte, 20+tcpHdrLen+len(tcpPayload))
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 63 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], []byte{192, 168, 43, 2})
	copy(pkt[16:20], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = byte(dataOffsetWords << 4)
	copy(pkt[20+tcpHdrLen:], tcpPayload)
	return pkt
}

var clientHello = []byte{0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x03, 0x03}

func TestIsWebSplitCandidate(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"tls client hello to 443", buildIPv4TCP(5, 443, clientHello), true},
		{"http GET to 80", buildIPv4TCP(5, 80, []byte("GET / HTTP/1.1\r\n")), true},
		{"client hello to non-web port", buildIPv4TCP(5, 6881, clientHello), false},
		{"random payload to 443", buildIPv4TCP(5, 443, []byte{1, 2, 3, 4, 5, 6, 7, 8}), false},
		{"empty payload to 443", buildIPv4TCP(5, 443, nil), false},
		{"data offset larger than packet", buildIPv4TCP(15, 443, nil)[:41], false},
		{"data offset below minimum", buildIPv4TCP(2, 443, clientHello), false},
		{"udp packet", func() []byte { p := buildIPv4TCP(5, 443, clientHello); p[9] = 17; return p }(), false},
		{"non-first fragment", func() []byte {
			p := buildIPv4TCP(5, 443, clientHello)
			binary.BigEndian.PutUint16(p[6:8], 0x0010) // fragment offset 16
			return p
		}(), false},
		{"first fragment with more-fragments set", func() []byte {
			p := buildIPv4TCP(5, 443, clientHello)
			binary.BigEndian.PutUint16(p[6:8], 0x2000) // MF
			return p
		}(), false},
		{"truncated ip header", []byte{0x45, 0, 0, 10}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWebSplitCandidate(tt.pkt); got != tt.want {
				t.Fatalf("isWebSplitCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSplitRejectsMalformedHeaders(t *testing.T) {
	// A TCP data offset below 20 bytes must not cause out-of-range writes.
	pkt := buildIPv4TCP(0, 443, clientHello)
	if _, _, ok := buildSplitIPv4TCP(pkt, 2, 64); ok {
		t.Fatal("expected malformed packet to be rejected")
	}
}

func FuzzIsWebSplitCandidate(f *testing.F) {
	f.Add(buildIPv4TCP(5, 443, clientHello))
	f.Add(buildIPv4TCP(15, 443, nil)[:41])
	f.Add([]byte{0x4f, 0, 0, 0})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		if isWebSplitCandidate(pkt) {
			// Anything accepted must be safe to split and process.
			_, _, _ = buildSplitIPv4TCP(pkt, 2, 64)
			_, _ = processPacket(append([]byte(nil), pkt...), &captureSender{}, &defaultConfig)
		}
	})
}
