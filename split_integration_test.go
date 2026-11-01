//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestRawSocketsInjectSplitSegments sends split segments through the real
// raw sockets over loopback and checks a raw TCP listener receives both,
// byte-exact. It proves the kernel accepts the hand-built IPv4/IPv6 headers
// (e.g. the sockaddr rules for IPPROTO_RAW over IPv6). Needs root.
func TestRawSocketsInjectSplitSegments(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for raw sockets")
	}
	raw := openRawSockets()
	defer raw.close()
	hello := captureClientHello(t, "blocked.example.com")

	t.Run("ipv4", func(t *testing.T) {
		pkt := buildIPv4TCP(5, 443, hello)
		copy(pkt[12:16], []byte{127, 0, 0, 1})
		copy(pkt[16:20], []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(pkt[20:22], 50000) // source port
		seg1, seg2, ok := buildSplitIPv4TCP(pkt, splitPosition(hello, splitModeAuto, 2), 64)
		if !ok {
			t.Fatal("build failed")
		}
		got := injectAndReceive(t, syscall.AF_INET, func(p []byte) error { return raw.send4(p, [4]byte{127, 0, 0, 1}) }, seg1, seg2)
		for i, want := range [][]byte{seg1[20:], seg2[20:]} {
			if !bytes.Equal(got[i], want) {
				t.Fatalf("segment %d differs after injection", i)
			}
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		pkt := buildIPv6TCP(443, hello, 63)
		loopback := [16]byte{15: 1}
		copy(pkt[8:24], loopback[:])
		copy(pkt[24:40], loopback[:])
		seg1, seg2, ok := buildSplitIPv6TCP(pkt, splitPosition(hello, splitModeAuto, 2), 64)
		if !ok {
			t.Fatal("build failed")
		}
		got := injectAndReceive(t, syscall.AF_INET6, func(p []byte) error { return raw.send6(p, loopback) }, seg1, seg2)
		for i, want := range [][]byte{seg1[ipv6HeaderLen:], seg2[ipv6HeaderLen:]} {
			if !bytes.Equal(got[i], want) {
				t.Fatalf("segment %d differs after injection", i)
			}
		}
	})
}

// injectAndReceive sends the segments and returns the TCP segments a raw
// IPPROTO_TCP socket of the same family sees for destination port 443.
func injectAndReceive(t *testing.T, family int, send func([]byte) error, segs ...[]byte) [][]byte {
	t.Helper()
	rx, err := syscall.Socket(family, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("receive socket: %v", err)
	}
	defer syscall.Close(rx)
	tv := syscall.NsecToTimeval(int64(2 * time.Second))
	_ = syscall.SetsockoptTimeval(rx, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	for i, seg := range segs {
		if err := send(seg); err != nil {
			t.Fatalf("send segment %d: %v", i, err)
		}
	}

	var got [][]byte
	buf := make([]byte, 65536)
	for len(got) < len(segs) {
		n, _, err := syscall.Recvfrom(rx, buf, 0)
		if err != nil {
			t.Fatalf("received %d of %d segments: %v", len(got), len(segs), err)
		}
		tcp := buf[:n]
		if family == syscall.AF_INET { // IPv4 raw sockets include the IP header
			tcp = tcp[int(tcp[0]&0x0F)*4:]
		}
		if len(tcp) >= 20 && binary.BigEndian.Uint16(tcp[2:4]) == 443 && binary.BigEndian.Uint16(tcp[0:2]) == 50000 {
			got = append(got, append([]byte(nil), tcp...))
		}
	}
	return got
}
