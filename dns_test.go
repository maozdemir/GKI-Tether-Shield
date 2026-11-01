//go:build linux

package main

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// dnsQuery returns a minimal A query for example.com with the given ID.
func dnsQuery(id uint16) []byte {
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return q
}

func answerFor(q []byte) []byte {
	resp := append([]byte(nil), q...)
	resp[2] |= 0x80 // QR: this is a response
	return resp
}

// startFakeUpstream runs a UDP DNS server; respond decides what to send back.
func startFakeUpstream(t *testing.T, respond func(q []byte) [][]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for _, r := range respond(append([]byte(nil), buf[:n]...)) {
				_, _ = pc.WriteTo(r, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func withPlainUpstream(t *testing.T, addr string) {
	t.Helper()
	orig := plainDNSUpstream
	plainDNSUpstream = addr
	t.Cleanup(func() { plainDNSUpstream = orig })
}

func withDoHEnabled(t *testing.T, enabled bool) {
	t.Helper()
	withConfig(t, func(c *Config) { c.DohEnabled = enabled })
}

func TestResolveDNSUsesPlainUpstreamWhenDoHDisabled(t *testing.T) {
	withDoHEnabled(t, false)
	withPlainUpstream(t, startFakeUpstream(t, func(q []byte) [][]byte { return [][]byte{answerFor(q)} }))

	resp, err := resolveDNS(dnsQuery(0xbeef))
	if err != nil {
		t.Fatalf("resolveDNS with DoH disabled: %v", err)
	}
	if binary.BigEndian.Uint16(resp[:2]) != 0xbeef || resp[2]&0x80 == 0 {
		t.Fatalf("unexpected response header % x", resp[:4])
	}
}

func TestPlainDNSIgnoresSpoofedResponses(t *testing.T) {
	withPlainUpstream(t, startFakeUpstream(t, func(q []byte) [][]byte {
		spoofed := answerFor(q)
		spoofed[0] ^= 0xff                     // wrong transaction ID
		notAnswer := append([]byte(nil), q...) // QR bit unset
		return [][]byte{spoofed, notAnswer, answerFor(q)}
	}))

	resp, err := resolvePlainUDP(dnsQuery(0x1234))
	if err != nil {
		t.Fatalf("resolvePlainUDP: %v", err)
	}
	if binary.BigEndian.Uint16(resp[:2]) != 0x1234 || resp[2]&0x80 == 0 {
		t.Fatalf("accepted a spoofed response: % x", resp[:4])
	}
}

func TestTCPDNSClosesIdleConnections(t *testing.T) {
	orig := dnsTCPTimeout
	dnsTCPTimeout = 100 * time.Millisecond
	t.Cleanup(func() { dnsTCPTimeout = orig })

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { serveDNSTCPConn(server); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle TCP DNS connection was not closed")
	}
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF after server closed, got %v", err)
	}
}

func TestTryAcquireDNSWorkerIsBounded(t *testing.T) {
	sem := make(chan struct{}, 2)
	for i := range 2 {
		if !tryAcquire(sem) {
			t.Fatalf("expected slot %d to be free", i+1)
		}
	}
	if tryAcquire(sem) {
		t.Fatal("third acquire must fail when the pool is full")
	}
	<-sem
	if !tryAcquire(sem) {
		t.Fatal("slot must be reusable after release")
	}
}

// TestDNSProxyAnswersOverIPv4AndIPv6 runs the real listeners and resolves a
// query over UDP and TCP on both 127.0.0.1 and ::1 (plain upstream mode).
func TestDNSProxyAnswersOverIPv4AndIPv6(t *testing.T) {
	withDoHEnabled(t, false)
	withPlainUpstream(t, startFakeUpstream(t, func(q []byte) [][]byte { return [][]byte{answerFor(q)} }))

	pc, l, err := listenDNS(0)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	defer l.Close()
	go serveDNSUDP(pc)
	go serveDNSTCP(l)
	port := pc.LocalAddr().(*net.UDPAddr).Port

	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(host, strconv.Itoa(port))

		udp, err := net.DialTimeout("udp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial udp %s: %v", addr, err)
		}
		_ = udp.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = udp.Write(dnsQuery(0x0a0b))
		buf := make([]byte, 512)
		n, err := udp.Read(buf)
		udp.Close()
		if err != nil || n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x0a0b {
			t.Fatalf("UDP over %s: n=%d err=%v", host, n, err)
		}

		tcp, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial tcp %s: %v", addr, err)
		}
		_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
		q := dnsQuery(0x0c0d)
		_, _ = tcp.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
		var lenBuf [2]byte
		if _, err := io.ReadFull(tcp, lenBuf[:]); err != nil {
			t.Fatalf("TCP over %s: %v", host, err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		_, err = io.ReadFull(tcp, resp)
		tcp.Close()
		if err != nil || binary.BigEndian.Uint16(resp[:2]) != 0x0c0d {
			t.Fatalf("TCP over %s: bad response %v", host, err)
		}
	}
}
