//go:build linux

package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// captureClientHello returns the first TLS record a real Go client sends for
// serverName (a modern ClientHello, including post-quantum key shares).
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = conn.Handshake() // fails once the pipe closes; we only need the hello
		client.Close()
	}()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := readFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := readFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(header, body...)
}

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestFindSNIInRealClientHello(t *testing.T) {
	hello := captureClientHello(t, "blocked.example.com")
	start, length, ok := findTLSServerName(hello)
	if !ok {
		t.Fatal("SNI not found in a real ClientHello")
	}
	if got := string(hello[start : start+length]); got != "blocked.example.com" {
		t.Fatalf("SNI = %q", got)
	}
}

func TestSplitPositionAutoLandsInsideTheServerName(t *testing.T) {
	hello := captureClientHello(t, "blocked.example.com")
	start, length, _ := findTLSServerName(hello)

	pos := splitPosition(hello, splitModeAuto, 2)
	if pos <= start || pos >= start+length {
		t.Fatalf("split at %d, want strictly inside the name [%d,%d)", pos, start, start+length)
	}
	if bytes.Contains(hello[:pos], []byte("blocked.example.com")) || bytes.Contains(hello[pos:], []byte("blocked.example.com")) {
		t.Fatal("neither segment may contain the full server name")
	}
	if got := splitPosition(hello, splitModeFixed, 2); got != 2 {
		t.Fatalf("fixed mode = %d, want 2", got)
	}
}

func TestSplitPositionFallsBackWhenNameIsNotInThisPacket(t *testing.T) {
	hello := captureClientHello(t, "blocked.example.com")
	start, _, _ := findTLSServerName(hello)
	// Only part of the record arrived in this segment (e.g. large key share
	// first): the name is cut off, so use the fixed position.
	if got := splitPosition(hello[:start+3], splitModeAuto, 2); got != 2 {
		t.Fatalf("truncated hello: split at %d, want fallback 2", got)
	}
	for cut := 0; cut < len(hello); cut += 7 {
		_, _, _ = findTLSServerName(hello[:cut]) // must never panic
	}
}

func TestSplitPositionHTTPHost(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nhOsT:   blocked.example.com\r\nAccept: */*\r\n\r\n")
	pos := splitPosition(req, splitModeAuto, 2)
	i := bytes.Index(req, []byte("blocked.example.com"))
	if pos <= i || pos >= i+len("blocked.example.com") {
		t.Fatalf("split at %d, want inside the Host value at [%d,%d)", pos, i, i+19)
	}
	if got := splitPosition([]byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"), splitModeAuto, 2); got != 2 {
		t.Fatalf("no Host header: split at %d, want fallback 2", got)
	}
}

func FuzzFindTLSServerName(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03})
	f.Fuzz(func(t *testing.T, data []byte) {
		start, length, ok := findTLSServerName(data)
		if ok && (start < 0 || length <= 0 || start+length > len(data)) {
			t.Fatalf("out of range: start=%d len=%d size=%d", start, length, len(data))
		}
		if pos := splitPosition(data, splitModeAuto, 2); pos < 1 {
			t.Fatalf("split position %d", pos)
		}
	})
}
