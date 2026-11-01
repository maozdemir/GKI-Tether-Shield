//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingLogCapsSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	l := &rotatingLog{path: path, maxBytes: 100}
	defer l.Close()

	line := strings.Repeat("x", 39) + "\n" // 40 bytes
	for range 10 {
		if _, err := l.Write([]byte(line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	cur, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Size() > 100 {
		t.Fatalf("current log is %d bytes, cap is 100", cur.Size())
	}
	old, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("expected a rotated %s.1: %v", path, err)
	}
	if old.Size() > 100 {
		t.Fatalf("rotated log is %d bytes, cap is 100", old.Size())
	}
}

func TestRotatingLogAppendsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	first := &rotatingLog{path: path, maxBytes: 1000}
	_, _ = first.Write([]byte("one\n"))
	first.Close()

	second := &rotatingLog{path: path, maxBytes: 1000}
	_, _ = second.Write([]byte("two\n"))
	second.Close()

	if data, _ := os.ReadFile(path); string(data) != "one\ntwo\n" {
		t.Fatalf("log content = %q", data)
	}
}

func TestLogLimiter(t *testing.T) {
	l := &logLimiter{max: 2, window: time.Minute}
	start := time.Unix(1000, 0)

	if ok, _ := l.allow(start); !ok {
		t.Fatal("first message must pass")
	}
	if ok, _ := l.allow(start.Add(time.Second)); !ok {
		t.Fatal("second message must pass")
	}
	for range 5 {
		if ok, _ := l.allow(start.Add(2 * time.Second)); ok {
			t.Fatal("messages over the limit must be suppressed")
		}
	}
	ok, suppressed := l.allow(start.Add(2 * time.Minute))
	if !ok || suppressed != 5 {
		t.Fatalf("new window: ok=%v suppressed=%d, want true, 5", ok, suppressed)
	}
}
