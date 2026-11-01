//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTTLEngineSetting(t *testing.T) {
	if defaultConfig.TtlEngine != ttlEngineNFQueue {
		t.Fatalf("TTL_ENGINE defaults to %q, want nfqueue until proven on devices", defaultConfig.TtlEngine)
	}
	for in, want := range map[string]string{"ebpf": "ebpf", " eBPF ": "ebpf", "NFQUEUE": "nfqueue", "auto": "nfqueue", "": "nfqueue"} {
		if got := parseConfig(defaultConfig, strings.NewReader("TTL_ENGINE="+in+"\n")).TtlEngine; got != want {
			t.Errorf("TTL_ENGINE=%q -> %q, want %q", in, got, want)
		}
	}
	next, err := applyConfigUpdate(defaultConfig, map[string]any{"TTL_ENGINE": "ebpf"})
	if err != nil || next.TtlEngine != ttlEngineEBPF {
		t.Fatalf("API update: %+v, %v", next, err)
	}
	if _, err := applyConfigUpdate(defaultConfig, map[string]any{"TTL_ENGINE": "kernel"}); err == nil {
		t.Fatal("unknown TTL_ENGINE must be rejected")
	}
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := saveConfigToFile(path, next); err != nil {
		t.Fatal(err)
	}
	if got := loadConfigFile(path, defaultConfig); got.TtlEngine != ttlEngineEBPF {
		t.Fatal("TTL_ENGINE must round-trip through config.conf")
	}
}

func TestTTLEngineManagerIsInertUntilStarted(t *testing.T) {
	m := &ttlEngineState{active: ttlEngineNFQueue}
	m.apply(Config{TtlEngine: ttlEngineEBPF, TargetTTL: 64})
	if engine, _, _ := m.stats(); engine != ttlEngineNFQueue || m.progs != nil {
		t.Fatal("manager acted before start (tests and the CLI must never load BPF)")
	}
}

func useTempEngineStatus(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ttl_engine")
	orig, origHandover := ttlEngineStatusPath, ttlEngineHandover
	ttlEngineStatusPath = func() string { return path }
	ttlEngineHandover = 200 * time.Millisecond
	t.Cleanup(func() { ttlEngineStatusPath, ttlEngineHandover = orig, origHandover })
	return path
}

func readStatus(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("status file: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestTTLEngineSwitchesAndHandsOver(t *testing.T) {
	inNewNetns(t)
	tx, _ := addVeth(t)
	loadTestPrograms(t, 64) // skips when BPF is unavailable
	status := useTempEngineStatus(t)

	m := &ttlEngineState{active: ttlEngineNFQueue}
	t.Cleanup(m.shutdown)
	m.start(Config{TtlEngine: ttlEngineEBPF, TargetTTL: 64})
	if got := readStatus(t, status); got != ttlEngineEBPF {
		t.Fatalf("status = %q, want ebpf", got)
	}
	if !hasTTLFilter(testNetns(t), tx, nil) {
		t.Fatal("eBPF engine active but not attached")
	}

	// Switching to NFQUEUE reports it at once but keeps the program attached
	// until service.sh has restored the queue rules.
	m.apply(Config{TtlEngine: ttlEngineNFQueue, TargetTTL: 64})
	if got := readStatus(t, status); got != ttlEngineNFQueue {
		t.Fatalf("status = %q, want nfqueue", got)
	}
	if !hasTTLFilter(testNetns(t), tx, nil) {
		t.Fatal("detached before the NFQUEUE rules could be restored")
	}
	deadline := time.Now().Add(3 * time.Second)
	for hasTTLFilter(testNetns(t), tx, nil) {
		if time.Now().After(deadline) {
			t.Fatal("still attached after the handover")
		}
		time.Sleep(50 * time.Millisecond)
	}

	m.shutdown()
	if _, err := os.Stat(status); !os.IsNotExist(err) {
		t.Fatal("status file left behind after shutdown")
	}
}

func TestTTLEngineStartClearsFiltersFromEarlierDaemon(t *testing.T) {
	inNewNetns(t)
	tx, _ := addVeth(t)
	old := loadTestPrograms(t, 64)
	if err := newTCAttacher(old, testNetns(t)).sync(); err != nil {
		t.Fatal(err)
	}
	useTempEngineStatus(t)

	m := &ttlEngineState{active: ttlEngineNFQueue}
	t.Cleanup(m.shutdown)
	m.start(Config{TtlEngine: ttlEngineNFQueue, TargetTTL: 64})
	if hasTTLFilter(testNetns(t), tx, nil) {
		t.Fatal("a filter left by an earlier eBPF daemon kept running in NFQUEUE mode")
	}
}
