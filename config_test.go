//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// withConfig installs a modified copy of the current config for one test.
func withConfig(t *testing.T, modify func(*Config)) {
	t.Helper()
	original := *cfgSnapshot()
	next := original
	modify(&next)
	setCfg(next)
	t.Cleanup(func() { setCfg(original) })
}

func TestParseConfigAppliesValidValuesOnly(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"TARGET_TTL=65",
		"TCP_SPLIT=false",
		"SPLIT_POS=500", // out of range: keep default
		"DOH_PROVIDER=Quad9",
		"DOH_ENABLED=1",
		"QUEUE_NUM=65535", // would overflow the queue range: keep default
		"garbage line",
	}, "\n")

	got := parseConfig(defaultConfig, strings.NewReader(in))

	if got.TargetTTL != 65 || got.TcpSplit || got.SplitPos != defaultConfig.SplitPos ||
		got.DohProvider != "quad9" || !got.DohEnabled || got.QueueNum != defaultConfig.QueueNum {
		t.Fatalf("unexpected config: %+v", got)
	}
	if defaultConfig.TargetTTL != 64 {
		t.Fatal("parseConfig must not mutate its base")
	}
}

func TestLoadConfigFileMissingReturnsBase(t *testing.T) {
	got := loadConfigFile(filepath.Join(t.TempDir(), "missing.conf"), defaultConfig)
	if got != defaultConfig {
		t.Fatalf("missing file should yield the base config, got %+v", got)
	}
}

func TestLoadConfigFileIgnoresUnknownProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte("DOH_PROVIDER=evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadConfigFile(path, defaultConfig); got.DohProvider != "cloudflare" {
		t.Fatalf("unknown provider was loaded: %q", got.DohProvider)
	}
}

// Run under -race (CI does): readers and writers must not race.
func TestConfigConcurrentAccess(t *testing.T) {
	original := *cfgSnapshot()
	defer setCfg(original)

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 1000 {
				c := *cfgSnapshot()
				c.TargetTTL = uint8(60 + i)
				c.DohProvider = "quad9"
				setCfg(c)
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				c := cfgSnapshot()
				_ = c.TargetTTL
				_ = c.DohProvider
			}
		}()
	}
	wg.Wait()
}

func TestSplitModeParsingAndUpdates(t *testing.T) {
	if got := parseConfig(defaultConfig, strings.NewReader("SPLIT_MODE=FIXED\n")); got.SplitMode != splitModeFixed {
		t.Fatalf("SPLIT_MODE=FIXED -> %q", got.SplitMode)
	}
	if got := parseConfig(defaultConfig, strings.NewReader("SPLIT_MODE=sideways\n")); got.SplitMode != splitModeAuto {
		t.Fatalf("invalid SPLIT_MODE must keep the default, got %q", got.SplitMode)
	}
	if _, err := applyConfigUpdate(defaultConfig, map[string]any{"SPLIT_MODE": "sideways"}); err == nil {
		t.Fatal("invalid SPLIT_MODE must be rejected by the API")
	}
	next, err := applyConfigUpdate(defaultConfig, map[string]any{"SPLIT_MODE": "fixed"})
	if err != nil || next.SplitMode != splitModeFixed {
		t.Fatalf("SPLIT_MODE update: %+v, %v", next, err)
	}
}

func TestBlockQUICSetting(t *testing.T) {
	if !defaultConfig.BlockQUIC {
		t.Fatal("BLOCK_QUIC defaults to on")
	}
	if got := parseConfig(defaultConfig, strings.NewReader("BLOCK_QUIC=0\n")); got.BlockQUIC {
		t.Fatal("BLOCK_QUIC=0 must disable it")
	}
	next, err := applyConfigUpdate(defaultConfig, map[string]any{"BLOCK_QUIC": "0"})
	if err != nil || next.BlockQUIC {
		t.Fatalf("API update: %+v, %v", next, err)
	}
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := saveConfigToFile(path, next); err != nil {
		t.Fatal(err)
	}
	if got := loadConfigFile(path, defaultConfig); got.BlockQUIC {
		t.Fatal("BLOCK_QUIC must round-trip through config.conf")
	}
}
