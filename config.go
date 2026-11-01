//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// moduleDir is the directory containing the daemon binary, i.e. the
// module's own directory wherever the root manager installed it.
func moduleDir() string {
	exe, err := os.Executable()
	if err != nil {
		return DEFAULT_MODULE_DIR
	}
	return filepath.Dir(exe)
}

func getConfigPath() string {
	return filepath.Join(moduleDir(), "config.conf")
}

func getWebrootFile() string {
	return filepath.Join(moduleDir(), "webroot", "index.html")
}

type Config struct {
	QueueNum          uint16 `json:"QUEUE_NUM"`
	TargetTTL         uint8  `json:"TARGET_TTL"`
	TcpSplit          bool   `json:"TCP_SPLIT"`
	SplitPos          int    `json:"SPLIT_POS"`
	BufferbloatQoS    bool   `json:"BUFFERBLOAT_QOS"`
	WifiPowerSaveLock bool   `json:"WIFI_POWER_SAVE_LOCK"`
	TcpLowLatency     bool   `json:"TCP_LOW_LATENCY"`
	DohEnabled        bool   `json:"DOH_ENABLED"`
	DohProvider       string `json:"DOH_PROVIDER"`
}

var defaultConfig = Config{
	QueueNum:          6464,
	TargetTTL:         64,
	TcpSplit:          true,
	SplitPos:          2,
	BufferbloatQoS:    true,
	WifiPowerSaveLock: true,
	TcpLowLatency:     true,
	DohEnabled:        true,
	DohProvider:       "cloudflare",
}

// The active config is an immutable snapshot: readers (packet workers, DNS,
// web UI) take one consistent snapshot per use, writers publish a new one.
var currentCfg atomic.Pointer[Config]

// cfgWriteMu serializes read-modify-write updates (web API, SIGHUP reload)
// so concurrent writers cannot lose each other's changes.
var cfgWriteMu sync.Mutex

func init() {
	setCfg(defaultConfig)
}

// cfgSnapshot returns the active config. Callers must not modify it.
func cfgSnapshot() *Config {
	return currentCfg.Load()
}

func setCfg(c Config) {
	currentCfg.Store(&c)
}

func parseBool(v string) bool {
	return v == "1" || strings.EqualFold(v, "true")
}

// parseConfig returns base with the valid KEY=VALUE lines from r applied.
// Invalid or out-of-range values keep the base value.
func parseConfig(base Config, r io.Reader) Config {
	c := base
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		applyConfigValue(&c, strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return c
}

func applyConfigValue(c *Config, k, v string) {
	switch k {
	case "TARGET_TTL":
		if val, err := strconv.Atoi(v); err == nil && val > 0 && val <= 255 {
			c.TargetTTL = uint8(val)
		}
	case "TCP_SPLIT":
		c.TcpSplit = parseBool(v)
	case "SPLIT_POS":
		if val, err := strconv.Atoi(v); err == nil && val > 0 && val < 100 {
			c.SplitPos = val
		}
	case "BUFFERBLOAT_QOS":
		c.BufferbloatQoS = parseBool(v)
	case "WIFI_POWER_SAVE_LOCK":
		c.WifiPowerSaveLock = parseBool(v)
	case "TCP_LOW_LATENCY":
		c.TcpLowLatency = parseBool(v)
	case "DOH_ENABLED":
		c.DohEnabled = parseBool(v)
	case "DOH_PROVIDER":
		if _, ok := lookupDoHProvider(v); ok {
			c.DohProvider = strings.ToLower(v)
		}
	case "QUEUE_NUM":
		if val, err := strconv.Atoi(v); err == nil && val > 0 && val <= 65535-NUM_QUEUES {
			c.QueueNum = uint16(val)
		}
	}
}

// loadConfigFile returns base overlaid with the file's settings; a missing
// or unreadable file yields base unchanged.
func loadConfigFile(path string, base Config) Config {
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logf("read config %s: %v", path, err)
		}
		return base
	}
	defer f.Close()
	return parseConfig(base, f)
}

// reloadConfig re-reads config.conf (on SIGHUP, e.g. after a manual edit).
// QueueNum cannot change while queues are bound, so the running value stays.
func reloadConfig() {
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	running := cfgSnapshot().QueueNum
	next := loadConfigFile(getConfigPath(), defaultConfig)
	next.QueueNum = running
	setCfg(next)
}

// saveConfigToFile writes the config atomically (temp file + rename) so a
// crash mid-write never leaves an empty or truncated config behind.
func saveConfigToFile(path string, c Config) error {
	content := fmt.Sprintf(`# GKI Hotspot Shield Configuration
TARGET_TTL=%d
TCP_SPLIT=%t
SPLIT_POS=%d
BUFFERBLOAT_QOS=%t
WIFI_POWER_SAVE_LOCK=%t
TCP_LOW_LATENCY=%t
DOH_ENABLED=%t
DOH_PROVIDER=%s
QUEUE_NUM=%d
`, c.TargetTTL, c.TcpSplit, c.SplitPos, c.BufferbloatQoS, c.WifiPowerSaveLock, c.TcpLowLatency, c.DohEnabled, c.DohProvider, c.QueueNum)

	return writeFileAtomic(path, []byte(content), 0o644)
}

// writeFileAtomic writes via a temp file + rename, so readers never see a
// partial file and an existing symlink at path is replaced, not followed.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, errors.Join(werr, cerr))
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
