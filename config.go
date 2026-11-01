//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// getStatsPath keeps stats in the root-only module dir. The old location,
// /data/local/tmp, is writable by the adb shell user, who could plant a
// symlink there and have the root daemon overwrite any file.
func getStatsPath() string {
	return filepath.Join(moduleDir(), "stats.json")
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

var cfg = Config{
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

func loadConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "TARGET_TTL":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val <= 255 {
				cfg.TargetTTL = uint8(val)
			}
		case "TCP_SPLIT":
			cfg.TcpSplit = (v == "1" || strings.ToLower(v) == "true")
		case "SPLIT_POS":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val < 100 {
				cfg.SplitPos = val
			}
		case "BUFFERBLOAT_QOS":
			cfg.BufferbloatQoS = (v == "1" || strings.ToLower(v) == "true")
		case "WIFI_POWER_SAVE_LOCK":
			cfg.WifiPowerSaveLock = (v == "1" || strings.ToLower(v) == "true")
		case "TCP_LOW_LATENCY":
			cfg.TcpLowLatency = (v == "1" || strings.ToLower(v) == "true")
		case "DOH_ENABLED":
			cfg.DohEnabled = (v == "1" || strings.ToLower(v) == "true")
		case "DOH_PROVIDER":
			if _, ok := lookupDoHProvider(v); ok {
				cfg.DohProvider = strings.ToLower(v)
			}
		case "QUEUE_NUM":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val <= 65535-NUM_QUEUES {
				cfg.QueueNum = uint16(val)
			}
		}
	}
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
