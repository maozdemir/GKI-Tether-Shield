//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CLI subcommands talk to the running daemon's API over loopback. They run
// as root (ttlshield, or the KernelSU/APatch/MMRL WebUI through ksu.exec),
// which the API trusts for writes.
//
//	tether_shield status              live counters and settings
//	tether_shield config get          current config as JSON
//	tether_shield config set '<json>' apply a config update (same as the WebUI)

const cliTimeout = 3 * time.Second

func localAPIBase() string {
	return fmt.Sprintf("http://127.0.0.1:%d", WEB_PORT)
}

// runCLI handles a subcommand. handled is false for arguments that are not a
// CLI command, so main continues with normal daemon startup.
func runCLI(args []string, apiBase string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch {
	case args[0] == "status" || args[0] == "-status" || args[0] == "--status":
		return runAPI(http.MethodGet, apiBase+"/api/stats", "", stdout, stderr), true
	case args[0] == "config" && len(args) >= 2 && args[1] == "get":
		return runAPI(http.MethodGet, apiBase+"/api/config", "", stdout, stderr), true
	case args[0] == "config" && len(args) >= 2 && args[1] == "set":
		if len(args) != 3 {
			fmt.Fprintln(stderr, `usage: tether_shield config set '{"KEY": value, ...}'`)
			return 2, true
		}
		return runAPI(http.MethodPost, apiBase+"/api/config", args[2], stdout, stderr), true
	case args[0] == "config":
		fmt.Fprintln(stderr, "usage: tether_shield config get | config set '<json>'")
		return 2, true
	}
	return 0, false
}

// apiRequest performs one request against the local API and returns the
// pretty-printed JSON body; non-200 responses become errors carrying the
// server's error message.
func apiRequest(method, url, body string) (string, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: cliTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("daemon not reachable (is it running?): %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Error != "" {
			return "", fmt.Errorf("daemon refused (HTTP %d): %s", resp.StatusCode, apiErr.Error)
		}
		return "", fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return pretty.String(), nil
}

// runAPI performs the request and prints the result; returns the exit code.
func runAPI(method, url, body string, stdout, stderr io.Writer) int {
	out, err := apiRequest(method, url, body)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, out)
	return 0
}
