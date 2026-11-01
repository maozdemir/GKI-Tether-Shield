//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsTrustedLocalRequest(t *testing.T) {
	tests := []struct {
		name, host, origin string
		want               bool
	}{
		{"same origin via 127.0.0.1", "127.0.0.1:64640", "http://127.0.0.1:64640", true},
		{"same origin via localhost", "localhost:64640", "http://localhost:64640", true},
		{"no origin header (GET / native client)", "127.0.0.1:64640", "", true},
		{"cross-site origin (CSRF)", "127.0.0.1:64640", "https://evil.example", false},
		{"null origin (sandboxed iframe)", "127.0.0.1:64640", "null", false},
		{"rebound hostname (DNS rebinding)", "evil.example:64640", "http://evil.example:64640", false},
		{"wrong port", "127.0.0.1:80", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/config", nil)
			r.Host = tt.host
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if got := isTrustedLocalRequest(r); got != tt.want {
				t.Fatalf("isTrustedLocalRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyConfigUpdate(t *testing.T) {
	base := Config{TargetTTL: 64, SplitPos: 2, DohProvider: "cloudflare"}

	got, err := applyConfigUpdate(base, map[string]any{
		"TARGET_TTL": float64(65), "TCP_SPLIT": "1", "DOH_PROVIDER": "Quad9",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TargetTTL != 65 || !got.TcpSplit || got.DohProvider != "quad9" {
		t.Fatalf("update not applied: %+v", got)
	}
	if base.TargetTTL != 64 || base.DohProvider != "cloudflare" {
		t.Fatal("applyConfigUpdate must not mutate its input")
	}

	for _, bad := range []string{"cloudflare\nQUEUE_NUM=1", "evil.example", ""} {
		if _, err := applyConfigUpdate(base, map[string]any{"DOH_PROVIDER": bad}); err == nil {
			t.Fatalf("DOH_PROVIDER %q must be rejected", bad)
		}
	}
}

func TestConfigHandlerRejectsCrossSiteAndNonJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	h := configHandler(func() string { return path })

	post := func(contentType, origin, body string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
		r.Host = "127.0.0.1:64640"
		r.Header.Set("Content-Type", contentType)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}

	if code := post("text/plain", "", `{"DOH_ENABLED":"0"}`); code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST got %d, want 415", code)
	}
	if code := post("application/json", "https://evil.example", `{"DOH_ENABLED":"0"}`); code != http.StatusForbidden {
		t.Fatalf("cross-site POST got %d, want 403", code)
	}
	if code := post("application/json", "", `{"DOH_PROVIDER":"x\nQUEUE_NUM=1"}`); code != http.StatusBadRequest {
		t.Fatalf("injected provider got %d, want 400", code)
	}
	if code := post("application/json", "", strings.Repeat(" ", 8192)+"{}"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body got %d, want 413", code)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("rejected requests must not write the config file")
	}

	if code := post("application/json; charset=utf-8", "http://127.0.0.1:64640", `{"TARGET_TTL":64}`); code != http.StatusOK {
		t.Fatalf("valid POST got %d, want 200", code)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "TARGET_TTL=64") {
		t.Fatalf("config not written: %q, %v", data, err)
	}
}

func TestLoadConfigIgnoresUnknownProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte("DOH_PROVIDER=evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := cfg
	defer func() { cfg = original }()
	cfg.DohProvider = "cloudflare"
	loadConfig(path)
	if cfg.DohProvider != "cloudflare" {
		t.Fatalf("unknown provider was loaded: %q", cfg.DohProvider)
	}
}
