//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const maxConfigBodyBytes = 4096

var trustedWebHosts = map[string]bool{
	fmt.Sprintf("127.0.0.1:%d", WEB_PORT): true,
	fmt.Sprintf("localhost:%d", WEB_PORT): true,
}

// isTrustedLocalRequest blocks DNS rebinding (Host must be our loopback
// address) and cross-site requests from web pages (Origin, when a browser
// sends one, must be our own origin). It cannot stop a local app that forges
// both headers; that needs per-UID authentication.
func isTrustedLocalRequest(r *http.Request) bool {
	if !trustedWebHosts[r.Host] {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	host, ok := strings.CutPrefix(origin, "http://")
	return ok && trustedWebHosts[host]
}

func requireTrustedLocal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isTrustedLocalRequest(r) {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}

func parseBoolValue(v any) bool {
	return v == "1" || v == true || v == "true"
}

// applyConfigUpdate returns a copy of base with the update applied. Numeric
// values out of range are ignored (as before); an unknown DoH provider rejects
// the whole update so arbitrary text can never reach the config file.
func applyConfigUpdate(base Config, update map[string]any) (Config, error) {
	next := base
	if f, ok := update["TARGET_TTL"].(float64); ok && f > 0 && f <= 255 {
		next.TargetTTL = uint8(f)
	}
	if f, ok := update["SPLIT_POS"].(float64); ok && f > 0 && f < 100 {
		next.SplitPos = int(f)
	}
	if v, ok := update["SPLIT_MODE"]; ok {
		s, _ := v.(string)
		mode, valid := parseSplitMode(s)
		if !valid {
			return base, fmt.Errorf("SPLIT_MODE must be %q or %q", splitModeAuto, splitModeFixed)
		}
		next.SplitMode = mode
	}
	boolFields := map[string]*bool{
		"TCP_SPLIT":            &next.TcpSplit,
		"BLOCK_QUIC":           &next.BlockQUIC,
		"BUFFERBLOAT_QOS":      &next.BufferbloatQoS,
		"WIFI_POWER_SAVE_LOCK": &next.WifiPowerSaveLock,
		"TCP_LOW_LATENCY":      &next.TcpLowLatency,
		"DOH_ENABLED":          &next.DohEnabled,
	}
	for key, field := range boolFields {
		if v, ok := update[key]; ok {
			*field = parseBoolValue(v)
		}
	}
	if v, ok := update["DOH_PROVIDER"]; ok {
		name, _ := v.(string)
		if _, known := lookupDoHProvider(name); !known {
			return base, fmt.Errorf("unknown DOH_PROVIDER %q", name)
		}
		next.DohProvider = strings.ToLower(strings.TrimSpace(name))
	}
	return next, nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func handleConfigPost(w http.ResponseWriter, r *http.Request, configPath func() string) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		// Requiring JSON forces a CORS preflight for cross-origin fetches,
		// which this server never answers.
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var update map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBodyBytes))
	if err := dec.Decode(&update); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	next, err := applyConfigUpdate(*cfgSnapshot(), update)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := saveConfigToFile(configPath(), next); err != nil {
		logf("save config: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to save config")
		return
	}
	setCfg(next)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// configHandler serves GET/POST /api/config. canWrite decides whether the
// caller may change settings (see auth.go); reads only need the Host/Origin
// checks of requireTrustedLocal.
func configHandler(configPath func() string, canWrite func(*http.Request) bool) http.HandlerFunc {
	return requireTrustedLocal(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfgSnapshot())
		case http.MethodPost:
			if !canWrite(r) {
				writeJSONError(w, http.StatusForbidden, "settings can only be changed from the Hotspot Shield app")
				return
			}
			handleConfigPost(w, r, configPath)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	c := cfgSnapshot()
	stats := map[string]any{
		"total_packets":        atomic.LoadUint64(&totalPackets),
		"ipv4_packets":         atomic.LoadUint64(&ipv4Packets),
		"ipv6_packets":         atomic.LoadUint64(&ipv6Packets),
		"ttl_modified":         atomic.LoadUint64(&ttlModified),
		"tcp_split_packets":    atomic.LoadUint64(&tcpSplitPkts),
		"doh_queries":          atomic.LoadUint64(&dohQueries),
		"dns_cache_hits":       atomic.LoadUint64(&dnsCacheHits),
		"dns_fallback_queries": atomic.LoadUint64(&dnsFallbackQueries),
		"dns_plain_queries":    atomic.LoadUint64(&dnsPlainQueries),
		"dns_last_fallback":    lastDNSFallback.Load(),
		"target_ttl":           c.TargetTTL,
		"tcp_split_enabled":    c.TcpSplit,
		"block_quic":           c.BlockQUIC,
		"bufferbloat_qos":      c.BufferbloatQoS,
		"doh_enabled":          c.DohEnabled,
		"doh_provider":         c.DohProvider,
		"version":              moduleVersion,
		"version_code":         versionCode(),
		"updated_at":           time.Now().Format(time.RFC3339),
	}
	_ = json.NewEncoder(w).Encode(stats)
}

// indexHandler serves the dashboard. When the companion app sends a nonce,
// the response carries a MAC over the exact page bytes (see pageMAC).
func indexHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := webUIHTML
		if len(page) == 0 {
			data, err := os.ReadFile(getWebrootFile())
			if err != nil {
				http.Error(w, "dashboard not found", http.StatusNotFound)
				return
			}
			page = data
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if nonce := r.Header.Get(pageNonceHeader); token != "" && validNonce(nonce) {
			w.Header().Set(pageMACHeader, pageMAC(token, nonce, page))
		}
		_, _ = w.Write(page)
	}
}

func startHTTPServer() {
	token, err := createWebUIToken()
	if err != nil {
		// Without a token only UID-authorized callers (the app) can save.
		logf("web UI token: %v", err)
	}
	auth := newWriteAuthorizer(token)

	mux := http.NewServeMux()
	mux.HandleFunc("/", requireTrustedLocal(indexHandler(token)))
	mux.HandleFunc("/api/stats", requireTrustedLocal(statsHandler))
	mux.HandleFunc("/api/config", configHandler(getConfigPath, auth.allowed))

	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", WEB_PORT),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logf("web UI server stopped: %v", err)
		}
	}()
}
