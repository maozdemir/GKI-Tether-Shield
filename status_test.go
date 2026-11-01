//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchStatusPrettyPrintsLiveStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(statsHandler))
	defer srv.Close()

	out, err := apiRequest(http.MethodGet, srv.URL+"/api/stats", "")
	if err != nil {
		t.Fatalf("apiRequest: %v", err)
	}
	for _, want := range []string{`"total_packets"`, `"doh_provider"`, "\n  "} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestFetchStatusReportsUnreachableDaemon(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more

	if _, err := apiRequest(http.MethodGet, url+"/api/stats", ""); err == nil {
		t.Fatal("expected an error when the daemon is not running")
	}
}
