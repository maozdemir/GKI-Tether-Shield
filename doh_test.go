//go:build linux

package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestLookupDoHProvider(t *testing.T) {
	for _, name := range []string{"cloudflare", "quad9", "google", "adguard", "Cloudflare"} {
		p, ok := lookupDoHProvider(name)
		if !ok {
			t.Fatalf("provider %q should be known", name)
		}
		if !strings.HasPrefix(p.url, "https://"+p.host+"/") {
			t.Fatalf("provider %q url %q must use its TLS hostname %q", name, p.url, p.host)
		}
	}
	for _, name := range []string{"", "evil.example", "cloudflare\nQUEUE_NUM=1"} {
		if _, ok := lookupDoHProvider(name); ok {
			t.Fatalf("provider %q must be rejected", name)
		}
	}
}

func TestPinnedDoHAddr(t *testing.T) {
	got, err := pinnedDoHAddr("cloudflare-dns.com:443")
	if err != nil || got != "1.1.1.1:443" {
		t.Fatalf("pinnedDoHAddr = %q, %v; want 1.1.1.1:443", got, err)
	}
	if _, err := pinnedDoHAddr("attacker.example:443"); err == nil {
		t.Fatal("unknown hosts must not be dialed")
	}
}

func TestDoHClientVerifiesCertificates(t *testing.T) {
	tr, ok := dohClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("dohClient must use *http.Transport")
	}
	if cfg := tr.TLSClientConfig; cfg != nil && cfg.InsecureSkipVerify {
		t.Fatal("DoH must verify TLS certificates")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("DoH must require TLS 1.2+")
	}
}

// TestDoHProvidersLive performs a real verified DoH query against every
// provider. Opt-in: DOH_INTEGRATION=1 go test -run TestDoHProvidersLive
func TestDoHProvidersLive(t *testing.T) {
	if os.Getenv("DOH_INTEGRATION") != "1" {
		t.Skip("set DOH_INTEGRATION=1 to query real DoH servers")
	}
	// Minimal query: ID 0x1234, RD, 1 question, example.com A IN.
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x01, 0x00, 0x01}
	original := *cfgSnapshot()
	defer setCfg(original)
	for name := range dohProviders {
		next := original
		next.DohProvider = name
		setCfg(next)
		resp, err := queryDoH(query)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 {
			t.Errorf("%s: unexpected DNS response header % x", name, resp[:4])
		}
	}
}
