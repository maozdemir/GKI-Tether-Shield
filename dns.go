//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dnsCacheEntry struct {
	response  []byte
	expiresAt time.Time
}

var (
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.RWMutex
)

const (
	dohMaxResponseBytes = 64 * 1024
	dnsCacheTTL         = 60 * time.Second
	dnsCacheMaxEntries  = 10000
)

// dohProvider describes a DoH resolver. The URL uses the provider's real
// hostname so TLS certificates are verified against it; the connection is
// dialed straight to the pinned IP so no bootstrap DNS lookup is needed.
type dohProvider struct {
	url  string
	host string
	ip   string
}

var dohProviders = map[string]dohProvider{
	"cloudflare": {url: "https://cloudflare-dns.com/dns-query", host: "cloudflare-dns.com", ip: "1.1.1.1"},
	"quad9":      {url: "https://dns.quad9.net/dns-query", host: "dns.quad9.net", ip: "9.9.9.9"},
	"google":     {url: "https://dns.google/dns-query", host: "dns.google", ip: "8.8.8.8"},
	"adguard":    {url: "https://dns.adguard-dns.com/dns-query", host: "dns.adguard-dns.com", ip: "94.140.14.14"},
}

const defaultDoHProvider = "cloudflare"

func lookupDoHProvider(name string) (dohProvider, bool) {
	p, ok := dohProviders[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// pinnedDoHAddr maps "host:port" of a known DoH provider to "ip:port".
// Unknown hosts are refused so the client can never be steered elsewhere.
func pinnedDoHAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid DoH address %q: %w", addr, err)
	}
	for _, p := range dohProviders {
		if p.host == host {
			return net.JoinHostPort(p.ip, port), nil
		}
	}
	return "", fmt.Errorf("refusing to dial unknown DoH host %q", host)
}

var dohDialer = &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}

var dohClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pinned, err := pinnedDoHAddr(addr)
			if err != nil {
				return nil, err
			}
			return dohDialer.DialContext(ctx, network, pinned)
		},
	},
}

// androidCertDirs lists where Android keeps trusted root CAs. Go only adds
// these automatically for GOOS=android, but the daemon is built as GOOS=linux.
// User-installed CAs (/data/misc/keychain/certs-added) are deliberately excluded:
// they are how corporate/carrier TLS interception works, and Android apps
// targeting API 24+ do not trust them by default either.
const androidCertDirs = "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"

func configureAndroidCertDirs() {
	if os.Getenv("SSL_CERT_DIR") == "" {
		_ = os.Setenv("SSL_CERT_DIR", androidCertDirs)
	}
}

func currentDoHProvider() dohProvider {
	if p, ok := lookupDoHProvider(cfg.DohProvider); ok {
		return p
	}
	return dohProviders[defaultDoHProvider]
}

// resolveFallbackUDP forwards to 1.1.1.1:53 if DoH fails or times out
func resolveFallbackUDP(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func lookupDNSCache(queryKey string, query []byte) ([]byte, bool) {
	dnsCacheMu.RLock()
	entry, ok := dnsCache[queryKey]
	dnsCacheMu.RUnlock()
	if !ok || !time.Now().Before(entry.expiresAt) {
		return nil, false
	}
	resp := make([]byte, len(entry.response))
	copy(resp, entry.response)
	resp[0], resp[1] = query[0], query[1] // restore the caller's transaction ID
	return resp, true
}

func storeDNSCache(queryKey string, resp []byte) {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if len(dnsCache) > dnsCacheMaxEntries {
		dnsCache = make(map[string]dnsCacheEntry)
	}
	dnsCache[queryKey] = dnsCacheEntry{response: resp, expiresAt: time.Now().Add(dnsCacheTTL)}
}

func queryDoH(query []byte) ([]byte, error) {
	p := currentDoHProvider()
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s: %w", p.host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s returned status %d", p.host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("DoH %s returned a truncated response", p.host)
	}
	return body, nil
}

func resolveDoH(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short")
	}

	queryKey := string(query[2:])
	if resp, ok := lookupDNSCache(queryKey, query); ok {
		atomic.AddUint64(&dnsCacheHits, 1)
		return resp, nil
	}

	resp, err := queryDoH(query)
	if err != nil {
		// Fallback to direct UDP DNS if DoH failed
		return resolveFallbackUDP(query)
	}
	atomic.AddUint64(&dohQueries, 1)
	storeDNSCache(queryKey, resp)
	return resp, nil
}

func startDNSServer() {
	// UDP DNS Listener on 0.0.0.0:53545
	go func() {
		conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", DNS_PORT))
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			if !cfg.DohEnabled || n < 12 {
				continue
			}

			qCopy := make([]byte, n)
			copy(qCopy, buf[:n])

			go func(q []byte, target net.Addr) {
				resp, err := resolveDoH(q)
				if err == nil && len(resp) > 0 {
					_, _ = conn.WriteTo(resp, target)
				}
			}(qCopy, clientAddr)
		}
	}()

	// TCP DNS Listener on 0.0.0.0:53545
	go func() {
		l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", DNS_PORT))
		if err != nil {
			return
		}
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				qLen := binary.BigEndian.Uint16(lenBuf[:])
				q := make([]byte, qLen)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}

				resp, err := resolveDoH(q)
				if err == nil && len(resp) > 0 {
					var respLenBuf [2]byte
					binary.BigEndian.PutUint16(respLenBuf[:], uint16(len(resp)))
					_, _ = c.Write(respLenBuf[:])
					_, _ = c.Write(resp)
				}
			}(conn)
		}
	}()
}
