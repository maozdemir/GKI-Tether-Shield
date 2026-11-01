//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const dohMaxResponseBytes = 64 * 1024

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
	if p, ok := lookupDoHProvider(cfgSnapshot().DohProvider); ok {
		return p
	}
	return dohProviders[defaultDoHProvider]
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

// plainDNSUpstream is used when DoH is disabled or fails. A var so tests
// can point it at a local server.
var plainDNSUpstream = "1.1.1.1:53"

const plainDNSTimeout = 2 * time.Second

// resolvePlainUDP sends query to plainDNSUpstream and returns the first
// reply whose transaction ID matches and has the QR (response) bit set, so
// stray or spoofed datagrams are ignored.
func resolvePlainUDP(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short")
	}
	conn, err := net.DialTimeout("udp", plainDNSUpstream, plainDNSTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", plainDNSUpstream, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(plainDNSTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("send to %s: %w", plainDNSUpstream, err)
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read from %s: %w", plainDNSUpstream, err)
		}
		if n >= 12 && buf[0] == query[0] && buf[1] == query[1] && buf[2]&0x80 != 0 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// resolveDNS answers a redirected client query. iptables keeps redirecting
// port 53 here even when DoH is switched off, so queries must still be
// answered (in plain DNS) rather than dropped.
func resolveDNS(query []byte) ([]byte, error) {
	if cfgSnapshot().DohEnabled {
		return resolveDoH(query)
	}
	atomic.AddUint64(&dnsPlainQueries, 1)
	return resolvePlainUDP(query)
}

// lastDNSFallback is the Unix time of the last unencrypted fallback query,
// so the dashboard can warn while DoH is failing.
var lastDNSFallback atomic.Int64

var dnsLogLimiter = &logLimiter{max: 3, window: time.Minute}

// resolveFallback answers in plain DNS after DoH failed, and records it:
// the user chose encrypted DNS, so silently downgrading is not acceptable.
func resolveFallback(query []byte, dohErr error) ([]byte, error) {
	atomic.AddUint64(&dnsFallbackQueries, 1)
	lastDNSFallback.Store(dnsNow().Unix())
	if ok, suppressed := dnsLogLimiter.allow(time.Now()); ok {
		logf("DoH failed, answering in plain DNS (%d similar suppressed): %v", suppressed, dohErr)
	}
	return resolvePlainUDP(query)
}

const (
	maxConcurrentDNSQueries = 256
	maxConcurrentDNSConns   = 64
)

var (
	dnsQuerySlots = make(chan struct{}, maxConcurrentDNSQueries)
	dnsConnSlots  = make(chan struct{}, maxConcurrentDNSConns)
	dnsTCPTimeout = 5 * time.Second
)

// tryAcquire takes a slot without blocking; release with <-sem.
func tryAcquire(sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func serveDNSUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// Under a flood, drop queries instead of piling up goroutines;
		// clients retry.
		if n < 12 || !tryAcquire(dnsQuerySlots) {
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		go func(target net.Addr) {
			defer func() { <-dnsQuerySlots }()
			if resp, err := resolveDNS(q); err == nil && len(resp) > 0 {
				_, _ = conn.WriteTo(resp, target)
			}
		}(clientAddr)
	}
}

// serveDNSTCPConn answers one length-prefixed query, bounded by a deadline
// so idle or slow clients cannot hold the connection open.
func serveDNSTCPConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(dnsTCPTimeout))

	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	resp, err := resolveDNS(q)
	if err != nil || len(resp) == 0 || len(resp) > 0xffff {
		return
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
	_, _ = c.Write(append(out, resp...))
}

func serveDNSTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !tryAcquire(dnsConnSlots) {
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-dnsConnSlots }()
			serveDNSTCPConn(c)
		}()
	}
}

// listenDNS opens dual-stack (IPv4 + IPv6) UDP and TCP listeners on port,
// so tether clients querying over either family reach the proxy. service.sh
// only accepts this port from loopback and downstream interfaces (iptables
// and ip6tables), so no modem interface can reach it.
func listenDNS(port int) (net.PacketConn, net.Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("DNS UDP listen on %s: %w", addr, err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", pc.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		pc.Close()
		return nil, nil, fmt.Errorf("DNS TCP listen on %s: %w", addr, err)
	}
	return pc, l, nil
}

func startDNSServer() {
	pc, l, err := listenDNS(DNS_PORT)
	if err != nil {
		logf("%v", err)
		return
	}
	go serveDNSUDP(pc)
	go serveDNSTCP(l)
}
