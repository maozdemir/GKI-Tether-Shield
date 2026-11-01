//go:build linux

package main

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildResponse returns a DNS response with the given rcode, truncation flag
// and one A record per TTL.
func buildResponse(t *testing.T, rcode dnsmessage.RCode, truncated bool, ttls ...uint32) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: rcode, Truncated: truncated})
	name := dnsmessage.MustNewName("example.com.")
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range ttls {
		hdr := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}
		if err := b.AResource(hdr, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestCacheTTLFor(t *testing.T) {
	tests := []struct {
		name string
		resp []byte
		want time.Duration
	}{
		{"min answer ttl", buildResponse(t, dnsmessage.RCodeSuccess, false, 30, 10), 10 * time.Second},
		{"clamped to max", buildResponse(t, dnsmessage.RCodeSuccess, false, 86400), dnsCacheMaxTTL},
		{"raised to min", buildResponse(t, dnsmessage.RCodeSuccess, false, 1), dnsCacheMinTTL},
		{"ttl 0 is not cached", buildResponse(t, dnsmessage.RCodeSuccess, false, 0), 0},
		{"nxdomain not cached", buildResponse(t, dnsmessage.RCodeNameError, false), 0},
		{"servfail not cached", buildResponse(t, dnsmessage.RCodeServerFailure, false), 0},
		{"truncated not cached", buildResponse(t, dnsmessage.RCodeSuccess, true, 60), 0},
		{"no answers not cached", buildResponse(t, dnsmessage.RCodeSuccess, false), 0},
		{"garbage not cached", []byte{1, 2, 3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cacheTTLFor(tt.resp); got != tt.want {
				t.Fatalf("cacheTTLFor = %v, want %v", got, tt.want)
			}
		})
	}
}

func withDoHQuery(t *testing.T, fn func([]byte) ([]byte, error)) {
	t.Helper()
	orig := dohQueryFunc
	dohQueryFunc = fn
	t.Cleanup(func() { dohQueryFunc = orig })
}

func clearDNSCache(t *testing.T) {
	t.Helper()
	dnsCacheMu.Lock()
	dnsCache = make(map[string]dnsCacheEntry)
	dnsCacheMu.Unlock()
}

func TestResolveDoHCoalescesConcurrentQueries(t *testing.T) {
	clearDNSCache(t)
	var upstream atomic.Int32
	release := make(chan struct{})
	withDoHQuery(t, func(q []byte) ([]byte, error) {
		upstream.Add(1)
		<-release
		resp := buildResponse(t, dnsmessage.RCodeSuccess, false, 60)
		copy(resp[:2], q[:2])
		return resp, nil
	})

	const callers = 8
	var wg sync.WaitGroup
	ids := make([]uint16, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := resolveDoH(dnsQuery(uint16(100 + i)))
			if err != nil {
				t.Errorf("resolveDoH: %v", err)
				return
			}
			ids[i] = binary.BigEndian.Uint16(resp[:2])
		}()
	}
	time.Sleep(100 * time.Millisecond) // let all callers join the flight
	close(release)
	wg.Wait()

	if n := upstream.Load(); n != 1 {
		t.Fatalf("upstream queried %d times, want 1", n)
	}
	for i, id := range ids {
		if id != uint16(100+i) {
			t.Fatalf("caller %d got transaction ID %d, want %d", i, id, 100+i)
		}
	}
}

func TestResolveDoHDoesNotCacheFailures(t *testing.T) {
	clearDNSCache(t)
	var upstream atomic.Int32
	withDoHQuery(t, func(q []byte) ([]byte, error) {
		upstream.Add(1)
		resp := buildResponse(t, dnsmessage.RCodeServerFailure, false)
		copy(resp[:2], q[:2])
		return resp, nil
	})

	for range 2 {
		if _, err := resolveDoH(dnsQuery(7)); err != nil {
			t.Fatal(err)
		}
	}
	if n := upstream.Load(); n != 2 {
		t.Fatalf("SERVFAIL was cached: upstream queried %d times, want 2", n)
	}
}
