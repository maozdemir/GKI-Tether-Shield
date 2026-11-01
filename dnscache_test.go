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

// answerTTLs parses resp and returns the TTL of every answer and additional
// record, in order (OPT pseudo-records included, as their raw TTL field).
func answerTTLs(t *testing.T, resp []byte) []uint32 {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	var ttls []uint32
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ttls = append(ttls, h.TTL)
		if err := p.SkipAnswer(); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatal(err)
	}
	for {
		h, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ttls = append(ttls, h.TTL)
		if err := p.SkipAdditional(); err != nil {
			t.Fatal(err)
		}
	}
	return ttls
}

func TestCachedAnswersCountDownTTLs(t *testing.T) {
	clearDNSCache(t)
	now := time.Unix(1_000_000, 0)
	origNow := dnsNow
	dnsNow = func() time.Time { return now }
	t.Cleanup(func() { dnsNow = origNow })

	// Two answers (300s, 120s) plus an EDNS OPT record whose TTL field
	// carries flags (DO bit) and must never be rewritten.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9, Response: true})
	name := dnsmessage.MustNewName("example.com.")
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	for _, ttl := range []uint32{300, 120} {
		_ = b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
	}
	_ = b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true); err != nil {
		t.Fatal(err)
	}
	_ = b.OPTResource(opt, dnsmessage.OPTResource{})
	resp, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	optTTL := answerTTLs(t, resp)[2]

	query := dnsQuery(0x4242)
	key := string(query[2:])
	storeDNSCache(key, resp, cacheTTLFor(resp))

	now = now.Add(50 * time.Second)
	cached, ok := lookupDNSCache(key, query)
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if got := answerTTLs(t, cached); got[0] != 250 || got[1] != 70 || got[2] != optTTL {
		t.Fatalf("TTLs after 50s = %v, want [250 70 %d]", got, optTTL)
	}
	if binary.BigEndian.Uint16(cached[:2]) != 0x4242 {
		t.Fatal("cached answer must carry the caller's transaction ID")
	}
	if got := answerTTLs(t, resp); got[0] != 300 {
		t.Fatal("the stored response must not be modified")
	}
}

func TestRRTTLOffsetsRejectsMalformedMessages(t *testing.T) {
	good := buildResponse(t, dnsmessage.RCodeSuccess, false, 60)
	if _, ok := rrTTLOffsets(good); !ok {
		t.Fatal("well-formed message must parse")
	}
	for cut := 12; cut < len(good); cut++ {
		if _, ok := rrTTLOffsets(good[:cut]); ok {
			t.Fatalf("truncated message (%d bytes) must be rejected", cut)
		}
	}
	loop := append([]byte(nil), good[:12]...)
	binary.BigEndian.PutUint16(loop[4:6], 1)  // one question
	binary.BigEndian.PutUint16(loop[6:8], 0)  // no answers
	loop = append(loop, 0xC0, 12, 0, 1, 0, 1) // question name is a compression pointer
	if _, ok := rrTTLOffsets(loop); !ok {
		// a pointer terminates a name, so this parses; it just has no records
		t.Fatal("pointer-terminated question should parse")
	}
}

func FuzzRRTTLOffsets(f *testing.F) {
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, msg []byte) {
		offsets, ok := rrTTLOffsets(msg)
		if !ok {
			return
		}
		for _, off := range offsets {
			if off < 0 || off+4 > len(msg) {
				t.Fatalf("offset %d out of range for %d-byte message", off, len(msg))
			}
		}
	})
}
