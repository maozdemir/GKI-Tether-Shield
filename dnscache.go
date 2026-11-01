//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	dnsCacheMinTTL     = 5 * time.Second
	dnsCacheMaxTTL     = 5 * time.Minute
	dnsCacheMaxEntries = 10000
)

type dnsCacheEntry struct {
	response   []byte
	storedAt   time.Time
	expiresAt  time.Time
	ttlOffsets []int // byte offsets of the records' TTL fields (OPT excluded)
}

// dnsNow is the cache clock (a var for tests).
var dnsNow = time.Now

var (
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.RWMutex

	// dohFlight merges identical concurrent lookups into one upstream query.
	dohFlight singleflight.Group
	// dohQueryFunc performs the upstream DoH request (a var for tests).
	dohQueryFunc = queryDoH
)

// cacheTTLFor returns how long resp may be cached: the smallest answer TTL,
// clamped to [dnsCacheMinTTL, dnsCacheMaxTTL]. Failures (non-NOERROR),
// truncated or empty answers, TTL 0 and unparsable messages are not cached.
func cacheTTLFor(resp []byte) time.Duration {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeSuccess || hdr.Truncated {
		return 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0
	}
	minTTL, answers := uint32(0), 0
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return 0
		}
		if answers == 0 || h.TTL < minTTL {
			minTTL = h.TTL
		}
		answers++
		if err := p.SkipAnswer(); err != nil {
			return 0
		}
	}
	if answers == 0 || minTTL == 0 {
		return 0
	}
	ttl := time.Duration(minTTL) * time.Second
	return min(max(ttl, dnsCacheMinTTL), dnsCacheMaxTTL)
}

const dnsTypeOPT = 41

// rrTTLOffsets walks a DNS message and returns the byte offsets of the TTL
// field of every resource record (answers, authorities, additionals) except
// EDNS OPT pseudo-records, whose "TTL" holds flags. ok is false for any
// malformed or truncated message.
func rrTTLOffsets(msg []byte) (offsets []int, ok bool) {
	if len(msg) < 12 {
		return nil, false
	}
	count := func(i int) int { return int(binary.BigEndian.Uint16(msg[i : i+2])) }
	off := 12
	for range count(4) { // questions: name, type, class
		if off, ok = skipDNSName(msg, off); !ok || off+4 > len(msg) {
			return nil, false
		}
		off += 4
	}
	records := count(6) + count(8) + count(10)
	for range records {
		if off, ok = skipDNSName(msg, off); !ok || off+10 > len(msg) {
			return nil, false
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		if rrType != dnsTypeOPT {
			offsets = append(offsets, off+4)
		}
		off += 10 + rdLen
		if off > len(msg) {
			return nil, false
		}
	}
	return offsets, true
}

// skipDNSName returns the offset just past the (possibly compressed) name
// starting at off. A compression pointer ends the name, so loops can't occur.
func skipDNSName(msg []byte, off int) (int, bool) {
	for off < len(msg) {
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case l&0xC0 != 0:
			return 0, false // reserved label types
		default:
			off += 1 + l
		}
	}
	return 0, false
}

// withQueryID returns a copy of resp carrying the caller's transaction ID.
func withQueryID(resp, query []byte) []byte {
	out := append([]byte(nil), resp...)
	out[0], out[1] = query[0], query[1]
	return out
}

func lookupDNSCache(queryKey string, query []byte) ([]byte, bool) {
	dnsCacheMu.RLock()
	entry, ok := dnsCache[queryKey]
	dnsCacheMu.RUnlock()
	now := dnsNow()
	if !ok || !now.Before(entry.expiresAt) {
		return nil, false
	}
	resp := withQueryID(entry.response, query)
	// Report the remaining lifetime, not the original TTL, so clients don't
	// cache an answer for longer than the authoritative TTL allows.
	elapsed := uint32(now.Sub(entry.storedAt) / time.Second)
	for _, off := range entry.ttlOffsets {
		ttl := binary.BigEndian.Uint32(resp[off : off+4])
		if ttl > elapsed {
			ttl -= elapsed
		} else {
			ttl = 0
		}
		binary.BigEndian.PutUint32(resp[off:off+4], ttl)
	}
	return resp, true
}

func storeDNSCache(queryKey string, resp []byte, ttl time.Duration) {
	offsets, ok := rrTTLOffsets(resp)
	if !ok {
		return // never serve a cached answer whose TTLs can't be adjusted
	}
	now := dnsNow()
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if len(dnsCache) >= dnsCacheMaxEntries {
		for k, e := range dnsCache {
			if !now.Before(e.expiresAt) {
				delete(dnsCache, k)
			}
		}
		if len(dnsCache) >= dnsCacheMaxEntries {
			dnsCache = make(map[string]dnsCacheEntry)
		}
	}
	dnsCache[queryKey] = dnsCacheEntry{response: resp, storedAt: now, expiresAt: now.Add(ttl), ttlOffsets: offsets}
}

func resolveDoH(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short")
	}

	// The cache key ignores the transaction ID (first two bytes).
	queryKey := string(query[2:])
	if resp, ok := lookupDNSCache(queryKey, query); ok {
		atomic.AddUint64(&dnsCacheHits, 1)
		return resp, nil
	}

	v, err, _ := dohFlight.Do(queryKey, func() (any, error) {
		resp, err := dohQueryFunc(query)
		if err != nil {
			return nil, err
		}
		atomic.AddUint64(&dohQueries, 1)
		if ttl := cacheTTLFor(resp); ttl > 0 {
			storeDNSCache(queryKey, resp, ttl)
		}
		return resp, nil
	})
	if err != nil {
		return resolveFallback(query, err)
	}
	return withQueryID(v.([]byte), query), nil
}
