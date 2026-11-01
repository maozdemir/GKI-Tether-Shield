//go:build linux

package main

import (
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
	response  []byte
	expiresAt time.Time
}

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
	if !ok || !time.Now().Before(entry.expiresAt) {
		return nil, false
	}
	return withQueryID(entry.response, query), true
}

func storeDNSCache(queryKey string, resp []byte, ttl time.Duration) {
	now := time.Now()
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
	dnsCache[queryKey] = dnsCacheEntry{response: resp, expiresAt: now.Add(ttl)}
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
		// Fallback to plain DNS if DoH failed
		return resolvePlainUDP(query)
	}
	return withQueryID(v.([]byte), query), nil
}
