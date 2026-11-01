//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel ttl bpf/ttl.c -- -O2 -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TTL engines: the eBPF engine rewrites TTL / hop limit in the kernel (tc
// egress); NFQUEUE copies each packet to this daemon. "auto" tries eBPF and
// falls back to NFQUEUE.
const (
	ttlEngineNFQueue = "nfqueue"
	ttlEngineEBPF    = "ebpf"
	ttlEngineAuto    = "auto"
)

// parseTTLEngine accepts nfqueue, ebpf or auto (case-insensitive).
func parseTTLEngine(v string) (string, bool) {
	switch e := strings.ToLower(strings.TrimSpace(v)); e {
	case ttlEngineNFQueue, ttlEngineEBPF, ttlEngineAuto:
		return e, true
	}
	return "", false
}

// Indexes of the program's per-CPU counters (enum counter in bpf/ttl.c).
const (
	bpfCntIPv4Seen = iota
	bpfCntIPv6Seen
	bpfCntIPv4Rewritten
	bpfCntIPv6Rewritten
	bpfCntMax
)

// ethHeaderLen is the IP header offset on Ethernet-framed links.
const ethHeaderLen = 14

// ttlCounters are the eBPF program's packet counts since it was loaded.
type ttlCounters struct {
	IPv4Seen, IPv6Seen, IPv4Rewritten, IPv6Rewritten uint64
}

// ttlProgSet holds the loaded program for each link framing. Both
// instances share one target_ttl and one counters map.
type ttlProgSet struct {
	raw  *ebpf.Program // IP header at offset 0: cellular, CLAT, tun, ppp
	eth  *ebpf.Program // IP header after the Ethernet header
	maps ttlMaps
}

var memlockOnce sync.Once

// loadTTLPrograms loads the eBPF program for both framings and sets the
// target TTL. GKI 5.10 still charges BPF memory to RLIMIT_MEMLOCK.
func loadTTLPrograms(target uint8) (*ttlProgSet, error) {
	memlockOnce.Do(func() {
		if err := rlimit.RemoveMemlock(); err != nil {
			logf("eBPF: raising memlock limit: %v", err)
		}
	})
	spec, err := loadTtl()
	if err != nil {
		return nil, fmt.Errorf("parse eBPF object: %w", err)
	}
	var raw ttlObjects
	if err := spec.LoadAndAssign(&raw, nil); err != nil {
		return nil, fmt.Errorf("load eBPF program: %w", err)
	}

	ethSpec := spec.Copy()
	if err := ethSpec.Variables["l3_off"].Set(uint32(ethHeaderLen)); err != nil {
		raw.Close()
		return nil, fmt.Errorf("set eBPF l3_off: %w", err)
	}
	var eth struct {
		FixTtl *ebpf.Program `ebpf:"fix_ttl"`
	}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		"target_ttl": raw.TargetTtl,
		"counters":   raw.Counters,
	}}
	if err := ethSpec.LoadAndAssign(&eth, opts); err != nil {
		raw.Close()
		return nil, fmt.Errorf("load eBPF program (Ethernet): %w", err)
	}

	p := &ttlProgSet{raw: raw.FixTtl, eth: eth.FixTtl, maps: raw.ttlMaps}
	if err := p.setTarget(target); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// setTarget changes the TTL / hop limit the attached programs write.
func (p *ttlProgSet) setTarget(ttl uint8) error {
	if err := p.maps.TargetTtl.Put(uint32(0), uint32(ttl)); err != nil {
		return fmt.Errorf("set eBPF target TTL: %w", err)
	}
	return nil
}

// counters sums the per-CPU counters.
func (p *ttlProgSet) counters() (ttlCounters, error) {
	var out [bpfCntMax]uint64
	var perCPU []uint64
	for i := range out {
		if err := p.maps.Counters.Lookup(uint32(i), &perCPU); err != nil {
			return ttlCounters{}, fmt.Errorf("read eBPF counter %d: %w", i, err)
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return ttlCounters{
		IPv4Seen: out[bpfCntIPv4Seen], IPv6Seen: out[bpfCntIPv6Seen],
		IPv4Rewritten: out[bpfCntIPv4Rewritten], IPv6Rewritten: out[bpfCntIPv6Rewritten],
	}, nil
}

// Close releases the programs and maps. Programs already attached to tc
// stay attached (the kernel holds a reference) until detached.
func (p *ttlProgSet) Close() error {
	return errors.Join(p.raw.Close(), closeIfSet(p.eth), p.maps.Close())
}

func closeIfSet(prog *ebpf.Program) error {
	if prog == nil {
		return nil
	}
	return prog.Close()
}
