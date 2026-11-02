//go:build linux

package main

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ttlEngineHandover is how long the eBPF program stays attached after
// switching to NFQUEUE: service.sh restores the iptables queue rules within
// one loop (LOOP_INTERVAL, 10s), so TTL fixing never pauses in between.
var ttlEngineHandover = 25 * time.Second

// ttlEngineState runs the configured TTL engine. The eBPF engine falls back
// to NFQUEUE (whose iptables rules service.sh keeps until the status file
// says eBPF is active) whenever it can't load or attach.
type ttlEngineState struct {
	mu      sync.Mutex
	enabled bool // set by main; tests and the CLI leave it off
	net     *tcNetns
	progs   *ttlProgSet
	att     *tcAttacher
	active  string
	lastErr string
	detach  *time.Timer
	// Counts from earlier eBPF sessions, so totals survive a detach.
	base ttlCounters
}

var ttlEngineMgr = &ttlEngineState{active: ttlEngineNFQueue}

// ttlEngineStatusPath is read by service.sh to decide whether the iptables
// TTL queue rules are needed.
var ttlEngineStatusPath = func() string {
	return filepath.Join(moduleDir(), "ttl_engine")
}

// start enables the manager and applies c.
func (m *ttlEngineState) start(c Config) {
	n, err := currentTCNetns()
	if err != nil {
		logf("eBPF TTL engine unavailable: %v", err)
		return
	}
	m.mu.Lock()
	m.enabled = true
	m.net = n
	m.mu.Unlock()
	if c.TtlEngine != ttlEngineEBPF {
		removeTTLFilters(n)
	}
	m.apply(c)
}

// apply switches to the engine c asks for and updates the eBPF target TTL.
func (m *ttlEngineState) apply(c Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}
	if m.progs != nil {
		if err := m.progs.setTarget(c.TargetTTL); err != nil {
			logf("eBPF: %v", err)
		}
	}
	if c.TtlEngine != ttlEngineEBPF {
		// Report NFQUEUE first so service.sh restores the queue rules, and
		// detach only once it has.
		m.setActive(ttlEngineNFQueue)
		m.lastErr = ""
		if m.progs != nil && m.detach == nil {
			m.detach = time.AfterFunc(ttlEngineHandover, m.detachIfNFQueue)
		}
		return
	}
	m.cancelDetach()
	if m.progs == nil {
		if err := m.startEBPF(c.TargetTTL); err != nil {
			m.lastErr = err.Error()
			logf("eBPF TTL engine unavailable, using NFQUEUE: %v", err)
			m.setActive(ttlEngineNFQueue)
			return
		}
		logf("eBPF TTL engine active (target %d)", c.TargetTTL)
	}
	m.lastErr = ""
	m.setActive(ttlEngineEBPF)
}

func (m *ttlEngineState) startEBPF(target uint8) error {
	progs, err := loadTTLPrograms(target)
	if err != nil {
		return err
	}
	att := newTCAttacher(progs, m.net)
	if err := att.start(); err != nil {
		att.close()
		progs.Close()
		return err
	}
	m.progs, m.att = progs, att
	return nil
}

// stopEBPF detaches and unloads the program, keeping its counts. Callers
// hold m.mu.
func (m *ttlEngineState) stopEBPF() {
	if m.progs == nil {
		return
	}
	if c, err := m.progs.counters(); err == nil {
		m.base = m.base.add(c)
	}
	m.att.close()
	m.progs.Close()
	m.progs, m.att = nil, nil
	logf("eBPF TTL engine detached")
}

func (m *ttlEngineState) detachIfNFQueue() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detach = nil
	if m.active == ttlEngineNFQueue {
		m.stopEBPF()
	}
}

func (m *ttlEngineState) cancelDetach() {
	if m.detach != nil {
		m.detach.Stop()
		m.detach = nil
	}
}

// setActive records the running engine and publishes it for service.sh.
func (m *ttlEngineState) setActive(engine string) {
	m.active = engine
	if err := writeFileAtomic(ttlEngineStatusPath(), []byte(engine+"\n"), 0o644); err != nil {
		logf("write TTL engine status: %v", err)
	}
}

// shutdown detaches the program and removes the status file, so service.sh
// goes back to the full NFQUEUE rules.
func (m *ttlEngineState) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}
	m.cancelDetach()
	m.stopEBPF()
	m.active = ttlEngineNFQueue
	_ = os.Remove(ttlEngineStatusPath())
	m.net.close()
	m.net, m.enabled = nil, false
}

// stats returns the running engine, the eBPF counts (including detached
// sessions) and the last eBPF failure, if any.
func (m *ttlEngineState) stats() (engine string, counts ttlCounters, lastErr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts = m.base
	if m.progs != nil {
		if c, err := m.progs.counters(); err == nil {
			counts = counts.add(c)
		}
	}
	return m.active, counts, m.lastErr
}

func (c ttlCounters) add(o ttlCounters) ttlCounters {
	return ttlCounters{
		IPv4Seen:      c.IPv4Seen + o.IPv4Seen,
		IPv6Seen:      c.IPv6Seen + o.IPv6Seen,
		IPv4Rewritten: c.IPv4Rewritten + o.IPv4Rewritten,
		IPv6Rewritten: c.IPv6Rewritten + o.IPv6Rewritten,
	}
}
