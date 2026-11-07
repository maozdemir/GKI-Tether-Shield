//go:build linux

package main

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// sqmManager runs auto-adjusting shaping (autorate.go, sqm.go) on the
// phone's mobile-data uplink while BUFFERBLOAT_QOS and QOS_AUTORATE are on,
// hotspot or not. It follows the uplink when it changes and removes the
// shaper when turned off or when the daemon stops.

const (
	sqmTick        = 100 * time.Millisecond // ping interval while busy
	sqmControlEach = 2                      // controller runs every 2 ticks
	sqmUplinkEvery = 2 * time.Second
	// sqmMinChange: smaller cap changes aren't worth a netlink call.
	sqmMinChange = 0.01
	// tsGiveUpAfter: this many unanswered timestamp probes (3 s busy) and
	// the pinger falls back to round-trip echo requests.
	tsGiveUpAfter = 30
)

// sqmIfaceStatusPath tells service.sh which link the daemon shapes, so its
// own fq_codel handling leaves it alone.
var sqmIfaceStatusPath = func() string {
	return filepath.Join(moduleDir(), "sqm_iface")
}

type sqmStatus struct {
	Active    bool    `json:"active"`
	Iface     string  `json:"iface,omitempty"`
	Download  bool    `json:"download_shaped"`
	DownKbit  float64 `json:"down_kbit"`
	UpKbit    float64 `json:"up_kbit"`
	RateDown  float64 `json:"rate_down_kbit"` // achieved
	RateUp    float64 `json:"rate_up_kbit"`
	Measuring bool    `json:"measuring"`
	OneWay    bool    `json:"one_way"` // delays measured per direction
	RTTms     float64 `json:"rtt_ms"`
	DelayMs   float64 `json:"delay_ms"` // download (round trip if !one_way)
	UpDelayMs float64 `json:"up_delay_ms"`
	Error     string  `json:"error,omitempty"`
}

type sqmManager struct {
	mu      sync.Mutex
	enabled bool // set by main; tests and the CLI leave it off
	stop    chan struct{}
	done    chan struct{}
	status  sqmStatus
	lastErr string
}

var sqmMgr = &sqmManager{}

func sqmWanted(c Config) bool { return c.BufferbloatQoS && c.QosAutorate }

// start enables the manager and applies c.
func (m *sqmManager) start(c Config) {
	m.mu.Lock()
	m.enabled = true
	m.mu.Unlock()
	m.apply(c)
}

// apply starts or stops shaping to match c.
func (m *sqmManager) apply(c Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}
	switch want := sqmWanted(c); {
	case want && m.stop == nil:
		m.stop, m.done = make(chan struct{}), make(chan struct{})
		go m.run(m.stop, m.done)
	case !want && m.stop != nil:
		m.stopLocked()
	}
}

// stopLocked stops the loop and waits for it to undo the shaper. Callers
// hold m.mu; it is released while waiting (the loop publishes status).
func (m *sqmManager) stopLocked() {
	close(m.stop)
	done := m.done
	m.stop, m.done = nil, nil
	m.mu.Unlock()
	<-done
	m.mu.Lock()
	m.status = sqmStatus{}
}

func (m *sqmManager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		m.stopLocked()
	}
	m.enabled = false
}

func (m *sqmManager) snapshot() sqmStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	if s.Error == "" {
		s.Error = m.lastErr
	}
	return s
}

func (m *sqmManager) publish(s sqmStatus) {
	m.mu.Lock()
	m.status = s
	m.mu.Unlock()
}

func (m *sqmManager) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	m.mu.Lock()
	changed := m.lastErr != msg
	m.lastErr = msg
	m.mu.Unlock()
	if changed {
		logf("SQM: %s", msg)
	}
}

func (m *sqmManager) clearErr() {
	m.mu.Lock()
	m.lastErr = ""
	m.mu.Unlock()
}

func (m *sqmManager) run(stop, done chan struct{}) {
	defer close(done)
	defer func() { _ = os.Remove(sqmIfaceStatusPath()) }()
	n, err := currentTCNetns()
	if err != nil {
		m.fail("%v", err)
		return
	}
	defer n.close()
	removeAllSQM(n) // leftovers from a daemon that was killed

	var sess *sqmSession
	defer func() {
		if sess != nil {
			sess.close()
		}
	}()
	tick := time.NewTicker(sqmTick)
	defer tick.Stop()
	var lastUplink time.Time
	for {
		select {
		case <-stop:
			return
		case now := <-tick.C:
			if now.Sub(lastUplink) >= sqmUplinkEvery {
				lastUplink = now
				sess = m.followUplink(n, sess)
			}
			if sess != nil {
				m.publish(sess.step(now))
			} else {
				m.publish(sqmStatus{})
			}
		}
	}
}

// followUplink keeps a session on the current mobile-data uplink.
func (m *sqmManager) followUplink(n *tcNetns, sess *sqmSession) *sqmSession {
	up, err := findMobileUplink(n)
	if sess != nil && up.name == sess.name && sess.sh.intact() {
		return sess
	}
	if sess != nil {
		if up.name == sess.name {
			logf("SQM: shaper on %s was removed, re-adding it", sess.name)
		}
		sess.close()
		sess = nil
	}
	if err != nil || up.name == "" {
		_ = writeFileAtomic(sqmIfaceStatusPath(), nil, 0o644)
		m.clearErr()
		return nil // Wi-Fi or no network: nothing to shape
	}
	s, err := newSQMSession(n, up)
	if err != nil {
		m.fail("%v", err)
		removeSQM(n, up.link)
		return nil
	}
	m.clearErr()
	return s
}

type mobileUplink struct {
	name string
	link netlink.Link
	v6   bool // measure with IPv6 pings
	clat bool // IPv4 reaches it through CLAT (464XLAT)
}

// findMobileUplink returns the link of the phone's own default route when
// that is mobile data (not Wi-Fi or another downstream name). Root's
// unmarked lookups follow Android's default network.
func findMobileUplink(n *tcNetns) (mobileUplink, error) {
	var up mobileUplink
	for _, target := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		routes, err := n.nl.RouteGet(net.ParseIP(target))
		if err != nil || len(routes) == 0 || routes[0].LinkIndex == 0 {
			continue
		}
		l, err := n.nl.LinkByIndex(routes[0].LinkIndex)
		if err != nil {
			continue
		}
		name := l.Attrs().Name
		if base, ok := strings.CutPrefix(name, "v4-"); ok {
			// CLAT: IPv4 is translated and sent out of the IPv6 uplink.
			if l, err = n.nl.LinkByName(base); err != nil {
				continue
			}
			name, up.clat = base, true
		}
		if isDownstreamIface(name) {
			return mobileUplink{}, nil
		}
		up.name, up.link = name, l
		up.v6 = up.clat || strings.Contains(target, ":")
		return up, nil
	}
	return up, fmt.Errorf("no default route")
}

type sqmSession struct {
	name     string
	sh       *shaper
	ctl      *autorate
	ping     *pinger
	samples  chan rttSample
	ticks    int
	lastRx   uint64
	lastTx   uint64
	lastAt   time.Time
	rateDown float64
	rateUp   float64
	setDown  float64
	setUp    float64
	// Timestamp probes sent and answered, to fall back to echo.
	tsSent, tsReplies int
}

func newSQMSession(n *tcNetns, up mobileUplink) (*sqmSession, error) {
	ctl := newAutorate(defaultAutorateConfig)
	// Downloads arriving through CLAT can't be redirected safely: on its
	// way back from the ifb a packet skips the uplink's ingress programs,
	// which include CLAT's translation. Upload shaping still applies.
	sh, err := newShaper(n, up.link, ctl.down(), ctl.up(), !up.clat)
	if err != nil {
		return nil, err
	}
	p, err := newPinger(up.name, up.v6)
	if err != nil {
		sh.close()
		return nil, err
	}
	s := &sqmSession{
		name: up.name, sh: sh, ctl: ctl, ping: p,
		samples: make(chan rttSample, 64),
		setDown: ctl.down(), setUp: ctl.up(),
	}
	s.lastRx, s.lastTx = linkBytes(up.name)
	s.lastAt = time.Now()
	go s.receive()
	_ = writeFileAtomic(sqmIfaceStatusPath(), []byte(up.name+"\n"), 0o644)
	logf("SQM: auto-adjusting shaper on %s (download shaped: %v)", up.name, !up.clat)
	return s, nil
}

// receive forwards RTT samples until the socket is closed.
func (s *sqmSession) receive() {
	for {
		sample, ok, err := s.ping.receive()
		if err != nil {
			return
		}
		if ok {
			select {
			case s.samples <- sample:
			default:
			}
		}
	}
}

func (s *sqmSession) close() {
	s.ping.close()
	s.sh.close()
	logf("SQM: shaper removed from %s", s.name)
}

// step runs one tick: pings while busy, and every sqmControlEach ticks
// measures throughput and moves the caps.
func (s *sqmSession) step(now time.Time) sqmStatus {
	for drained := false; !drained; {
		select {
		case sample := <-s.samples:
			if sample.owd {
				s.tsReplies++
				s.ctl.observeOWD(sample.at, sample.reflector, sample.rtt, sample.up, sample.down)
			} else {
				s.ctl.observe(sample.at, sample.reflector, sample.rtt)
			}
		default:
			drained = true
		}
	}
	measuring := s.ctl.active(s.rateDown, s.rateUp)
	if measuring {
		_ = s.ping.send(now)
		if s.ping.usingTimestamps() {
			s.tsSent++
			if s.tsSent >= tsGiveUpAfter && s.tsReplies == 0 {
				s.ping.useEcho()
				logf("SQM: no reflector answers ICMP timestamps, using round-trip pings")
			}
		}
	}
	s.ticks++
	if s.ticks%sqmControlEach == 0 {
		rx, tx := linkBytes(s.name)
		if dt := now.Sub(s.lastAt).Seconds(); dt > 0 {
			s.rateDown = float64(rx-s.lastRx) * 8 / 1000 / dt
			s.rateUp = float64(tx-s.lastTx) * 8 / 1000 / dt
			if rx < s.lastRx || tx < s.lastTx { // counters reset
				s.rateDown, s.rateUp = 0, 0
			}
		}
		s.lastRx, s.lastTx, s.lastAt = rx, tx, now
		down, up := s.ctl.tick(now, s.rateDown, s.rateUp)
		if changed(down, s.setDown) || changed(up, s.setUp) {
			if err := s.sh.setRates(down, up); err != nil {
				logf("SQM: %v", err)
			} else {
				s.setDown, s.setUp = down, up
			}
		}
	}
	return sqmStatus{
		Active:    true,
		Iface:     s.name,
		Download:  s.sh.ingress,
		DownKbit:  math.Round(s.setDown),
		UpKbit:    math.Round(s.setUp),
		RateDown:  math.Round(s.rateDown),
		RateUp:    math.Round(s.rateUp),
		Measuring: measuring,
		OneWay:    s.ctl.owd,
		RTTms:     math.Round(s.ctl.lastRTT*10) / 10,
		DelayMs:   math.Round(s.ctl.dir[dirDown].lastDelay*10) / 10,
		UpDelayMs: math.Round(s.ctl.dir[dirUp].lastDelay*10) / 10,
	}
}

func changed(next, cur float64) bool {
	return math.Abs(next-cur) > cur*sqmMinChange
}

// linkBytes reads a link's received and sent byte counters. Downloads are
// counted on the uplink itself (before the ifb), uploads after shaping.
func linkBytes(name string) (rx, tx uint64) {
	read := func(f string) uint64 {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics", f))
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	return read("rx_bytes"), read("tx_bytes")
}
