//go:build linux

package main

import "time"

// Auto-adjusting bufferbloat control (SQM autorate), in the spirit of
// OpenWrt's cake-autorate. On mobile data the queue that causes lag sits in
// the modem and at the carrier's tower, where the phone can't manage it. So
// the shaper caps the speed just below what the link delivers right now:
// then the queue forms on the phone, where fq_codel keeps it short.
//
// The link's speed keeps changing, so the cap follows it:
//   - while the link is busy and ping stays low, the cap rises;
//   - when ping rises under load (the queue moved past the phone), the cap
//     drops below the speed actually achieved;
//   - while idle, the cap keeps what it learned (so the next download and
//     a quick speed test start at full speed); a cap cut below the middle
//     value drifts back up to it.
//
// Rates are in kbit/s. This file is pure logic; sqm_engine.go feeds it.

type rateLimits struct {
	min, base, max float64
}

type autorateConfig struct {
	down, up rateLimits
	// delayThreshold is how far above its baseline an RTT sample must be
	// to count as bufferbloat. Cellular RTT jitters a lot, hence 30 ms.
	delayThreshold time.Duration
	// bloatSamples of the last bloatWindow samples must be over the
	// threshold for the link to count as bloated.
	bloatSamples, bloatWindow int
	// activeKbit is the traffic (either direction) above which the link
	// counts as in use. Below it the controller stops measuring.
	activeKbit float64
	// loadHigh is the share of the cap that counts as "using the cap".
	loadHigh float64
	// increase multiplies a busy, unbloated cap each tick; decrease
	// multiplies the achieved rate when bloated; idleDecay is the share of
	// the distance up to base covered per idle tick (a cap above base is
	// kept while idle).
	increase, decrease, idleDecay float64
	// refractory is the pause after a decrease before the next change, so
	// the queue can drain before its delay is judged again.
	refractory time.Duration
	// sampleMaxAge: with no RTT sample this recent, nothing is judged.
	sampleMaxAge time.Duration
	// giveUp: busy this long without any recent RTT sample (pings
	// blocked), the caps go to the maximum: shaping blind would only cost
	// speed.
	giveUp time.Duration
}

var defaultAutorateConfig = autorateConfig{
	down:           rateLimits{min: 2000, base: 20000, max: 1000000},
	up:             rateLimits{min: 1000, base: 8000, max: 300000},
	delayThreshold: 30 * time.Millisecond,
	bloatSamples:   3,
	bloatWindow:    6,
	activeKbit:     1000,
	loadHigh:       0.75,
	increase:       1.05,
	decrease:       0.9,
	idleDecay:      0.02,
	refractory:     1 * time.Second,
	sampleMaxAge:   2 * time.Second,
	giveUp:         10 * time.Second,
}

// Baseline tracking: a lower RTT is believed quickly, a higher one slowly
// (and only when it isn't bloat), so the baseline follows the idle RTT.
const (
	baselineDown = 0.9
	baselineUp   = 0.001
)

type autorate struct {
	cfg      autorateConfig
	down, up float64 // current caps

	baselines  map[string]float64 // per reflector, in ms
	window     []bool             // recent samples: over the threshold?
	lastSample time.Time
	lastDelay  float64 // ms above baseline, latest sample
	lastRTT    float64 // ms, latest sample
	holdUntil  time.Time
	busySince  time.Time // zero while idle
}

func newAutorate(cfg autorateConfig) *autorate {
	return &autorate{
		cfg:       cfg,
		down:      cfg.down.base,
		up:        cfg.up.base,
		baselines: map[string]float64{},
	}
}

// observe records one RTT sample to reflector.
func (a *autorate) observe(now time.Time, reflector string, rtt time.Duration) {
	ms := float64(rtt) / float64(time.Millisecond)
	base, ok := a.baselines[reflector]
	if !ok {
		base = ms
	}
	delay := ms - base
	bloated := delay > float64(a.cfg.delayThreshold)/float64(time.Millisecond)
	switch {
	case delay < 0:
		base += (ms - base) * baselineDown
	case !bloated:
		base += (ms - base) * baselineUp
	}
	a.baselines[reflector] = base

	a.window = append(a.window, bloated)
	if len(a.window) > a.cfg.bloatWindow {
		a.window = a.window[len(a.window)-a.cfg.bloatWindow:]
	}
	a.lastSample = now
	a.lastDelay = max(delay, 0)
	a.lastRTT = ms
}

func (a *autorate) bloated() bool {
	n := 0
	for _, b := range a.window {
		if b {
			n++
		}
	}
	return n >= a.cfg.bloatSamples
}

// active reports whether the link carries enough traffic to be measured.
func (a *autorate) active(downKbit, upKbit float64) bool {
	return downKbit > a.cfg.activeKbit || upKbit > a.cfg.activeKbit
}

// tick updates the caps from the rates achieved since the last tick and
// returns them.
func (a *autorate) tick(now time.Time, downKbit, upKbit float64) (down, up float64) {
	if !a.active(downKbit, upKbit) {
		a.down = a.decay(a.down, a.cfg.down)
		a.up = a.decay(a.up, a.cfg.up)
		a.window = a.window[:0]
		a.busySince = time.Time{}
		return a.down, a.up
	}
	if a.busySince.IsZero() {
		a.busySince = now
	}
	if now.Sub(a.busySince) >= a.cfg.giveUp && now.Sub(a.lastSample) >= a.cfg.giveUp {
		a.down, a.up = a.cfg.down.max, a.cfg.up.max
		return a.down, a.up
	}
	if now.Before(a.holdUntil) || now.Sub(a.lastSample) > a.cfg.sampleMaxAge {
		return a.down, a.up
	}
	loadDown, loadUp := downKbit/a.down, upKbit/a.up
	if a.bloated() {
		// RTT can't say which direction is queued: cut the busiest one,
		// and the other only if it is also using its cap. Cutting a
		// direction that only carries ACKs would throttle the other.
		cutDown := loadDown >= loadUp || loadDown >= a.cfg.loadHigh
		cutUp := loadUp >= loadDown || loadUp >= a.cfg.loadHigh
		if cutDown && downKbit > a.cfg.activeKbit {
			a.down = clampRate(min(a.down, downKbit)*a.cfg.decrease, a.cfg.down)
		}
		if cutUp && upKbit > a.cfg.activeKbit {
			a.up = clampRate(min(a.up, upKbit)*a.cfg.decrease, a.cfg.up)
		}
		a.window = a.window[:0]
		a.holdUntil = now.Add(a.cfg.refractory)
		return a.down, a.up
	}
	if loadDown >= a.cfg.loadHigh {
		a.down = clampRate(a.down*a.cfg.increase, a.cfg.down)
	}
	if loadUp >= a.cfg.loadHigh {
		a.up = clampRate(a.up*a.cfg.increase, a.cfg.up)
	}
	return a.down, a.up
}

func (a *autorate) decay(rate float64, l rateLimits) float64 {
	if rate >= l.base {
		return rate
	}
	return rate + (l.base-rate)*a.cfg.idleDecay
}

func clampRate(rate float64, l rateLimits) float64 {
	return min(max(rate, l.min), l.max)
}
