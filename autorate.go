//go:build linux

package main

import "time"

// Auto-adjusting bufferbloat control (SQM autorate), in the spirit of
// OpenWrt's cake-autorate. On mobile data the queue that causes lag sits in
// the modem and at the carrier's tower, where the phone can't manage it. So
// the shaper caps the speed just below what the link delivers right now:
// then the queue forms on the phone, where fq_codel keeps it short.
//
// The link's speed keeps changing, so each direction's cap follows it:
//   - while the direction is busy and its delay stays low, the cap rises;
//   - when its delay rises under load (the queue moved past the phone), the
//     cap drops below the speed actually achieved;
//   - while idle, the cap keeps what it learned (so the next download and
//     a quick speed test start at full speed); a cap cut below the middle
//     value drifts back up to it.
//
// Delay is measured one way where possible (ICMP timestamps: upload and
// download delay separately), so a busy upload doesn't throttle downloads.
// With round-trip pings only, a rise can't be pinned on one direction; then
// every direction carrying a real share of the load is cut.
//
// Rates are in kbit/s, delays in ms. This file is pure logic; sqm_engine.go
// feeds it.

type rateLimits struct {
	min, base, max float64
}

type autorateConfig struct {
	down, up rateLimits
	// delayThreshold is how far above its baseline a delay sample must be
	// to count as bufferbloat. Cellular delay jitters a lot, hence 30 ms
	// (round trip; one-way samples use half).
	delayThreshold time.Duration
	// bloatSamples of the last bloatWindow samples must be over the
	// threshold for a direction to count as bloated.
	bloatSamples, bloatWindow int
	// activeKbit is the traffic (either direction) above which the link
	// counts as in use. Below it the controller stops measuring.
	activeKbit float64
	// loadHigh is the share of the cap that counts as "using the cap".
	loadHigh float64
	// cutShare (round-trip mode): on bufferbloat, a direction whose load
	// is at least this fraction of the busiest direction's is cut too.
	cutShare float64
	// increase multiplies a busy, unbloated cap each tick; decrease
	// multiplies the achieved rate when bloated; idleDecay is the share of
	// the distance up to base covered per idle tick.
	increase, decrease, idleDecay float64
	// refractory is the pause after a decrease before the next change, so
	// the queue can drain before its delay is judged again.
	refractory time.Duration
	// sampleMaxAge: with no delay sample this recent, nothing is judged.
	sampleMaxAge time.Duration
	// giveUp: busy this long without any recent delay sample (pings
	// blocked), the caps go to the maximum: shaping blind would only cost
	// speed.
	giveUp time.Duration
}

var defaultAutorateConfig = autorateConfig{
	down:           rateLimits{min: 2000, base: 20000, max: 1000000},
	up:             rateLimits{min: 2000, base: 8000, max: 300000},
	delayThreshold: 30 * time.Millisecond,
	bloatSamples:   3,
	bloatWindow:    6,
	activeKbit:     1000,
	loadHigh:       0.75,
	cutShare:       0.5,
	increase:       1.05,
	decrease:       0.9,
	idleDecay:      0.02,
	refractory:     1 * time.Second,
	sampleMaxAge:   2 * time.Second,
	giveUp:         10 * time.Second,
}

// Baseline tracking: a lower delay is believed quickly, a higher one slowly
// (and only when it isn't bloat), so the baseline follows the idle delay.
const (
	baselineDown = 0.9
	baselineUp   = 0.001
)

const (
	dirDown = 0
	dirUp   = 1
)

// achievedWindow is how many ticks of achieved rate a cut looks back over:
// a cut goes below the best of them, so one tick's dip (TCP recovering from
// a loss) doesn't drag the cap down with it.
const achievedWindow = 5

type direction struct {
	lim       rateLimits
	rate      float64
	achieved  []float64 // recent achieved rates, newest last
	window    []bool    // recent samples: over the threshold?
	holdUntil time.Time
	lastDelay float64
}

type reflectorBase struct {
	rtt    float64
	owd    [2]float64
	hasOWD bool
}

type autorate struct {
	cfg        autorateConfig
	dir        [2]direction
	owd        bool // latest sample was one-way
	baselines  map[string]*reflectorBase
	lastSample time.Time
	lastRTT    float64
	busySince  time.Time // zero while idle
}

func newAutorate(cfg autorateConfig) *autorate {
	a := &autorate{cfg: cfg, baselines: map[string]*reflectorBase{}}
	a.dir[dirDown] = direction{lim: cfg.down, rate: cfg.down.base}
	a.dir[dirUp] = direction{lim: cfg.up, rate: cfg.up.base}
	return a
}

func (a *autorate) down() float64 { return a.dir[dirDown].rate }
func (a *autorate) up() float64   { return a.dir[dirUp].rate }

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// track updates a baseline with sample v and returns v's delay above it.
func track(base *float64, v, threshold float64) float64 {
	delay := v - *base
	switch {
	case delay < 0:
		*base += (v - *base) * baselineDown
	case delay <= threshold:
		*base += (v - *base) * baselineUp
	}
	return delay
}

func (a *autorate) reflector(name string, rtt float64) *reflectorBase {
	r, ok := a.baselines[name]
	if !ok {
		r = &reflectorBase{rtt: rtt}
		a.baselines[name] = r
	}
	return r
}

// observe records a round-trip sample to reflector: both directions get
// the same verdict.
func (a *autorate) observe(now time.Time, reflector string, rtt time.Duration) {
	v := ms(rtt)
	r := a.reflector(reflector, v)
	delay := track(&r.rtt, v, ms(a.cfg.delayThreshold))
	bloated := delay > ms(a.cfg.delayThreshold)
	a.record(dirDown, bloated, delay)
	a.record(dirUp, bloated, delay)
	a.owd = false
	a.lastSample, a.lastRTT = now, v
}

// observeOWD records a one-way sample: up and down are the measured
// one-way times (each including the unknown clock offset to the
// reflector, which the baselines absorb).
func (a *autorate) observeOWD(now time.Time, reflector string, rtt, up, down time.Duration) {
	v, u, d := ms(rtt), ms(up), ms(down)
	r := a.reflector(reflector, v)
	if !r.hasOWD {
		r.owd, r.hasOWD = [2]float64{d, u}, true
	}
	half := ms(a.cfg.delayThreshold) / 2
	rttDelay := track(&r.rtt, v, ms(a.cfg.delayThreshold))
	dDelay := track(&r.owd[dirDown], d, half)
	uDelay := track(&r.owd[dirUp], u, half)
	// One way "rose" but the round trip didn't: the phone's clock was
	// adjusted, not a queue. Start the one-way baselines over.
	if (dDelay > half || uDelay > half) && rttDelay < half/2 {
		r.owd = [2]float64{d, u}
		dDelay, uDelay = 0, 0
	}
	a.record(dirDown, dDelay > half, dDelay)
	a.record(dirUp, uDelay > half, uDelay)
	a.owd = true
	a.lastSample, a.lastRTT = now, v
}

func (a *autorate) record(i int, bloated bool, delay float64) {
	d := &a.dir[i]
	d.window = append(d.window, bloated)
	if len(d.window) > a.cfg.bloatWindow {
		d.window = d.window[len(d.window)-a.cfg.bloatWindow:]
	}
	d.lastDelay = max(delay, 0)
}

func (d *direction) bloated(need int) bool {
	n := 0
	for _, b := range d.window {
		if b {
			n++
		}
	}
	return n >= need
}

// active reports whether the link carries enough traffic to be measured.
func (a *autorate) active(downKbit, upKbit float64) bool {
	return downKbit > a.cfg.activeKbit || upKbit > a.cfg.activeKbit
}

// tick updates the caps from the rates achieved since the last tick and
// returns them.
func (a *autorate) tick(now time.Time, downKbit, upKbit float64) (down, up float64) {
	achieved := [2]float64{downKbit, upKbit}
	if !a.active(downKbit, upKbit) {
		for i := range a.dir {
			d := &a.dir[i]
			if d.rate < d.lim.base {
				d.rate += (d.lim.base - d.rate) * a.cfg.idleDecay
			}
			d.window = d.window[:0]
			d.achieved = d.achieved[:0]
		}
		a.busySince = time.Time{}
		return a.down(), a.up()
	}
	if a.busySince.IsZero() {
		a.busySince = now
	}
	if now.Sub(a.busySince) >= a.cfg.giveUp && now.Sub(a.lastSample) >= a.cfg.giveUp {
		for i := range a.dir {
			a.dir[i].rate = a.dir[i].lim.max
		}
		return a.down(), a.up()
	}
	if now.Sub(a.lastSample) > a.cfg.sampleMaxAge {
		return a.down(), a.up()
	}

	var load [2]float64
	var bloated [2]bool
	for i := range a.dir {
		d := &a.dir[i]
		d.achieved = append(d.achieved, achieved[i])
		if len(d.achieved) > achievedWindow {
			d.achieved = d.achieved[len(d.achieved)-achievedWindow:]
		}
		load[i] = achieved[i] / a.dir[i].rate
		bloated[i] = a.dir[i].bloated(a.cfg.bloatSamples)
	}
	// Round trip: one verdict for both directions, so while it says
	// bloated, nothing rises.
	holdRise := !a.owd && (bloated[dirDown] || bloated[dirUp])
	if holdRise {
		// Round trip only: cut every direction carrying a real share of
		// its cap, at least cutShare of the busiest one's. A cap set far
		// above what the link can carry is never "full", yet that
		// direction may be the one filling the modem. A direction that
		// only carries ACKs stays: cutting it would throttle the other.
		busiest := max(load[dirDown], load[dirUp])
		for i := range bloated {
			bloated[i] = load[i] >= busiest*a.cfg.cutShare
		}
	}
	cutAny := false
	for i := range a.dir {
		d := &a.dir[i]
		if now.Before(d.holdUntil) {
			continue
		}
		switch {
		case bloated[i] && achieved[i] > a.cfg.activeKbit:
			best := 0.0
			for _, r := range d.achieved {
				best = max(best, r)
			}
			d.rate = clampRate(min(d.rate, best)*a.cfg.decrease, d.lim)
			d.holdUntil = now.Add(a.cfg.refractory)
			d.window = d.window[:0]
			cutAny = true
		case !bloated[i] && !holdRise && load[i] >= a.cfg.loadHigh:
			d.rate = clampRate(d.rate*a.cfg.increase, d.lim)
		}
	}
	if cutAny && !a.owd {
		// One verdict covered both directions: judge afresh.
		for i := range a.dir {
			a.dir[i].window = a.dir[i].window[:0]
		}
	}
	return a.down(), a.up()
}

func clampRate(rate float64, l rateLimits) float64 {
	return min(max(rate, l.min), l.max)
}
