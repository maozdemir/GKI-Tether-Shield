//go:build linux

package main

import (
	"testing"
	"time"
)

// feed sends n RTT samples of rtt, 100 ms apart, starting at *now.
func feed(a *autorate, now *time.Time, n int, rtt time.Duration) {
	for i := 0; i < n; i++ {
		*now = now.Add(100 * time.Millisecond)
		a.observe(*now, "r", rtt)
	}
}

func TestAutorateRisesWhileBusyAndPingStaysLow(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	start := a.down()
	for i := 0; i < 20; i++ {
		feed(a, &now, 2, 50*time.Millisecond)
		a.tick(now, a.down()*0.9, 500) // download fills the cap
	}
	if a.down() <= start*2 {
		t.Fatalf("down cap = %.0f, want well above %.0f", a.down(), start)
	}
	if a.up() != defaultAutorateConfig.up.base {
		t.Fatalf("upload cap moved to %.0f with no upload", a.up())
	}
}

func TestAutorateCutsBelowAchievedRateOnBloat(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate = 100000
	now := time.Unix(0, 0)
	feed(a, &now, 6, 50*time.Millisecond) // learn the baseline
	feed(a, &now, 4, 150*time.Millisecond)
	down, up := a.tick(now, 40000, 900) // link really does 40 Mbit/s
	if want := 40000 * 0.9; down != want {
		t.Fatalf("down cap = %.0f, want %.0f", down, want)
	}
	if up != defaultAutorateConfig.up.base {
		t.Fatalf("upload cap cut to %.0f although it only carried ACKs", up)
	}
	// Refractory: no further change while the queue drains.
	feed(a, &now, 4, 150*time.Millisecond)
	if d, _ := a.tick(now.Add(100*time.Millisecond), 30000, 900); d != down {
		t.Fatalf("cap changed during refractory: %.0f -> %.0f", down, d)
	}
}

func TestAutorateCutsUploadWhenUploadIsBusy(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	feed(a, &now, 6, 40*time.Millisecond)
	feed(a, &now, 3, 200*time.Millisecond)
	down, up := a.tick(now, 1500, 7000)
	if up != 7000*0.9 {
		t.Fatalf("up cap = %.0f, want %.0f", up, 7000*0.9)
	}
	if down != defaultAutorateConfig.down.base {
		t.Fatalf("down cap = %.0f, want unchanged", down)
	}
}

func TestAutorateIgnoresJitterBelowThreshold(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	feed(a, &now, 6, 50*time.Millisecond)
	for i := 0; i < 10; i++ {
		feed(a, &now, 1, 70*time.Millisecond) // +20 ms: normal cellular jitter
		feed(a, &now, 1, 50*time.Millisecond)
		a.tick(now, a.down()*0.9, 500)
	}
	if a.down() <= defaultAutorateConfig.down.base {
		t.Fatalf("jitter cut the cap to %.0f", a.down())
	}
}

func TestAutorateNeedsSeveralBloatedSamples(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	feed(a, &now, 6, 50*time.Millisecond)
	feed(a, &now, 2, 200*time.Millisecond) // a single spike, 2 of 6
	before := a.down()
	if d, _ := a.tick(now, before*0.9, 500); d < before {
		t.Fatalf("one spike cut the cap from %.0f to %.0f", before, d)
	}
}

func TestAutorateKeepsLearnedCapWhenIdle(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate, a.dir[dirUp].rate = 500000, 1500
	now := time.Unix(0, 0)
	for i := 0; i < 500; i++ {
		now = now.Add(200 * time.Millisecond)
		a.tick(now, 10, 10)
	}
	if a.down() != 500000 {
		t.Fatalf("idle down cap = %.0f, want the learned 500000 kept", a.down())
	}
}

func TestAutorateRecoversToBaseWhenIdle(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate, a.dir[dirUp].rate = 2000, 1500
	now := time.Unix(0, 0)
	for i := 0; i < 500; i++ {
		now = now.Add(200 * time.Millisecond)
		a.tick(now, 10, 10)
	}
	if d := a.down() - defaultAutorateConfig.down.base; d > 100 || d < -100 {
		t.Fatalf("idle down cap = %.0f, want about %.0f", a.down(), defaultAutorateConfig.down.base)
	}
	if d := a.up() - defaultAutorateConfig.up.base; d > 100 || d < -100 {
		t.Fatalf("idle up cap = %.0f, want about %.0f", a.up(), defaultAutorateConfig.up.base)
	}
}

func TestAutorateHoldsWithoutRecentSamples(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	feed(a, &now, 6, 50*time.Millisecond)
	before := a.down()
	// Reflectors stopped answering: don't guess.
	if d, _ := a.tick(now.Add(5*time.Second), before*0.9, 500); d != before {
		t.Fatalf("cap moved without RTT samples: %.0f -> %.0f", before, d)
	}
}

func TestAutorateStaysWithinLimits(t *testing.T) {
	cfg := defaultAutorateConfig
	a := newAutorate(cfg)
	now := time.Unix(0, 0)
	feed(a, &now, 6, 50*time.Millisecond)
	for i := 0; i < 50; i++ {
		feed(a, &now, 6, 500*time.Millisecond)
		now = now.Add(2 * time.Second)
		a.tick(now, 1200, 1100)
	}
	if a.down() < cfg.down.min || a.up() < cfg.up.min {
		t.Fatalf("caps fell below the minimum: %.0f / %.0f", a.down(), a.up())
	}
	a = newAutorate(cfg)
	for i := 0; i < 1000; i++ {
		feed(a, &now, 2, 50*time.Millisecond)
		a.tick(now, a.down(), a.up())
	}
	if a.down() > cfg.down.max || a.up() > cfg.up.max {
		t.Fatalf("caps rose above the maximum: %.0f / %.0f", a.down(), a.up())
	}
}

func TestAutorateBaselineIsPerReflector(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	for i := 0; i < 6; i++ {
		now = now.Add(100 * time.Millisecond)
		a.observe(now, "near", 30*time.Millisecond)
		a.observe(now, "far", 120*time.Millisecond)
	}
	if a.dir[dirDown].bloated(a.cfg.bloatSamples) || a.dir[dirUp].bloated(a.cfg.bloatSamples) {
		t.Fatal("a farther reflector counted as bufferbloat")
	}
}

func TestAutorateLiftsCapsWhenPingsAreBlocked(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(100, 0)
	for i := 0; i < 60; i++ { // 12 s busy, no RTT sample at all
		now = now.Add(200 * time.Millisecond)
		a.tick(now, 15000, 2000)
	}
	if a.down() != defaultAutorateConfig.down.max || a.up() != defaultAutorateConfig.up.max {
		t.Fatalf("caps = %.0f / %.0f, want the maximum when nothing answers", a.down(), a.up())
	}
}

// Seen on a real phone: a background upload filled the modem while the
// upload cap sat far above what the link can send, so the upload never
// looked "full". Both directions must be cut.
func TestAutorateCutsAnUploadWhoseCapIsTooHigh(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate, a.dir[dirUp].rate = 30000, 62000
	now := time.Unix(0, 0)
	feed(a, &now, 6, 55*time.Millisecond)
	feed(a, &now, 4, 95*time.Millisecond)
	down, up := a.tick(now, 27000, 35000)
	if up != 35000*0.9 {
		t.Fatalf("up cap = %.0f, want %.0f", up, 35000*0.9)
	}
	if down != 27000*0.9 {
		t.Fatalf("down cap = %.0f, want %.0f", down, 27000*0.9)
	}
}

// sendOWD feeds n one-way samples: up and down one-way times (the clock
// offset of 200 ms mimics a real reflector).
func feedOWD(a *autorate, now *time.Time, n int, up, down time.Duration) {
	const offset = 200 * time.Millisecond
	for i := 0; i < n; i++ {
		*now = now.Add(100 * time.Millisecond)
		a.observeOWD(*now, "r", up+down, up+offset, down-offset)
	}
}

// With one-way delay, a bloated upload is cut and the download is left
// alone even while both are busy: the A/B case seen on a real phone.
func TestAutorateOneWayCutsOnlyTheBloatedDirection(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate, a.dir[dirUp].rate = 80000, 62000
	now := time.Unix(0, 0)
	feedOWD(a, &now, 6, 25*time.Millisecond, 30*time.Millisecond)
	feedOWD(a, &now, 4, 80*time.Millisecond, 30*time.Millisecond)
	down, up := a.tick(now, 75000, 35000)
	if up != 35000*0.9 {
		t.Fatalf("up cap = %.0f, want %.0f", up, 35000*0.9)
	}
	if down < 80000 {
		t.Fatalf("download cut to %.0f although only the upload queued", down)
	}
}

func TestAutorateOneWayCutsBloatedDownload(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate = 100000
	now := time.Unix(0, 0)
	feedOWD(a, &now, 6, 25*time.Millisecond, 30*time.Millisecond)
	feedOWD(a, &now, 4, 25*time.Millisecond, 90*time.Millisecond)
	down, up := a.tick(now, 60000, 1500)
	if down != 60000*0.9 {
		t.Fatalf("down cap = %.0f, want %.0f", down, 60000*0.9)
	}
	if up != defaultAutorateConfig.up.base {
		t.Fatalf("up cap = %.0f, want unchanged", up)
	}
}

// A clock step on the phone shifts both one-way times in opposite
// directions while the round trip stays the same: not bufferbloat.
func TestAutorateOneWayIgnoresClockSteps(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	now := time.Unix(0, 0)
	feedOWD(a, &now, 6, 25*time.Millisecond, 30*time.Millisecond)
	for i := 0; i < 6; i++ {
		now = now.Add(100 * time.Millisecond)
		// The phone's clock jumped 500 ms: up looks 500 ms longer, down
		// 500 ms shorter; the round trip is unchanged.
		a.observeOWD(now, "r", 55*time.Millisecond, 725*time.Millisecond, -670*time.Millisecond)
	}
	before := a.up()
	if _, up := a.tick(now, 1500, 7500); up < before {
		t.Fatalf("clock step cut the upload cap from %.0f to %.0f", before, up)
	}
}

// A one-tick dip in achieved rate (TCP recovering from a loss) must not
// drag the cap down with it: a cut goes below the best recent rate.
func TestAutorateCutIgnoresOneTickDip(t *testing.T) {
	a := newAutorate(defaultAutorateConfig)
	a.dir[dirDown].rate = 40000
	now := time.Unix(0, 0)
	feedOWD(a, &now, 6, 25*time.Millisecond, 30*time.Millisecond)
	for i := 0; i < 4; i++ {
		feedOWD(a, &now, 1, 25*time.Millisecond, 30*time.Millisecond)
		a.tick(now, 36000, 1500)
	}
	feedOWD(a, &now, 4, 25*time.Millisecond, 90*time.Millisecond)
	down, _ := a.tick(now, 900, 1500) // this tick's rate dipped to 0.9 Mbit/s
	if down < 30000 {
		t.Fatalf("cap cut to %.0f after a one-tick dip, want about 0.9 x 36 Mbit/s", down)
	}
}
