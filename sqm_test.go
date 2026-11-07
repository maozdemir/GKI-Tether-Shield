//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sqmVeth creates veth pair tsq0 (the "uplink") / tsq1 (the "tower").
func sqmVeth(t *testing.T, n *tcNetns) (dev, peer netlink.Link) {
	t.Helper()
	if err := n.nl.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "tsq0"}, PeerName: "tsq1"}); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	for _, name := range []string{"tsq0", "tsq1"} {
		l, err := n.nl.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.nl.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	dev, _ = n.nl.LinkByName("tsq0")
	peer, _ = n.nl.LinkByName("tsq1")
	return dev, peer
}

func htbRate(t *testing.T, n *tcNetns, l netlink.Link) uint64 {
	t.Helper()
	classes, err := n.nl.ClassList(l, netlink.MakeHandle(sqmHandleMajor, 0))
	if err != nil {
		t.Fatalf("list classes on %s: %v", l.Attrs().Name, err)
	}
	for _, c := range classes {
		if h, ok := c.(*netlink.HtbClass); ok && c.Attrs().Handle == netlink.MakeHandle(sqmHandleMajor, 1) {
			return h.Rate * 8 // bytes/s -> bit/s
		}
	}
	t.Fatalf("no htb class on %s", l.Attrs().Name)
	return 0
}

func ifbTxPackets(t *testing.T, n *tcNetns) uint64 {
	t.Helper()
	l, err := n.nl.LinkByName(sqmIfbName)
	if err != nil {
		t.Fatalf("ifb: %v", err)
	}
	return l.Attrs().Statistics.TxPackets
}

func TestSQMShaperAttachesShapesAndRemovesCleanly(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	dev, peer := sqmVeth(t, n)

	s, err := newShaper(n, dev, 20000, 8000, true)
	if err != nil {
		t.Fatalf("newShaper: %v", err)
	}
	if !s.intact() {
		t.Fatal("shaper not intact right after setup")
	}
	ifb, _ := n.nl.LinkByName(sqmIfbName)
	if got := htbRate(t, n, dev); got != 8000*1000 {
		t.Fatalf("upload cap = %d bit/s, want 8 Mbit/s", got)
	}
	if got := htbRate(t, n, ifb); got != 20000*1000 {
		t.Fatalf("download cap = %d bit/s, want 20 Mbit/s", got)
	}

	// A packet arriving on the uplink goes through the ifb and still
	// reaches the stack.
	recv := packetSocket(t, dev.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	send := packetSocket(t, peer.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	before := ifbTxPackets(t, n)
	pkt := probeIPv4(64, 5, [4]byte{192, 0, 2, 10})
	marker := []byte("sqmprobe")
	copy(pkt[len(pkt)-len(marker):], marker)
	if _, err := unix.Write(send, ethFrame(0x0800, pkt)); err != nil {
		t.Fatalf("send: %v", err)
	}
	readMatching(t, recv, marker)
	deadline := time.Now().Add(2 * time.Second)
	for ifbTxPackets(t, n) == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ifbTxPackets(t, n) == before {
		t.Fatal("download packet did not pass the ifb")
	}

	if err := s.setRates(150000, 30000); err != nil {
		t.Fatalf("setRates: %v", err)
	}
	if got := htbRate(t, n, dev); got != 30000*1000 {
		t.Fatalf("upload cap after change = %d", got)
	}
	if got := htbRate(t, n, ifb); got != 150000*1000 {
		t.Fatalf("download cap after change = %d", got)
	}

	s.close()
	if hasSQMRoot(n, dev) || hasSQMFilter(n, dev) {
		t.Fatal("shaper left behind on the uplink")
	}
	if _, err := n.nl.LinkByName(sqmIfbName); err == nil {
		t.Fatal("ifb left behind")
	}
}

func TestSQMShaperUploadOnlyLeavesIngressAlone(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	dev, _ := sqmVeth(t, n)
	s, err := newShaper(n, dev, 20000, 8000, false)
	if err != nil {
		t.Fatalf("newShaper: %v", err)
	}
	defer s.close()
	if hasSQMFilter(n, dev) {
		t.Fatal("ingress redirect added although download shaping is off")
	}
	if _, err := n.nl.LinkByName(sqmIfbName); err == nil {
		t.Fatal("ifb created although download shaping is off")
	}
	if !s.intact() {
		t.Fatal("upload-only shaper not intact")
	}
}

func TestSQMIntactNoticesRemovedRoot(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	dev, _ := sqmVeth(t, n)
	s, err := newShaper(n, dev, 20000, 8000, true)
	if err != nil {
		t.Fatalf("newShaper: %v", err)
	}
	defer s.close()
	// What service.sh's "tc qdisc del root" or another tool would do.
	if err := n.nl.QdiscDel(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: dev.Attrs().Index, Handle: netlink.MakeHandle(sqmHandleMajor, 0), Parent: netlink.HANDLE_ROOT,
	}, QdiscType: "htb"}); err != nil {
		t.Fatal(err)
	}
	if s.intact() {
		t.Fatal("intact() missed the removed root qdisc")
	}
}

func TestSQMRemoveAllCleansLeftovers(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	dev, _ := sqmVeth(t, n)
	if _, err := newShaper(n, dev, 20000, 8000, true); err != nil {
		t.Fatalf("newShaper: %v", err)
	}
	// The daemon was killed: nothing closed the shaper.
	removeAllSQM(n)
	if hasSQMRoot(n, dev) || hasSQMFilter(n, dev) {
		t.Fatal("leftover shaper not removed")
	}
	if _, err := n.nl.LinkByName(sqmIfbName); err == nil {
		t.Fatal("leftover ifb not removed")
	}
}

func TestSQMPingerMeasuresRTT(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	lo, err := n.nl.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.nl.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	p, err := newPinger("lo", false)
	if err != nil {
		t.Fatalf("newPinger: %v", err)
	}
	defer p.close()
	p.targets = p.targets[:0]
	p.targets = append(p.targets, []byte{127, 0, 0, 1})
	if err := p.send(time.Now()); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, ok, err := p.receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if ok {
			if s.reflector != "127.0.0.1" || s.rtt <= 0 || s.rtt > time.Second {
				t.Fatalf("bad sample %+v", s)
			}
			return
		}
	}
	t.Fatal("no echo reply")
}
