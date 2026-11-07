//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
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
	for _, l := range []netlink.Link{dev, ifb} {
		if probeClassPackets(t, n, l) < 0 {
			t.Fatalf("no probe class on %s", l.Attrs().Name)
		}
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

func TestSQMPingerMeasuresDelayBothWays(t *testing.T) {
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
	for _, mode := range []string{"timestamp", "echo"} {
		if mode == "echo" {
			p.useEcho()
		}
		p.setTargets([]string{"127.0.0.1"})
		if err := p.send(time.Now()); err != nil {
			t.Fatalf("%s: send: %v", mode, err)
		}
		s := pingOnce(t, p)
		if s.reflector != "127.0.0.1" || s.rtt <= 0 || s.rtt > time.Second {
			t.Fatalf("%s: bad sample %+v", mode, s)
		}
		if s.owd != (mode == "timestamp") {
			t.Fatalf("%s: one-way = %v", mode, s.owd)
		}
		if s.owd && (s.up < -time.Second || s.up > time.Second || s.down < -time.Second || s.down > time.Second) {
			t.Fatalf("one-way times off on loopback: %+v", s)
		}
	}
}

func pingOnce(t *testing.T, p *pinger) rttSample {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, ok, err := p.receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if ok {
			return s
		}
	}
	t.Fatal("no reply")
	return rttSample{}
}

func TestSQMMsDiffAcrossMidnight(t *testing.T) {
	if d := msDiff(msPerDay-10, 5); d != 15*time.Millisecond {
		t.Fatalf("msDiff across midnight = %v, want 15ms", d)
	}
	if d := msDiff(5, msPerDay-10); d != -15*time.Millisecond {
		t.Fatalf("msDiff back across midnight = %v, want -15ms", d)
	}
}

// Cellular links are raw IP. Downloads arriving on one must pass the ifb
// and still reach a local socket (bpf_redirect would drop them).
func TestSQMShapesDownloadsOnRawIPLink(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	tunFD, tun := openTun(t, "tsqrmnet0")
	addr, _ := netlink.ParseAddr("10.77.0.1/24")
	if err := n.nl.AddrAdd(tun, addr); err != nil {
		t.Fatal(err)
	}
	s, err := newShaper(n, tun, 20000, 8000, true)
	if err != nil {
		t.Fatalf("newShaper on raw-IP link: %v", err)
	}
	defer s.close()

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sock)
	if err := unix.Bind(sock, &unix.SockaddrInet4{Port: 7451, Addr: [4]byte{10, 77, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	tv := unix.NsecToTimeval(int64(2 * time.Second))
	_ = unix.SetsockoptTimeval(sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	pkt := probeIPv4(64, 5, [4]byte{10, 77, 0, 2})
	copy(pkt[16:20], []byte{10, 77, 0, 1})
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:], ipv4Checksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[20:], 40000)        // UDP source port
	binary.BigEndian.PutUint16(pkt[22:], 7451)         // destination port
	binary.BigEndian.PutUint16(pkt[24:], probePayload) // UDP length; checksum 0
	marker := []byte("rawipsqm")
	copy(pkt[len(pkt)-len(marker):], marker)

	before := ifbTxPackets(t, n)
	if _, err := unix.Write(tunFD, pkt); err != nil { // arrives on the tun
		t.Fatalf("inject: %v", err)
	}
	buf := make([]byte, 2048)
	got, err := unix.Read(sock, buf)
	if err != nil {
		t.Fatalf("download packet never reached the socket: %v", err)
	}
	if !bytes.Contains(buf[:got], marker) {
		t.Fatalf("unexpected payload %q", buf[:got])
	}
	if ifbTxPackets(t, n) == before {
		t.Fatal("download packet bypassed the ifb")
	}

	// An ICMP reply (a delay probe) takes the probe class, ahead of bulk.
	ifb, _ := n.nl.LinkByName(sqmIfbName)
	probesBefore := probeClassPackets(t, n, ifb)
	icmp := probeIPv4(64, 5, [4]byte{10, 77, 0, 2})
	copy(icmp[16:20], []byte{10, 77, 0, 1})
	icmp[9] = 1 // ICMP
	icmp[10], icmp[11] = 0, 0
	binary.BigEndian.PutUint16(icmp[10:], ipv4Checksum(icmp[:20]))
	icmp[20] = 0 // echo reply
	if _, err := unix.Write(tunFD, icmp); err != nil {
		t.Fatalf("inject ICMP: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for probeClassPackets(t, n, ifb) == probesBefore && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if probeClassPackets(t, n, ifb) == probesBefore {
		t.Fatal("ICMP reply did not take the probe class")
	}
}

// probeClassPackets returns the packets sent by l's probe class, or -1 if
// it has none.
func probeClassPackets(t *testing.T, n *tcNetns, l netlink.Link) int64 {
	t.Helper()
	classes, err := n.nl.ClassList(l, netlink.MakeHandle(sqmHandleMajor, 0))
	if err != nil {
		t.Fatalf("list classes: %v", err)
	}
	for _, c := range classes {
		if c.Attrs().Handle != sqmProbeClass {
			continue
		}
		if st := c.Attrs().Statistics; st != nil && st.Basic != nil {
			return int64(st.Basic.Packets)
		}
		return 0
	}
	return -1
}
