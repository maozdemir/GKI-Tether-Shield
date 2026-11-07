//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// inNewNetns runs the test body in a throwaway network namespace, so links
// and tc filters it creates never touch the host.
func inNewNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for network namespaces and tc")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := netns.New()
	if err != nil {
		t.Fatalf("new netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// testNetns returns a netlink handle bound to the test's namespace (call
// after inNewNetns, on the test goroutine).
func testNetns(t *testing.T) *tcNetns {
	t.Helper()
	n, err := currentTCNetns()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.close)
	return n
}

func packetSocket(t *testing.T, ifindex int, sockType int, proto uint16) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, sockType, int(htons(proto)))
	if err != nil {
		t.Fatalf("packet socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifindex, Protocol: htons(proto)}); err != nil {
		t.Fatalf("bind packet socket: %v", err)
	}
	tv := unix.NsecToTimeval(int64(2 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd
}

// readMatching reads from fd until a packet contains marker.
func readMatching(t *testing.T, fd int, marker []byte) []byte {
	t.Helper()
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err != nil {
			continue
		}
		if bytes.Contains(buf[:n], marker) {
			return append([]byte(nil), buf[:n]...)
		}
	}
	t.Fatal("packet never arrived")
	return nil
}

var testMarker = []byte{0xde, 0xad, 0xbe, 0xef}

// markedIPv4 is a TTL-63 IPv4/UDP packet ending with testMarker.
func markedIPv4() []byte {
	p := probeIPv4(63, 5, testSrc4)
	copy(p[len(p)-4:], testMarker)
	return p
}

func startAttacher(t *testing.T) (*ttlProgSet, *tcAttacher) {
	t.Helper()
	p := loadTestPrograms(t, 64)
	a := newTCAttacher(p, testNetns(t))
	if err := a.start(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(a.close)
	return p, a
}

func addVeth(t *testing.T) (netlink.Link, netlink.Link) {
	t.Helper()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "tsv0"}, PeerName: "tsv1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable: %v", err)
	}
	a, _ := netlink.LinkByName("tsv0")
	b, _ := netlink.LinkByName("tsv1")
	for _, l := range []netlink.Link{a, b} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestEBPFAttachRewritesOnEthernetLink(t *testing.T) {
	inNewNetns(t)
	tx, rx := addVeth(t)
	_, a := startAttacher(t)
	if !hasTTLFilter(a.net, tx, a.ids) {
		t.Fatal("filter not attached to tsv0 egress")
	}

	recv := packetSocket(t, rx.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	send := packetSocket(t, tx.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	if _, err := unix.Write(send, ethFrame(0x0800, markedIPv4())); err != nil {
		t.Fatal(err)
	}
	got := readMatching(t, recv, testMarker)
	checkIPv4(t, got[ethHeaderLen:], 64)
}

// openTun creates a raw-IP tun device (no Ethernet header, like cellular
// rmnet / ccmni) and returns its file descriptor.
func openTun(t *testing.T, name string) (int, netlink.Link) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		t.Skipf("tun unavailable: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:], name)
	binary.NativeEndian.PutUint16(req[unix.IFNAMSIZ:], unix.IFF_TUN|unix.IFF_NO_PI)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		t.Fatalf("TUNSETIFF: %v", errno)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	tv := unix.NsecToTimeval(int64(2 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd, l
}

func TestEBPFAttachRewritesOnRawIPLink(t *testing.T) {
	inNewNetns(t)
	tunFD, tun := openTun(t, "tsrmnet0")
	if !rawIPLink(tun) {
		t.Fatalf("tun EncapType %q not treated as raw IP", tun.Attrs().EncapType)
	}
	_, a := startAttacher(t)
	if !hasTTLFilter(a.net, tun, a.ids) {
		t.Fatal("filter not attached to the tun device")
	}

	send := packetSocket(t, tun.Attrs().Index, unix.SOCK_DGRAM, unix.ETH_P_IP)
	if _, err := unix.Write(send, markedIPv4()); err != nil {
		t.Fatal(err)
	}
	// Reading the tun fd returns what the device transmitted.
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(tunFD, buf)
		if err == nil && bytes.Contains(buf[:n], testMarker) {
			checkIPv4(t, buf[:n], 64)
			return
		}
	}
	t.Fatal("packet never left the tun device")
}

func TestEBPFSkipsDownstreamAndReattaches(t *testing.T) {
	inNewNetns(t)
	tx, _ := addVeth(t)
	down := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wlan9"}}
	if err := netlink.LinkAdd(down); err != nil {
		t.Skipf("dummy unavailable: %v", err)
	}
	wlan, _ := netlink.LinkByName("wlan9")
	_ = netlink.LinkSetUp(wlan)

	_, a := startAttacher(t)
	if hasTTLFilter(a.net, wlan, nil) {
		t.Fatal("attached to a downstream (hotspot) interface")
	}

	// Something (e.g. netd) removes the qdisc: the next sync restores us.
	qdiscs, _ := netlink.QdiscList(tx)
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			if err := netlink.QdiscDel(q); err != nil {
				t.Fatal(err)
			}
		}
	}
	if hasTTLFilter(a.net, tx, nil) {
		t.Fatal("filter survived qdisc removal")
	}
	if err := a.sync(); err != nil {
		t.Fatal(err)
	}
	if !hasTTLFilter(a.net, tx, a.ids) {
		t.Fatal("not re-attached after the qdisc was removed")
	}
}

func TestEBPFKeepsForeignFiltersAndDetachesOwn(t *testing.T) {
	inNewNetns(t)
	tx, _ := addVeth(t)
	if err := ensureClsact(testNetns(t), tx); err != nil {
		t.Fatal(err)
	}
	// A filter owned by someone else (netd) on the same hook.
	other := loadTestPrograms(t, 64)
	foreign := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: tx.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS,
			Handle: netlink.MakeHandle(0, 1), Protocol: unix.ETH_P_IPV6, Priority: 4,
		},
		Fd: other.eth.FD(), Name: "netd_prog", DirectAction: true,
	}
	if err := netlink.FilterAdd(foreign); err != nil {
		t.Fatal(err)
	}

	p := loadTestPrograms(t, 64)
	a := newTCAttacher(p, testNetns(t))
	if err := a.start(); err != nil {
		t.Fatal(err)
	}
	a.close()

	filters, _ := netlink.FilterList(tx, netlink.HANDLE_MIN_EGRESS)
	if len(filters) != 1 || filters[0].(*netlink.BpfFilter).Name != "netd_prog" {
		t.Fatalf("after detach, filters = %+v; want only the foreign one", filters)
	}
}

func TestEBPFReplacesStaleFilterFromEarlierDaemon(t *testing.T) {
	inNewNetns(t)
	tx, _ := addVeth(t)
	old := loadTestPrograms(t, 64)
	oldA := newTCAttacher(old, testNetns(t))
	if err := oldA.sync(); err != nil {
		t.Fatal(err)
	}
	// The earlier daemon died without detaching; a new one starts.
	_, a := startAttacher(t)
	if !hasTTLFilter(a.net, tx, a.ids) {
		t.Fatal("stale filter from the earlier program was not replaced")
	}
}

func TestEBPFAttacherSkipsSQMIfb(t *testing.T) {
	inNewNetns(t)
	n := testNetns(t)
	if err := n.nl.LinkAdd(&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: sqmIfbName}}); err != nil {
		t.Fatalf("create ifb: %v", err)
	}
	ifb, err := n.nl.LinkByName(sqmIfbName)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.nl.LinkSetUp(ifb); err != nil {
		t.Fatal(err)
	}
	p, err := loadTTLPrograms(64)
	if err != nil {
		t.Skipf("BPF unavailable: %v", err)
	}
	defer p.Close()
	a := newTCAttacher(p, n)
	_ = a.sync()
	defer a.close()
	if hasTTLFilter(n, ifb, nil) {
		t.Fatal("TTL program attached to the SQM ifb, which carries downloads")
	}
}
