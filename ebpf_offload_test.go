//go:build linux

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Android's tethering BPF offload forwards hotspot traffic with a tc ingress
// program on the downstream interface that bpf_redirect()s each packet to the
// upstream's egress, skipping iptables (and so NFQUEUE). These tests mimic
// that path to prove the TTL program on the upstream egress still sees those
// packets.

// offloadRedirect loads a tc program that sends every packet to ifindex's
// egress, as the tethering offload program does.
func offloadRedirect(t *testing.T, ifindex int) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R1, int32(ifindex)),
			asm.Mov.Imm(asm.R2, 0), // egress
			asm.FnRedirect.Call(),
			asm.Return(),
		},
	})
	if err != nil {
		t.Skipf("redirect program unavailable: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

// addHotspotPair creates wlan8 (the client's side) and wlan7 (the phone's
// hotspot interface). Both match the downstream patterns, so the TTL program
// is never attached to them: only the redirect target can fix the TTL.
func addHotspotPair(t *testing.T) (client, hotspot netlink.Link) {
	t.Helper()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "wlan7"}, PeerName: "wlan8"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("veth unavailable: %v", err)
	}
	hotspot, _ = netlink.LinkByName("wlan7")
	client, _ = netlink.LinkByName("wlan8")
	for _, l := range []netlink.Link{hotspot, client} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	return client, hotspot
}

// offloadTo makes hotspot's ingress redirect everything to upstream.
func offloadTo(t *testing.T, n *tcNetns, hotspot, upstream netlink.Link) {
	t.Helper()
	if err := ensureClsact(n, hotspot); err != nil {
		t.Fatal(err)
	}
	prog := offloadRedirect(t, upstream.Attrs().Index)
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hotspot.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS,
			Handle: netlink.MakeHandle(0, 1), Protocol: unix.ETH_P_ALL, Priority: 1,
		},
		Fd: prog.FD(), Name: "tether_offload", DirectAction: true,
	}
	if err := n.nl.FilterAdd(f); err != nil {
		t.Fatalf("attach offload program: %v", err)
	}
}

// sendFromClient sends a forwarded-looking packet (TTL 63) from the hotspot
// client into the phone's hotspot interface.
func sendFromClient(t *testing.T, client netlink.Link) {
	t.Helper()
	fd := packetSocket(t, client.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	if _, err := unix.Write(fd, ethFrame(0x0800, markedIPv4())); err != nil {
		t.Fatal(err)
	}
}

func TestEBPFFixesOffloadedPacketsOnEthernetUpstream(t *testing.T) {
	inNewNetns(t)
	client, hotspot := addHotspotPair(t)
	up, upPeer := addVeth(t)
	_, a := startAttacher(t)
	if hasTTLFilter(a.net, hotspot, nil) || !hasTTLFilter(a.net, up, a.ids) {
		t.Fatal("TTL program must be on the upstream only")
	}
	offloadTo(t, a.net, hotspot, up)

	recv := packetSocket(t, upPeer.Attrs().Index, unix.SOCK_RAW, unix.ETH_P_ALL)
	sendFromClient(t, client)
	got := readMatching(t, recv, testMarker)
	checkIPv4(t, got[ethHeaderLen:], 64)
}

func TestEBPFFixesOffloadedPacketsOnRawIPUpstream(t *testing.T) {
	inNewNetns(t)
	client, hotspot := addHotspotPair(t)
	tunFD, tun := openTun(t, "tsrmnet1")
	_, a := startAttacher(t)
	if !hasTTLFilter(a.net, tun, a.ids) {
		t.Fatal("TTL program not on the raw-IP upstream")
	}
	// The kernel strips the Ethernet header when redirecting to a device
	// without one, as for rmnet behind the real offload program.
	offloadTo(t, a.net, hotspot, tun)

	sendFromClient(t, client)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(tunFD, buf)
		if err == nil && bytes.Contains(buf[:n], testMarker) {
			checkIPv4(t, buf[:n], 64)
			return
		}
	}
	t.Fatal("offloaded packet never left the raw-IP upstream")
}
