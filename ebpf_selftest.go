//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The eBPF self-test tells the installer whether this phone can run the
// eBPF TTL engine. It never touches the real network: packets are checked
// with the kernel's test runner, and attaching happens on a veth pair in a
// throwaway network namespace that disappears with the test's thread.
//
//	tether_shield ebpf-selftest   exit 0 and "ok", or exit 1 and the reason

const (
	selfTestTimeout = 10 * time.Second
	selfTestTarget  = 64
)

// tcActUnspec is TC_ACT_UNSPEC (-1) as the program's return value.
const tcActUnspec = 0xffffffff

// probePayload is the UDP header plus payload size of probe packets. It
// keeps packets complete even when the kernel's test runner strips an
// assumed Ethernet header from a raw-IP packet: newer kernels refuse a
// truncated IP packet there with EINVAL before running the program.
const probePayload = 8 + 40

var probeMarker = []byte{0x74, 0x73, 0x68, 0x64} // "tshd"

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// probeIPv4 builds an IPv4/UDP packet with a valid header checksum. ihl is
// the header length in 32-bit words (5 = no options).
func probeIPv4(ttl uint8, ihl int, src [4]byte) []byte {
	hlen := ihl * 4
	p := make([]byte, hlen+probePayload)
	p[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = ttl
	p[9] = 17 // UDP
	copy(p[12:16], src[:])
	copy(p[16:20], []byte{198, 51, 100, 7})
	for i := 20; i < hlen; i++ {
		p[i] = 1 // NOP options
	}
	binary.BigEndian.PutUint16(p[10:], ipv4Checksum(p[:hlen]))
	return p
}

func probeIPv6(hlim uint8, src [16]byte) []byte {
	p := make([]byte, 40+probePayload)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], probePayload)
	p[6] = 17
	p[7] = hlim
	copy(p[8:24], src[:])
	p[39] = 1
	return p
}

func ethFrame(ethertype uint16, payload []byte) []byte {
	f := make([]byte, ethHeaderLen, ethHeaderLen+len(payload))
	copy(f[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(f[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(f[12:], ethertype)
	return append(f, payload...)
}

// verifyIPv4 checks an IPv4 header's TTL and checksum.
func verifyIPv4(ip []byte, wantTTL uint8) error {
	if len(ip) < 20 {
		return fmt.Errorf("IPv4 packet too short (%d bytes)", len(ip))
	}
	if ip[8] != wantTTL {
		return fmt.Errorf("TTL = %d, want %d", ip[8], wantTTL)
	}
	hlen := int(ip[0]&0x0f) * 4
	if hlen < 20 || len(ip) < hlen {
		return fmt.Errorf("bad IPv4 header length %d", hlen)
	}
	if c := ipv4Checksum(ip[:hlen]); c != 0 {
		return fmt.Errorf("IPv4 header checksum invalid (residual %#04x)", c)
	}
	return nil
}

// runEBPFSelfTest reports whether the eBPF TTL engine works on this kernel.
func runEBPFSelfTest() error {
	errc := make(chan error, 1)
	go func() {
		// The thread switches into a throwaway network namespace and is
		// never unlocked, so the runtime discards it (and the namespace)
		// when this goroutine ends instead of reusing it.
		runtime.LockOSThread()
		errc <- selfTestOnThread()
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(selfTestTimeout):
		return errors.New("timed out")
	}
}

func selfTestOnThread() error {
	p, err := loadTTLPrograms(selfTestTarget)
	if err != nil {
		return err
	}
	defer p.Close()
	if err := selfTestPackets(p); err != nil {
		return fmt.Errorf("packet check: %w", err)
	}
	if err := selfTestAttach(p); err != nil {
		return fmt.Errorf("attach check: %w", err)
	}
	return nil
}

// selfTestPackets runs the program on IPv4 and IPv6 packets in the kernel.
func selfTestPackets(p *ttlProgSet) error {
	out, err := runProbe(p.eth, ethFrame(0x0800, probeIPv4(63, 5, [4]byte{192, 0, 2, 10})))
	if err != nil {
		return fmt.Errorf("IPv4: %w", err)
	}
	if err := verifyIPv4(out[ethHeaderLen:], selfTestTarget); err != nil {
		return fmt.Errorf("IPv4: %w", err)
	}
	src6 := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	out, err = runProbe(p.eth, ethFrame(0x86dd, probeIPv6(63, src6)))
	if err != nil {
		return fmt.Errorf("IPv6: %w", err)
	}
	if hl := out[ethHeaderLen+7]; hl != selfTestTarget {
		return fmt.Errorf("IPv6: hop limit = %d, want %d", hl, selfTestTarget)
	}
	return nil
}

// runProbe executes prog on data with the kernel's test runner.
func runProbe(prog *ebpf.Program, data []byte) ([]byte, error) {
	opts := &ebpf.RunOptions{Data: data, DataOut: make([]byte, len(data)+256)}
	ret, err := prog.Run(opts)
	if err != nil {
		return nil, err
	}
	if ret != tcActUnspec {
		return nil, fmt.Errorf("program returned %#x, want TC_ACT_UNSPEC", ret)
	}
	if len(opts.DataOut) != len(data) {
		return nil, fmt.Errorf("packet length changed from %d to %d", len(data), len(opts.DataOut))
	}
	return opts.DataOut, nil
}

// selfTestAttach attaches the program with tc to a veth pair in a fresh
// network namespace and checks a packet sent through it comes out fixed.
// Callers run it on a locked thread that is never returned to the runtime.
func selfTestAttach(p *ttlProgSet) error {
	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create network namespace: %w", err)
	}
	defer ns.Close()
	n, err := currentTCNetns()
	if err != nil {
		return err
	}
	defer n.close()

	tx, rx, err := selfTestVeth(n)
	if err != nil {
		return err
	}
	a := newTCAttacher(p, n)
	if err := a.sync(); err != nil {
		return err
	}
	defer a.close()
	if !hasTTLFilter(n, tx, a.ids) {
		return errors.New("filter missing after attach")
	}
	return selfTestSend(tx, rx)
}

func selfTestVeth(n *tcNetns) (tx, rx netlink.Link, err error) {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "tsself0"}, PeerName: "tsself1"}
	if err := n.nl.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("create veth: %w", err)
	}
	if tx, err = n.nl.LinkByName("tsself0"); err != nil {
		return nil, nil, err
	}
	if rx, err = n.nl.LinkByName("tsself1"); err != nil {
		return nil, nil, err
	}
	for _, l := range []netlink.Link{tx, rx} {
		if err := n.nl.LinkSetUp(l); err != nil {
			return nil, nil, fmt.Errorf("bring up %s: %w", l.Attrs().Name, err)
		}
	}
	return tx, rx, nil
}

// selfTestSend sends a TTL 63 packet out of tx and checks rx receives it
// with the target TTL.
func selfTestSend(tx, rx netlink.Link) error {
	recv, err := selfTestSocket(rx.Attrs().Index)
	if err != nil {
		return err
	}
	defer unix.Close(recv)
	send, err := selfTestSocket(tx.Attrs().Index)
	if err != nil {
		return err
	}
	defer unix.Close(send)

	pkt := probeIPv4(63, 5, [4]byte{192, 0, 2, 10})
	copy(pkt[len(pkt)-len(probeMarker):], probeMarker)
	if _, err := unix.Write(send, ethFrame(0x0800, pkt)); err != nil {
		return fmt.Errorf("send probe: %w", err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(recv, buf)
		if err != nil || !bytes.Contains(buf[:n], probeMarker) {
			continue
		}
		return verifyIPv4(buf[ethHeaderLen:n], selfTestTarget)
	}
	return errors.New("probe packet never arrived")
}

func selfTestSocket(ifindex int) (int, error) {
	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return -1, fmt.Errorf("packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifindex, Protocol: proto}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind packet socket: %w", err)
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// runSelfTestCLI prints the result for the installer: only "ok" or the
// reason, without the attacher's progress messages.
func runSelfTestCLI(stdout, stderr io.Writer) int {
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(os.Stderr)
	if err := runEBPFSelfTest(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}
