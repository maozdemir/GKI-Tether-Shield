//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// pinger sends ICMP echo requests out of one interface and reports RTTs.
// It uses a raw socket (the daemon is root) bound to the interface, so the
// pings take the mobile-data path, through the shaper, whatever the phone's
// default network is.

// Reflectors: large anycast resolvers that answer ping. A reflector that
// doesn't answer (some carriers drop pings to some of them) simply yields
// no samples.
var (
	reflectorsV4 = []string{"8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222"}
	reflectorsV6 = []string{"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe", "2620:119:35::35"}
)

const pingPayload = 16 // 8-byte send time + 8 bytes padding

type rttSample struct {
	reflector string
	rtt       time.Duration
	at        time.Time
}

type pinger struct {
	fd      int
	v6      bool
	id      uint16
	targets []net.IP

	mu   sync.Mutex
	seq  uint16
	next int
}

// newPinger opens a raw ICMP (v6: ICMPv6) socket bound to ifname.
func newPinger(ifname string, v6 bool) (*pinger, error) {
	family, proto, list := unix.AF_INET, unix.IPPROTO_ICMP, reflectorsV4
	if v6 {
		family, proto, list = unix.AF_INET6, unix.IPPROTO_ICMPV6, reflectorsV6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("ICMP socket: %w", err)
	}
	if err := unix.BindToDevice(fd, ifname); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind ICMP socket to %s: %w", ifname, err)
	}
	if v6 {
		// Only echo replies: the kernel filters the rest.
		var filter unix.ICMPv6Filter
		for i := range filter.Data {
			filter.Data[i] = 0xffffffff
		}
		filter.Data[129>>5] &^= 1 << (129 & 31)
		if err := unix.SetsockoptICMPv6Filter(fd, unix.IPPROTO_ICMPV6, unix.ICMPV6_FILTER, &filter); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("ICMPv6 filter: %w", err)
		}
	}
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	p := &pinger{fd: fd, v6: v6, id: uint16(os.Getpid())}
	for _, s := range list {
		p.targets = append(p.targets, net.ParseIP(s))
	}
	return p, nil
}

func (p *pinger) close() { unix.Close(p.fd) }

// send pings the next reflector in turn.
func (p *pinger) send(now time.Time) error {
	p.mu.Lock()
	dst := p.targets[p.next%len(p.targets)]
	p.next++
	p.seq++
	seq := p.seq
	p.mu.Unlock()

	msg := make([]byte, 8+pingPayload)
	msg[0] = 8 // echo request
	if p.v6 {
		msg[0] = 128
	}
	binary.BigEndian.PutUint16(msg[4:], p.id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	binary.BigEndian.PutUint64(msg[8:], uint64(now.UnixNano()))
	var sa unix.Sockaddr
	if p.v6 {
		a := &unix.SockaddrInet6{}
		copy(a.Addr[:], dst.To16())
		sa = a // the kernel fills in the ICMPv6 checksum
	} else {
		binary.BigEndian.PutUint16(msg[2:], ipv4Checksum(msg))
		a := &unix.SockaddrInet4{}
		copy(a.Addr[:], dst.To4())
		sa = a
	}
	return unix.Sendto(p.fd, msg, 0, sa)
}

// receive reads one reply, waiting at most the socket timeout. ok is false
// for a timeout or a packet that isn't a reply to us.
func (p *pinger) receive() (s rttSample, ok bool, err error) {
	buf := make([]byte, 1500)
	n, from, err := unix.Recvfrom(p.fd, buf, 0)
	now := time.Now()
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return s, false, nil
		}
		return s, false, err
	}
	icmp, src, ok := p.parse(buf[:n], from)
	if !ok {
		return s, false, nil
	}
	sent := time.Unix(0, int64(binary.BigEndian.Uint64(icmp[8:])))
	rtt := now.Sub(sent)
	if rtt <= 0 || rtt > 10*time.Second {
		return s, false, nil
	}
	return rttSample{reflector: src, rtt: rtt, at: now}, true, nil
}

// parse returns the ICMP message of an echo reply addressed to us.
func (p *pinger) parse(pkt []byte, from unix.Sockaddr) (icmp []byte, src string, ok bool) {
	wantType := byte(0)
	if p.v6 {
		wantType = 129
		icmp = pkt // raw ICMPv6 sockets get no IP header
		if a, isV6 := from.(*unix.SockaddrInet6); isV6 {
			src = net.IP(a.Addr[:]).String()
		}
	} else {
		if len(pkt) < 20 {
			return nil, "", false
		}
		hlen := int(pkt[0]&0x0f) * 4
		if hlen < 20 || len(pkt) < hlen {
			return nil, "", false
		}
		icmp = pkt[hlen:]
		src = net.IP(pkt[12:16]).String()
	}
	if len(icmp) < 8+pingPayload || icmp[0] != wantType || binary.BigEndian.Uint16(icmp[4:]) != p.id {
		return nil, "", false
	}
	return icmp, src, true
}
