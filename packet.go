//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"syscall"
)

const (
	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40
	tcpMinHeaderLen  = 20
	ipProtoTCP       = 6
	ipFragOffsetMask = 0x1FFF
	ipFlagMoreFrags  = 0x2000
)

// rawSender injects fully built IP packets (the split TCP segments).
type rawSender interface {
	send4(pkt []byte, dst [4]byte) error
	send6(pkt []byte, dst [16]byte) error
}

// rawSockets sends through raw sockets that carry caller-built IP headers;
// -1 means unavailable.
type rawSockets struct {
	v4, v6 int
}

var errNoRawSocket = errors.New("raw socket unavailable")

func (r rawSockets) send4(pkt []byte, dst [4]byte) error {
	if r.v4 < 0 {
		return errNoRawSocket
	}
	return syscall.Sendto(r.v4, pkt, 0, &syscall.SockaddrInet4{Addr: dst})
}

// send6 uses an IPPROTO_RAW socket, which implies a caller-built IPv6
// header; Linux requires the sockaddr port to be 0 (or 255) for it.
func (r rawSockets) send6(pkt []byte, dst [16]byte) error {
	if r.v6 < 0 {
		return errNoRawSocket
	}
	return syscall.Sendto(r.v6, pkt, 0, &syscall.SockaddrInet6{Addr: dst})
}

func openRawSockets() rawSockets {
	raw := rawSockets{v4: -1, v6: -1}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW); err == nil {
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		raw.v4 = fd
	} else {
		logf("IPv4 raw socket unavailable, TCP splitting disabled for IPv4: %v", err)
	}
	if fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW); err == nil {
		raw.v6 = fd
	} else {
		logf("IPv6 raw socket unavailable, TCP splitting disabled for IPv6: %v", err)
	}
	return raw
}

func (r rawSockets) close() {
	for _, fd := range []int{r.v4, r.v6} {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}
}

// onesSum adds data to a running one's-complement sum.
func onesSum(sum uint32, data []byte) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calcChecksum(data []byte) uint16 {
	return foldChecksum(onesSum(0, data))
}

// tcpChecksum computes the TCP checksum over the pseudo-header fields
// (source, destination, protocol, TCP length) and the segment; the same
// formula serves IPv4 and IPv6 since the fields are summed, not laid out.
func tcpChecksum(src, dst []byte, segment []byte) uint16 {
	sum := onesSum(0, src)
	sum = onesSum(sum, dst)
	sum += ipProtoTCP + uint32(len(segment))
	return foldChecksum(onesSum(sum, segment))
}

func isTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == tlsRecordHandshake && payload[1] == 0x03 &&
		payload[2] <= 0x04 && payload[5] == tlsHandshakeHello
}

func isHTTPRequest(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	s := string(payload[:4])
	return s == "GET " || s == "POST" || s == "HEAD" || s == "PUT " || s == "OPTI"
}

func isWebPort(port uint16) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443
}

// ipv4TCPHeaderLens validates an IPv4/TCP packet and returns its IP and TCP
// header lengths. ok is false for anything malformed, non-TCP, or fragmented,
// so callers can safely slice payload[ihl+tcphl:].
func ipv4TCPHeaderLens(payload []byte) (ihl, tcphl int, ok bool) {
	if len(payload) < ipv4MinHeaderLen || payload[0]>>4 != 4 || payload[9] != ipProtoTCP {
		return 0, 0, false
	}
	ihl = int(payload[0]&0x0F) * 4
	if ihl < ipv4MinHeaderLen || len(payload) < ihl+tcpMinHeaderLen {
		return 0, 0, false
	}
	fragField := binary.BigEndian.Uint16(payload[6:8])
	if fragField&(ipFragOffsetMask|ipFlagMoreFrags) != 0 {
		return 0, 0, false
	}
	tcphl = int(payload[ihl+12]>>4) * 4
	if tcphl < tcpMinHeaderLen || ihl+tcphl > len(payload) {
		return 0, 0, false
	}
	return ihl, tcphl, true
}

// ipv6TCPHeaderLen validates an IPv6 packet whose next header is TCP (no
// extension headers) and returns the TCP header length.
func ipv6TCPHeaderLen(payload []byte) (tcphl int, ok bool) {
	if len(payload) < ipv6HeaderLen+tcpMinHeaderLen || payload[0]>>4 != 6 || payload[6] != ipProtoTCP {
		return 0, false
	}
	if int(binary.BigEndian.Uint16(payload[4:6])) != len(payload)-ipv6HeaderLen {
		return 0, false
	}
	tcphl = int(payload[ipv6HeaderLen+12]>>4) * 4
	if tcphl < tcpMinHeaderLen || ipv6HeaderLen+tcphl > len(payload) {
		return 0, false
	}
	return tcphl, true
}

// webSplitData returns the TCP payload if it starts a TLS ClientHello or an
// HTTP request to a web port. Only web ports are considered: P2P protocols
// carry arbitrary binary data that can look like HTTP/TLS, and splitting them
// corrupts transfers.
func webSplitData(tcp []byte, tcphl int) ([]byte, bool) {
	if !isWebPort(binary.BigEndian.Uint16(tcp[2:4])) {
		return nil, false
	}
	data := tcp[tcphl:]
	return data, isTLSClientHello(data) || isHTTPRequest(data)
}

// isWebSplitCandidate reports whether an IPv4 packet should be split.
func isWebSplitCandidate(payload []byte) bool {
	ihl, tcphl, ok := ipv4TCPHeaderLens(payload)
	if !ok {
		return false
	}
	_, ok = webSplitData(payload[ihl:], tcphl)
	return ok
}

// splitTCP builds the two segments of packet, split pos bytes into its TCP
// payload. ipHdr is the IP header length; finish fixes up the IP header
// (length, TTL / hop limit, checksum) of a segment and returns the
// pseudo-header source and destination addresses for the TCP checksum.
func splitTCP(packet []byte, ipHdr, tcphl, pos int,
	finish func(seg []byte) (src, dst []byte)) (seg1, seg2 []byte, ok bool) {
	headerLen := ipHdr + tcphl
	dataLen := len(packet) - headerLen
	if pos <= 0 || pos >= dataLen {
		return nil, nil, false
	}
	origSeq := binary.BigEndian.Uint32(packet[ipHdr+4 : ipHdr+8])

	build := func(from, to int, seq uint32) []byte {
		seg := make([]byte, headerLen+to-from)
		copy(seg, packet[:headerLen])
		copy(seg[headerLen:], packet[headerLen+from:headerLen+to])
		binary.BigEndian.PutUint32(seg[ipHdr+4:ipHdr+8], seq)
		src, dst := finish(seg)
		seg[ipHdr+16], seg[ipHdr+17] = 0, 0
		binary.BigEndian.PutUint16(seg[ipHdr+16:ipHdr+18], tcpChecksum(src, dst, seg[ipHdr:]))
		return seg
	}
	return build(0, pos, origSeq), build(pos, dataLen, origSeq+uint32(pos)), true
}

func buildSplitIPv4TCP(packet []byte, pos int, ttl uint8) (seg1, seg2 []byte, ok bool) {
	ihl, tcphl, ok := ipv4TCPHeaderLens(packet)
	if !ok {
		return nil, nil, false
	}
	return splitTCP(packet, ihl, tcphl, pos, func(seg []byte) ([]byte, []byte) {
		binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
		seg[8] = ttl
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:12], calcChecksum(seg[:ihl]))
		return seg[12:16], seg[16:20]
	})
}

func buildSplitIPv6TCP(packet []byte, pos int, hopLimit uint8) (seg1, seg2 []byte, ok bool) {
	tcphl, ok := ipv6TCPHeaderLen(packet)
	if !ok {
		return nil, nil, false
	}
	return splitTCP(packet, ipv6HeaderLen, tcphl, pos, func(seg []byte) ([]byte, []byte) {
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)-ipv6HeaderLen))
		seg[7] = hopLimit
		return seg[8:24], seg[24:40]
	})
}

// processPacket decides the verdict for one queued packet and, for web
// handshakes, injects split replacement segments through raw.
func processPacket(payload []byte, raw rawSender, c *Config) (verdict uint32, data []byte) {
	switch {
	case len(payload) >= ipv4MinHeaderLen && payload[0]>>4 == 4:
		atomic.AddUint64(&ipv4Packets, 1)
		return processIPv4(payload, raw, c)
	case len(payload) >= ipv6HeaderLen && payload[0]>>4 == 6:
		atomic.AddUint64(&ipv6Packets, 1)
		return processIPv6(payload, raw, c)
	}
	return NF_ACCEPT, nil
}

func processIPv4(payload []byte, raw rawSender, c *Config) (uint32, []byte) {
	if c.TcpSplit && trySplitIPv4(payload, raw, c) {
		return NF_DROP, nil
	}
	ihl := int(payload[0]&0x0F) * 4
	if ihl < ipv4MinHeaderLen || ihl > len(payload) || payload[8] == c.TargetTTL {
		return NF_ACCEPT, nil
	}
	payload[8] = c.TargetTTL
	payload[10], payload[11] = 0, 0
	binary.BigEndian.PutUint16(payload[10:12], calcChecksum(payload[:ihl]))
	atomic.AddUint64(&ttlModified, 1)
	return NF_ACCEPT, payload
}

func processIPv6(payload []byte, raw rawSender, c *Config) (uint32, []byte) {
	if c.TcpSplit && trySplitIPv6(payload, raw, c) {
		return NF_DROP, nil
	}
	if payload[7] == c.TargetTTL {
		return NF_ACCEPT, nil
	}
	payload[7] = c.TargetTTL // IPv6 has no header checksum
	atomic.AddUint64(&ttlModified, 1)
	return NF_ACCEPT, payload
}

func trySplitIPv4(payload []byte, raw rawSender, c *Config) bool {
	ihl, tcphl, ok := ipv4TCPHeaderLens(payload)
	if !ok {
		return false
	}
	data, web := webSplitData(payload[ihl:], tcphl)
	if !web {
		return false
	}
	seg1, seg2, ok := buildSplitIPv4TCP(payload, splitPosition(data, c.SplitMode, c.SplitPos), c.TargetTTL)
	dst := [4]byte(payload[16:20])
	return ok && sendSplit(func(p []byte) error { return raw.send4(p, dst) }, seg1, seg2)
}

func trySplitIPv6(payload []byte, raw rawSender, c *Config) bool {
	tcphl, ok := ipv6TCPHeaderLen(payload)
	if !ok {
		return false
	}
	data, web := webSplitData(payload[ipv6HeaderLen:], tcphl)
	if !web {
		return false
	}
	seg1, seg2, ok := buildSplitIPv6TCP(payload, splitPosition(data, c.SplitMode, c.SplitPos), c.TargetTTL)
	dst := [16]byte(payload[24:40])
	return ok && sendSplit(func(p []byte) error { return raw.send6(p, dst) }, seg1, seg2)
}

// sendSplit sends both segments. If the first fails nothing was sent and the
// original packet is accepted instead; a failure after it is harmless since
// TCP retransmits the missing part.
func sendSplit(send func([]byte) error, seg1, seg2 []byte) bool {
	if err := send(seg1); err != nil {
		return false
	}
	_ = send(seg2)
	atomic.AddUint64(&tcpSplitPkts, 1)
	atomic.AddUint64(&ttlModified, 1)
	return true
}

// handlePacket issues exactly one verdict for every queued packet. A panic
// while parsing must never leave a packet without a verdict (it would stall in
// the queue) or kill the daemon (TTL normalization would silently stop).
func handlePacket(fd int, raw rawSender, qNum uint16, packetID uint32, payload []byte) {
	verdictSent := false
	defer func() {
		if r := recover(); r != nil {
			packetLogf("packet %d: recovered from panic: %v", packetID, r)
			if !verdictSent {
				_ = sendVerdict(fd, qNum, packetID, NF_ACCEPT, nil)
			}
		}
	}()

	verdict, data := processPacket(payload, raw, cfgSnapshot())
	verdictSent = true
	_ = sendVerdict(fd, qNum, packetID, verdict, data)
}
