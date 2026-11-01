//go:build linux

package main

import (
	"encoding/binary"
	"sync/atomic"
	"syscall"
)

func calcChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calcTCPChecksumIPv4(srcIP, dstIP []byte, tcpSegment []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(6) // IPPROTO_TCP
	sum += uint32(len(tcpSegment))

	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
	}
	if len(tcpSegment)%2 == 1 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func isTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if payload[0] == 0x16 && payload[1] == 0x03 && (payload[2] >= 0x00 && payload[2] <= 0x04) {
		if payload[5] == 0x01 {
			return true
		}
	}
	return false
}

func isHTTPRequest(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	s := string(payload[:4])
	return s == "GET " || s == "POST" || s == "HEAD" || s == "PUT " || s == "OPTI"
}

const (
	ipv4MinHeaderLen = 20
	tcpMinHeaderLen  = 20
	ipProtoTCP       = 6
	ipFragOffsetMask = 0x1FFF
	ipFlagMoreFrags  = 0x2000
)

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

func isWebPort(port uint16) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443
}

// isWebSplitCandidate reports whether payload is a well-formed IPv4 TCP packet
// to a web port whose data starts with a TLS ClientHello or an HTTP request.
// Only web ports are considered: P2P protocols carry arbitrary binary data that
// can look like HTTP/TLS, and splitting them corrupts transfers.
func isWebSplitCandidate(payload []byte) bool {
	ihl, tcphl, ok := ipv4TCPHeaderLens(payload)
	if !ok {
		return false
	}
	if !isWebPort(binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])) {
		return false
	}
	tcpPayload := payload[ihl+tcphl:]
	return isTLSClientHello(tcpPayload) || isHTTPRequest(tcpPayload)
}

func splitAndSendIPv4TCP(rawFd int, payload []byte, splitPos int, ttl uint8) bool {
	ihl, tcphl, ok := ipv4TCPHeaderLens(payload)
	if !ok {
		return false
	}
	headerLen := ihl + tcphl
	dataLen := len(payload) - headerLen

	if dataLen <= splitPos || splitPos <= 0 {
		return false
	}

	srcIP := payload[12:16]
	dstIP := payload[16:20]
	dstAddr := [4]byte{dstIP[0], dstIP[1], dstIP[2], dstIP[3]}
	dstPort := binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
	origSeq := binary.BigEndian.Uint32(payload[ihl+4 : ihl+8])

	pkt1 := make([]byte, headerLen+splitPos)
	copy(pkt1, payload[:headerLen+splitPos])

	binary.BigEndian.PutUint16(pkt1[2:4], uint16(len(pkt1)))
	pkt1[8] = ttl
	pkt1[10], pkt1[11] = 0, 0
	binary.BigEndian.PutUint16(pkt1[10:12], calcChecksum(pkt1[:ihl]))

	pkt1[ihl+16], pkt1[ihl+17] = 0, 0
	tcpCsum1 := calcTCPChecksumIPv4(srcIP, dstIP, pkt1[ihl:])
	binary.BigEndian.PutUint16(pkt1[ihl+16:ihl+18], tcpCsum1)

	remainLen := dataLen - splitPos
	pkt2 := make([]byte, headerLen+remainLen)
	copy(pkt2[:headerLen], payload[:headerLen])
	copy(pkt2[headerLen:], payload[headerLen+splitPos:])

	binary.BigEndian.PutUint32(pkt2[ihl+4:ihl+8], origSeq+uint32(splitPos))
	binary.BigEndian.PutUint16(pkt2[2:4], uint16(len(pkt2)))
	pkt2[8] = ttl
	pkt2[10], pkt2[11] = 0, 0
	binary.BigEndian.PutUint16(pkt2[10:12], calcChecksum(pkt2[:ihl]))

	pkt2[ihl+16], pkt2[ihl+17] = 0, 0
	tcpCsum2 := calcTCPChecksumIPv4(srcIP, dstIP, pkt2[ihl:])
	binary.BigEndian.PutUint16(pkt2[ihl+16:ihl+18], tcpCsum2)

	sa := &syscall.SockaddrInet4{
		Port: int(dstPort),
		Addr: dstAddr,
	}

	if rawFd < 0 {
		return false
	}
	if err := syscall.Sendto(rawFd, pkt1, 0, sa); err != nil {
		return false
	}
	if err := syscall.Sendto(rawFd, pkt2, 0, sa); err != nil {
		return false
	}

	return true
}

// handlePacket issues exactly one verdict for every queued packet. A panic
// while parsing must never leave a packet without a verdict (it would stall in
// the queue) or kill the daemon (TTL normalization would silently stop).
func handlePacket(fd, rawFd int, qNum uint16, packetID uint32, payload []byte) {
	verdictSent := false
	verdict := func(v uint32, data []byte) {
		verdictSent = true
		_ = sendVerdict(fd, qNum, packetID, v, data)
	}
	defer func() {
		if r := recover(); r != nil {
			packetLogf("packet %d: recovered from panic: %v", packetID, r)
			if !verdictSent {
				_ = sendVerdict(fd, qNum, packetID, NF_ACCEPT, nil)
			}
		}
	}()

	if len(payload) == 0 {
		verdict(NF_ACCEPT, nil)
		return
	}

	c := cfgSnapshot() // one consistent config view per packet
	switch version := payload[0] >> 4; {
	case version == 4 && len(payload) >= ipv4MinHeaderLen:
		handleIPv4(payload, rawFd, c, verdict)
	case version == 6 && len(payload) >= 40:
		atomic.AddUint64(&ipv6Packets, 1)
		if payload[7] != c.TargetTTL {
			payload[7] = c.TargetTTL
			atomic.AddUint64(&ttlModified, 1)
			verdict(NF_ACCEPT, payload)
			return
		}
		verdict(NF_ACCEPT, nil)
	default:
		verdict(NF_ACCEPT, nil)
	}
}

func handleIPv4(payload []byte, rawFd int, c *Config, verdict func(uint32, []byte)) {
	atomic.AddUint64(&ipv4Packets, 1)

	if c.TcpSplit && rawFd > 0 && isWebSplitCandidate(payload) &&
		splitAndSendIPv4TCP(rawFd, payload, c.SplitPos, c.TargetTTL) {
		atomic.AddUint64(&tcpSplitPkts, 1)
		atomic.AddUint64(&ttlModified, 1)
		verdict(NF_DROP, nil)
		return
	}

	ihl := int(payload[0]&0x0F) * 4
	if ihl < ipv4MinHeaderLen || ihl > len(payload) || payload[8] == c.TargetTTL {
		verdict(NF_ACCEPT, nil)
		return
	}
	payload[8] = c.TargetTTL
	payload[10], payload[11] = 0, 0
	binary.BigEndian.PutUint16(payload[10:12], calcChecksum(payload[:ihl]))
	atomic.AddUint64(&ttlModified, 1)
	verdict(NF_ACCEPT, payload)
}
