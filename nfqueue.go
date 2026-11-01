//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"syscall"
)

const (
	nlmsgHeaderLen = 16
	nfgenHeaderLen = 4

	NFQA_CFG_CMD    = 1
	NFQA_CFG_PARAMS = 2
	NFQA_CFG_MASK   = 4
	NFQA_CFG_FLAGS  = 5

	// NFQA_CFG_F_FAIL_OPEN makes the kernel accept packets instead of
	// dropping them when the queue is full (daemon too slow or stalled).
	NFQA_CFG_F_FAIL_OPEN = 1
)

type nlAttr struct {
	typ  uint16
	data []byte
}

func nfaLen(attrLen int) int {
	return (4 + attrLen + 3) & ^3
}

func appendAttr(buf []byte, attrType uint16, data []byte) []byte {
	aLen := uint16(4 + len(data))
	pad := nfaLen(len(data)) - int(aLen)
	buf = binary.LittleEndian.AppendUint16(buf, aLen)
	buf = binary.LittleEndian.AppendUint16(buf, attrType)
	buf = append(buf, data...)
	return append(buf, make([]byte, pad)...)
}

// buildNfqMsg builds an nfnetlink_queue message: nlmsghdr (host byte order),
// nfgenmsg with the queue number in network byte order, then attributes.
func buildNfqMsg(msgType uint8, qNum uint16, attrs ...nlAttr) []byte {
	size := nlmsgHeaderLen + nfgenHeaderLen
	for _, a := range attrs {
		size += nfaLen(len(a.data))
	}
	msg := make([]byte, nlmsgHeaderLen, size)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(size))
	binary.LittleEndian.PutUint16(msg[4:6], uint16(NFNL_SUBSYS_QUEUE<<8|uint16(msgType)))
	binary.LittleEndian.PutUint16(msg[6:8], NLM_F_REQUEST)
	msg = append(msg, syscall.AF_UNSPEC, 0)
	msg = binary.BigEndian.AppendUint16(msg, qNum)
	for _, a := range attrs {
		msg = appendAttr(msg, a.typ, a.data)
	}
	return msg
}

func sendNetlink(fd int, msg []byte) error {
	return syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func sendConfig(fd int, cmd uint8, qNum uint16) error {
	cmdBuf := []byte{cmd, 0, 0, 0}
	return sendNetlink(fd, buildNfqMsg(NFQNL_MSG_CONFIG, qNum, nlAttr{NFQA_CFG_CMD, cmdBuf}))
}

func sendCopyMode(fd int, qNum uint16, mode uint8, copyRange uint32) error {
	params := binary.BigEndian.AppendUint32(nil, copyRange)
	params = append(params, mode, 0, 0, 0)
	return sendNetlink(fd, buildNfqMsg(NFQNL_MSG_CONFIG, qNum, nlAttr{NFQA_CFG_PARAMS, params}))
}

func buildQueueFlagsMsg(qNum uint16, flags, mask uint32) []byte {
	return buildNfqMsg(NFQNL_MSG_CONFIG, qNum,
		nlAttr{NFQA_CFG_FLAGS, binary.BigEndian.AppendUint32(nil, flags)},
		nlAttr{NFQA_CFG_MASK, binary.BigEndian.AppendUint32(nil, mask)},
	)
}

func sendQueueFlags(fd int, qNum uint16, flags, mask uint32) error {
	return sendNetlink(fd, buildQueueFlagsMsg(qNum, flags, mask))
}

func buildVerdictMsg(qNum uint16, packetID uint32, verdict uint32, payload []byte) []byte {
	vh := binary.BigEndian.AppendUint32(nil, verdict)
	vh = binary.BigEndian.AppendUint32(vh, packetID)
	attrs := []nlAttr{{NFQA_VERDICT_HDR, vh}}
	if len(payload) > 0 {
		attrs = append(attrs, nlAttr{NFQA_PAYLOAD, payload})
	}
	return buildNfqMsg(NFQNL_MSG_VERDICT, qNum, attrs...)
}

func sendVerdict(fd int, qNum uint16, packetID uint32, verdict uint32, payload []byte) error {
	return sendNetlink(fd, buildVerdictMsg(qNum, packetID, verdict, payload))
}

// NUM_QUEUES must match the --queue-balance range in service.sh. Each queue
// gets its own netlink socket and goroutine, so packet processing scales
// across CPU cores; flow hashing keeps a flow on one queue, preserving order.
const NUM_QUEUES = 4

const (
	netlinkBufBytes = 8 * 1024 * 1024
	recvBufBytes    = 65536
	copyRangeBytes  = 0xffff
)

type queueWorker struct {
	fd   int
	qNum uint16
}

// openQueue creates a dedicated netlink socket bound to NFQUEUE qNum.
func openQueue(qNum uint16) (*queueWorker, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("queue %d: netlink socket: %w", qNum, err)
	}
	q := &queueWorker{fd: fd, qNum: qNum}
	if err := q.configure(); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return q, nil
}

func (q *queueWorker) configure() error {
	_ = syscall.SetsockoptInt(q.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, netlinkBufBytes)
	_ = syscall.SetsockoptInt(q.fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, netlinkBufBytes)
	_ = syscall.SetsockoptInt(q.fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)

	if err := syscall.Bind(q.fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("queue %d: netlink bind: %w", q.qNum, err)
	}
	_ = sendConfig(q.fd, NFQNL_CFG_CMD_UNBIND, q.qNum)
	if err := sendConfig(q.fd, NFQNL_CFG_CMD_BIND, q.qNum); err != nil {
		return fmt.Errorf("queue %d: bind: %w", q.qNum, err)
	}
	if err := sendCopyMode(q.fd, q.qNum, NFQNL_COPY_PACKET, copyRangeBytes); err != nil {
		return fmt.Errorf("queue %d: set copy mode: %w", q.qNum, err)
	}
	// Without fail-open a full queue drops packets, so a burst the daemon
	// can't keep up with stalls every tethered connection.
	if err := sendQueueFlags(q.fd, q.qNum, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN); err != nil {
		logf("queue %d: enabling fail-open failed (continuing): %v", q.qNum, err)
	}
	return nil
}

func (q *queueWorker) close() {
	_ = sendConfig(q.fd, NFQNL_CFG_CMD_UNBIND, q.qNum)
	_ = syscall.Close(q.fd)
}

// run receives and handles packets until a non-recoverable socket error.
func (q *queueWorker) run(raw rawSender) error {
	buf := make([]byte, recvBufBytes)
	for {
		n, _, err := syscall.Recvfrom(q.fd, buf, 0)
		if err != nil {
			if err == syscall.ENOBUFS || err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return fmt.Errorf("queue %d: recv: %w", q.qNum, err)
		}
		parseNfqMessages(buf[:n], func(packetID uint32, payload []byte) {
			atomic.AddUint64(&totalPackets, 1)
			handlePacket(q.fd, raw, q.qNum, packetID, payload)
		})
	}
}

// parseNfqMessages walks a netlink datagram and calls onPacket for each
// NFQNL_MSG_PACKET carrying a packet ID. Malformed input is skipped safely.
func parseNfqMessages(buf []byte, onPacket func(packetID uint32, payload []byte)) {
	const packetMsgType = NFNL_SUBSYS_QUEUE<<8 | NFQNL_MSG_PACKET
	for offset := 0; offset+nlmsgHeaderLen <= len(buf); {
		msgLen := int(binary.LittleEndian.Uint32(buf[offset : offset+4]))
		if msgLen < nlmsgHeaderLen || offset+msgLen > len(buf) {
			return
		}
		msgType := binary.LittleEndian.Uint16(buf[offset+4 : offset+6])
		if msgType == packetMsgType {
			attrStart := offset + nlmsgHeaderLen + nfgenHeaderLen
			if packetID, payload := parsePacketAttrs(buf, attrStart, offset+msgLen); packetID != 0 {
				onPacket(packetID, payload)
			}
		}
		offset += (msgLen + 3) & ^3
	}
}

func parsePacketAttrs(buf []byte, start, end int) (packetID uint32, payload []byte) {
	for off := start; off+4 <= end; {
		aLen := int(binary.LittleEndian.Uint16(buf[off : off+2]))
		aType := binary.LittleEndian.Uint16(buf[off+2:off+4]) & 0x7fff
		if aLen < 4 || off+aLen > end {
			break
		}
		data := buf[off+4 : off+aLen]
		switch {
		case aType == NFQA_PACKET_HDR && len(data) >= 4:
			packetID = binary.BigEndian.Uint32(data[0:4])
		case aType == NFQA_PAYLOAD:
			payload = data
		}
		off += (aLen + 3) & ^3
	}
	return packetID, payload
}
