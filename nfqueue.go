//go:build linux

package main

import (
	"encoding/binary"
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
