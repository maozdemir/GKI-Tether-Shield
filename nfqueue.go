//go:build linux

package main

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

type nlmsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type nfgenmsg struct {
	Family  uint8
	Version uint8
	ResId   uint16
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func nfaLen(attrLen int) int {
	return (4 + attrLen + 3) & ^3
}

func appendAttr(buf []byte, attrType uint16, data []byte) []byte {
	aLen := uint16(4 + len(data))
	pad := nfaLen(len(data)) - int(aLen)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint16(hdr[0:2], aLen)
	binary.LittleEndian.PutUint16(hdr[2:4], attrType)
	buf = append(buf, hdr...)
	buf = append(buf, data...)
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

func sendConfig(fd int, cmd uint8, qNum uint16) error {
	nlh := nlmsghdr{
		Type:  uint16((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG),
		Flags: NLM_F_REQUEST,
	}
	nfg := nfgenmsg{
		Family:  syscall.AF_UNSPEC,
		Version: 0,
		ResId:   htons(qNum),
	}

	cmdBuf := make([]byte, 4)
	cmdBuf[0] = cmd

	msg := make([]byte, 16+4)
	copy(msg[16:], (*(*[4]byte)(unsafe.Pointer(&nfg)))[:])
	msg = appendAttr(msg, 1 /* NFQA_CFG_CMD */, cmdBuf)

	nlh.Len = uint32(len(msg))
	copy(msg[0:16], (*(*[16]byte)(unsafe.Pointer(&nlh)))[:])

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}

func sendCopyMode(fd int, qNum uint16, mode uint8, copyRange uint32) error {
	nlh := nlmsghdr{
		Type:  uint16((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG),
		Flags: NLM_F_REQUEST,
	}
	nfg := nfgenmsg{
		Family:  syscall.AF_UNSPEC,
		Version: 0,
		ResId:   htons(qNum),
	}

	paramBuf := make([]byte, 8)
	binary.BigEndian.PutUint32(paramBuf[0:4], copyRange)
	paramBuf[4] = mode

	msg := make([]byte, 16+4)
	copy(msg[16:], (*(*[4]byte)(unsafe.Pointer(&nfg)))[:])
	msg = appendAttr(msg, 2 /* NFQA_CFG_PARAMS */, paramBuf)

	nlh.Len = uint32(len(msg))
	copy(msg[0:16], (*(*[16]byte)(unsafe.Pointer(&nlh)))[:])

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}

func sendVerdict(fd int, qNum uint16, packetID uint32, verdict uint32, payload []byte) error {
	nlh := nlmsghdr{
		Type:  uint16((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT),
		Flags: NLM_F_REQUEST,
	}
	nfg := nfgenmsg{
		Family:  syscall.AF_UNSPEC,
		Version: 0,
		ResId:   htons(qNum),
	}

	vh := make([]byte, 8)
	binary.BigEndian.PutUint32(vh[0:4], verdict)
	binary.BigEndian.PutUint32(vh[4:8], packetID)

	msg := make([]byte, 16+4)
	copy(msg[16:], (*(*[4]byte)(unsafe.Pointer(&nfg)))[:])
	msg = appendAttr(msg, NFQA_VERDICT_HDR, vh)

	if len(payload) > 0 {
		msg = appendAttr(msg, NFQA_PAYLOAD, payload)
	}

	nlh.Len = uint32(len(msg))
	copy(msg[0:16], (*(*[16]byte)(unsafe.Pointer(&nlh)))[:])

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, msg, 0, sa)
}
