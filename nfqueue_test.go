//go:build linux

package main

import (
	"bytes"
	"testing"
)

func TestBuildVerdictMessage(t *testing.T) {
	got := buildVerdictMsg(6464, 7, NF_ACCEPT, nil)
	want := []byte{
		0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32 (host order)
		0x01, 0x03, // type = NFNL_SUBSYS_QUEUE<<8 | NFQNL_MSG_VERDICT
		0x01, 0x00, // flags = NLM_F_REQUEST
		0, 0, 0, 0, 0, 0, 0, 0, // seq, pid
		0x00, 0x00, 0x19, 0x40, // nfgenmsg: AF_UNSPEC, v0, res_id=6464 (big endian)
		0x0c, 0x00, 0x02, 0x00, // attr len 12, NFQA_VERDICT_HDR
		0x00, 0x00, 0x00, 0x01, // verdict NF_ACCEPT (big endian)
		0x00, 0x00, 0x00, 0x07, // packet id 7 (big endian)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("verdict message mismatch\n got % x\nwant % x", got, want)
	}
}

func TestBuildVerdictMessagePadsPayload(t *testing.T) {
	got := buildVerdictMsg(1, 1, NF_ACCEPT, []byte{0xaa, 0xbb, 0xcc})
	if len(got)%4 != 0 || len(got) != 32+8 {
		t.Fatalf("payload attribute must be 4-byte aligned, got len %d", len(got))
	}
	if got[0] != byte(len(got)) {
		t.Fatalf("nlmsg_len %d does not match message length %d", got[0], len(got))
	}
	if !bytes.Equal(got[32:40], []byte{0x07, 0x00, 0x0a, 0x00, 0xaa, 0xbb, 0xcc, 0x00}) {
		t.Fatalf("payload attribute mismatch: % x", got[32:40])
	}
}

func TestBuildQueueFlagsMessage(t *testing.T) {
	got := buildQueueFlagsMsg(6464, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN)
	want := []byte{
		0x24, 0x00, 0x00, 0x00, // nlmsg_len = 36
		0x02, 0x03, // type = NFNL_SUBSYS_QUEUE<<8 | NFQNL_MSG_CONFIG
		0x01, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0,
		0x00, 0x00, 0x19, 0x40,
		0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, // NFQA_CFG_FLAGS = FAIL_OPEN
		0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, // NFQA_CFG_MASK  = FAIL_OPEN
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("flags message mismatch\n got % x\nwant % x", got, want)
	}
}
