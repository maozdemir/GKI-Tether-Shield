//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// captureSender records injected packets instead of sending them.
type captureSender struct {
	v4, v6 [][]byte
	fail   bool
}

func (c *captureSender) send4(pkt []byte, dst [4]byte) error {
	if c.fail {
		return errors.New("send failed")
	}
	c.v4 = append(c.v4, pkt)
	return nil
}

func (c *captureSender) send6(pkt []byte, dst [16]byte) error {
	if c.fail {
		return errors.New("send failed")
	}
	c.v6 = append(c.v6, pkt)
	return nil
}

func buildIPv6TCP(dstPort uint16, payload []byte, hopLimit uint8) []byte {
	pkt := make([]byte, ipv6HeaderLen+20+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(20+len(payload)))
	pkt[6] = ipProtoTCP
	pkt[7] = hopLimit
	copy(pkt[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	copy(pkt[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2})
	tcp := pkt[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH|ACK
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(pkt[8:24], pkt[24:40], tcp))
	return pkt
}

// checkSegments verifies that segs are valid TCP segments (correct TCP and,
// for IPv4, IP checksums), carry the target TTL, have contiguous sequence
// numbers, and together carry exactly want.
func checkSegments(t *testing.T, segs [][]byte, ipHdr int, ipv6 bool, ttl uint8, want []byte) {
	t.Helper()
	if len(segs) != 2 {
		t.Fatalf("got %d segments, want 2", len(segs))
	}
	var joined []byte
	nextSeq := uint32(0)
	for i, seg := range segs {
		var src, dst []byte
		if ipv6 {
			src, dst = seg[8:24], seg[24:40]
			if seg[7] != ttl || int(binary.BigEndian.Uint16(seg[4:6])) != len(seg)-ipv6HeaderLen {
				t.Fatalf("segment %d: bad hop limit / payload length", i)
			}
		} else {
			src, dst = seg[12:16], seg[16:20]
			if seg[8] != ttl || int(binary.BigEndian.Uint16(seg[2:4])) != len(seg) || calcChecksum(seg[:ipHdr]) != 0 {
				t.Fatalf("segment %d: bad TTL / total length / IP checksum", i)
			}
		}
		if tcpChecksum(src, dst, seg[ipHdr:]) != 0 {
			t.Fatalf("segment %d: TCP checksum does not verify", i)
		}
		seq := binary.BigEndian.Uint32(seg[ipHdr+4 : ipHdr+8])
		if i > 0 && seq != nextSeq {
			t.Fatalf("segment %d: seq %d, want %d", i, seq, nextSeq)
		}
		data := seg[ipHdr+20:]
		nextSeq = seq + uint32(len(data))
		joined = append(joined, data...)
	}
	if !bytes.Equal(joined, want) {
		t.Fatal("segments do not reassemble to the original payload")
	}
}

func TestProcessPacketSplitsIPv4ClientHelloInsideSNI(t *testing.T) {
	hello := captureClientHello(t, "blocked.example.com")
	pkt := buildIPv4TCP(5, 443, hello)
	pkt[8] = 127 // Windows client after forwarding
	raw := &captureSender{}
	c := defaultConfig

	verdict, _ := processPacket(pkt, raw, &c)
	if verdict != NF_DROP {
		t.Fatalf("verdict %d, want NF_DROP (replaced by split segments)", verdict)
	}
	checkSegments(t, raw.v4, 20, false, c.TargetTTL, hello)
	for _, seg := range raw.v4 {
		if bytes.Contains(seg, []byte("blocked.example.com")) {
			t.Fatal("a segment carries the full SNI")
		}
	}
}

func TestProcessPacketSplitsIPv6ClientHello(t *testing.T) {
	hello := captureClientHello(t, "blocked.example.com")
	pkt := buildIPv6TCP(443, hello, 63)
	raw := &captureSender{}
	c := defaultConfig

	verdict, _ := processPacket(pkt, raw, &c)
	if verdict != NF_DROP {
		t.Fatalf("verdict %d, want NF_DROP", verdict)
	}
	checkSegments(t, raw.v6, ipv6HeaderLen, true, c.TargetTTL, hello)
	for _, seg := range raw.v6 {
		if bytes.Contains(seg, []byte("blocked.example.com")) {
			t.Fatal("a segment carries the full SNI")
		}
	}
}

func TestProcessPacketFixesTTLWithoutSplitting(t *testing.T) {
	c := defaultConfig
	raw := &captureSender{}

	v4 := buildIPv4TCP(5, 6881, []byte("bittorrent payload"))
	v4[8] = 63
	if verdict, data := processPacket(v4, raw, &c); verdict != NF_ACCEPT || data == nil ||
		data[8] != c.TargetTTL || calcChecksum(data[:20]) != 0 {
		t.Fatal("IPv4 non-web packet must be accepted with TTL rewritten and a valid IP checksum")
	}

	v6 := buildIPv6TCP(6881, []byte("bittorrent payload"), 63)
	if verdict, data := processPacket(v6, raw, &c); verdict != NF_ACCEPT || data == nil || data[7] != c.TargetTTL {
		t.Fatal("IPv6 non-web packet must be accepted with hop limit rewritten")
	}

	already := buildIPv6TCP(6881, []byte("x"), c.TargetTTL)
	if verdict, data := processPacket(already, raw, &c); verdict != NF_ACCEPT || data != nil {
		t.Fatal("a packet already at the target TTL must be accepted unmodified")
	}
	if len(raw.v4)+len(raw.v6) != 0 {
		t.Fatal("non-web traffic must never be split")
	}
}

func TestProcessPacketSkipsIPv6ExtensionHeaders(t *testing.T) {
	pkt := buildIPv6TCP(443, captureClientHello(t, "example.com"), 63)
	pkt[6] = 0 // hop-by-hop options header instead of TCP
	raw := &captureSender{}
	c := defaultConfig
	if verdict, data := processPacket(pkt, raw, &c); verdict != NF_ACCEPT || data == nil || len(raw.v6) != 0 {
		t.Fatal("packets with extension headers are not split, only hop-limit fixed")
	}
}

func TestProcessPacketFallsBackWhenRawSendFails(t *testing.T) {
	pkt := buildIPv4TCP(5, 443, captureClientHello(t, "example.com"))
	pkt[8] = 63
	c := defaultConfig
	verdict, data := processPacket(pkt, &captureSender{fail: true}, &c)
	if verdict != NF_ACCEPT || data == nil || data[8] != c.TargetTTL {
		t.Fatal("if the split cannot be sent, the original must go out with its TTL fixed")
	}
}

func TestProcessPacketRespectsDisabledSplit(t *testing.T) {
	pkt := buildIPv4TCP(5, 443, captureClientHello(t, "example.com"))
	raw := &captureSender{}
	c := defaultConfig
	c.TcpSplit = false
	if verdict, _ := processPacket(pkt, raw, &c); verdict != NF_ACCEPT || len(raw.v4) != 0 {
		t.Fatal("TCP_SPLIT=0 must not split")
	}
}
