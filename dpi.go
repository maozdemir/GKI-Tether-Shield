//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
)

// Where to split the first data segment of a web connection so that SNI-
// or Host-based DPI never sees the full server name in one packet.
const (
	splitModeAuto  = "auto"  // inside the TLS SNI / HTTP Host name; fixed position if not found
	splitModeFixed = "fixed" // always at SPLIT_POS bytes
)

const (
	tlsRecordHandshake  = 0x16
	tlsHandshakeHello   = 0x01
	tlsExtServerName    = 0x0000
	tlsServerNameHost   = 0x00
	tlsRecordHeaderLen  = 5
	tlsHandshakeHdrLen  = 4
	tlsHelloRandomLen   = 32
	tlsClientVersionLen = 2
)

// splitPosition returns the byte offset in tcpPayload at which to split.
func splitPosition(tcpPayload []byte, mode string, fixed int) int {
	if mode != splitModeFixed {
		start, length, ok := findTLSServerName(tcpPayload)
		if !ok {
			start, length, ok = findHTTPHost(tcpPayload)
		}
		if ok && length >= 2 {
			return start + length/2 // middle of the name: both halves are partial
		}
	}
	if fixed < 1 {
		return 1
	}
	return fixed
}

// findTLSServerName locates the host_name in a ClientHello's server_name
// extension. ok is false unless the whole name lies inside data (the hello
// may continue in the next TCP segment).
func findTLSServerName(data []byte) (start, length int, ok bool) {
	r := byteReader{buf: data}
	if r.u8() != tlsRecordHandshake {
		return 0, 0, false
	}
	r.skip(tlsRecordHeaderLen - 1) // version (2), record length (2)
	if r.u8() != tlsHandshakeHello {
		return 0, 0, false
	}
	r.skip(tlsHandshakeHdrLen - 1 + tlsClientVersionLen + tlsHelloRandomLen)
	r.skip(int(r.u8()))  // session_id
	r.skip(int(r.u16())) // cipher_suites
	r.skip(int(r.u8()))  // compression_methods
	extEnd := r.pos + 2 + int(r.u16())
	for r.ok() && r.pos+4 <= extEnd {
		extType, extLen := r.u16(), int(r.u16())
		if extType != tlsExtServerName {
			r.skip(extLen)
			continue
		}
		r.skip(2) // server_name_list length
		if r.u8() != tlsServerNameHost {
			return 0, 0, false
		}
		nameLen := int(r.u16())
		if !r.ok() || nameLen == 0 || r.pos+nameLen > len(data) {
			return 0, 0, false
		}
		return r.pos, nameLen, true
	}
	return 0, 0, false
}

// findHTTPHost locates the Host header value of an HTTP/1.x request head.
func findHTTPHost(data []byte) (start, length int, ok bool) {
	head := data
	if end := bytes.Index(data, []byte("\r\n\r\n")); end >= 0 {
		head = data[:end+2]
	}
	for pos := 0; pos < len(head); {
		lineEnd := bytes.Index(head[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			return 0, 0, false
		}
		line := head[pos : pos+lineEnd]
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			value := 5
			for value < len(line) && (line[value] == ' ' || line[value] == '\t') {
				value++
			}
			if value < len(line) {
				return pos + value, len(line) - value, true
			}
			return 0, 0, false
		}
		pos += lineEnd + 2
	}
	return 0, 0, false
}

// byteReader reads big-endian fields; any out-of-range access sets err, and
// later reads return zero, so parsers can check once at the end.
type byteReader struct {
	buf []byte
	pos int
	err bool
}

func (r *byteReader) ok() bool { return !r.err }

func (r *byteReader) skip(n int) {
	if r.err || n < 0 || r.pos+n > len(r.buf) {
		r.err = true
		return
	}
	r.pos += n
}

func (r *byteReader) u8() uint8 {
	if r.err || r.pos+1 > len(r.buf) {
		r.err = true
		return 0
	}
	v := r.buf[r.pos]
	r.pos++
	return v
}

func (r *byteReader) u16() uint16 {
	if r.err || r.pos+2 > len(r.buf) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v
}
