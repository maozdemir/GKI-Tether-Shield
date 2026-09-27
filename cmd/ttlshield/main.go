package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

//go:embed index.html
var webUIHTML []byte

const (
	NETLINK_NETFILTER  = 12
	NFNL_SUBSYS_QUEUE  = 3

	NFQNL_MSG_PACKET   = 0
	NFQNL_MSG_VERDICT  = 1
	NFQNL_MSG_CONFIG   = 2

	NFQA_PACKET_HDR    = 1
	NFQA_VERDICT_HDR   = 2
	NFQA_PAYLOAD       = 10

	NFQNL_CFG_CMD_BIND   = 1
	NFQNL_CFG_CMD_UNBIND = 2
	NFQNL_COPY_PACKET    = 2

	NF_ACCEPT          = 1
	NF_DROP            = 0

	NLM_F_REQUEST      = 1

	SOL_NETLINK        = 270
	NETLINK_NO_ENOBUFS = 5

	DEFAULT_CONFIG_PATH = "/data/adb/modules/gki_hotspot_shield/config.conf"
	STATS_PATH          = "/data/local/tmp/ttlfixer_stats.json"
	WEB_PORT            = 64640
	DNS_PORT            = 53545
)

func getConfigPath() string {
	if _, err := os.Stat("/data/adb/modules/gki_hotspot_shield/config.conf"); err == nil {
		return "/data/adb/modules/gki_hotspot_shield/config.conf"
	}
	if _, err := os.Stat("/data/adb/modules/nfqttl/config.conf"); err == nil {
		return "/data/adb/modules/nfqttl/config.conf"
	}
	return DEFAULT_CONFIG_PATH
}

func getWebrootFile() string {
	if _, err := os.Stat("/data/adb/modules/gki_hotspot_shield/webroot/index.html"); err == nil {
		return "/data/adb/modules/gki_hotspot_shield/webroot/index.html"
	}
	return "/data/adb/modules/nfqttl/webroot/index.html"
}

type Config struct {
	QueueNum           uint16 `json:"QUEUE_NUM"`
	TargetTTL          uint8  `json:"TARGET_TTL"`
	TcpSplit           bool   `json:"TCP_SPLIT"`
	SplitPos           int    `json:"SPLIT_POS"`
	BufferbloatQoS     bool   `json:"BUFFERBLOAT_QOS"`
	WifiPowerSaveLock  bool   `json:"WIFI_POWER_SAVE_LOCK"`
	TcpLowLatency      bool   `json:"TCP_LOW_LATENCY"`
	DohEnabled         bool   `json:"DOH_ENABLED"`
	DohProvider        string `json:"DOH_PROVIDER"`
}

var cfg = Config{
	QueueNum:          6464,
	TargetTTL:         64,
	TcpSplit:          true,
	SplitPos:          2,
	BufferbloatQoS:    true,
	WifiPowerSaveLock: true,
	TcpLowLatency:     true,
	DohEnabled:        true,
	DohProvider:       "cloudflare",
}

var (
	totalPackets uint64
	ttlModified  uint64
	tcpSplitPkts uint64
	ipv4Packets  uint64
	ipv6Packets  uint64
	dohQueries   uint64
	dnsCacheHits uint64
)

type dnsCacheEntry struct {
	response  []byte
	expiresAt time.Time
}

var (
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.RWMutex
)

var dohClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

func getDoHURL() (string, string) {
	switch strings.ToLower(cfg.DohProvider) {
	case "quad9":
		return "https://9.9.9.9/dns-query", "9.9.9.9"
	case "google":
		return "https://8.8.8.8/dns-query", "dns.google"
	case "adguard":
		return "https://94.140.14.14/dns-query", "dns.adguard-dns.com"
	case "cloudflare":
		fallthrough
	default:
		return "https://1.1.1.1/dns-query", "cloudflare-dns.com"
	}
}

// resolveFallbackUDP forwards to 1.1.1.1:53 if DoH fails or times out
func resolveFallbackUDP(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func resolveDoH(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("query too short")
	}

	queryKey := string(query[2:])

	dnsCacheMu.RLock()
	if entry, ok := dnsCache[queryKey]; ok {
		if time.Now().Before(entry.expiresAt) {
			dnsCacheMu.RUnlock()
			atomic.AddUint64(&dnsCacheHits, 1)
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0] = query[0]
			resp[1] = query[1]
			return resp, nil
		}
	}
	dnsCacheMu.RUnlock()

	dohURL, hostHeader := getDoHURL()

	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err == nil {
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Host", hostHeader)

		resp, err := dohClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err == nil && len(respBody) > 0 {
				atomic.AddUint64(&dohQueries, 1)

				dnsCacheMu.Lock()
				if len(dnsCache) > 10000 {
					dnsCache = make(map[string]dnsCacheEntry)
				}
				dnsCache[queryKey] = dnsCacheEntry{
					response:  respBody,
					expiresAt: time.Now().Add(60 * time.Second),
				}
				dnsCacheMu.Unlock()

				return respBody, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback to direct UDP DNS if DoH failed
	return resolveFallbackUDP(query)
}

func startDNSServer() {
	// UDP DNS Listener on 0.0.0.0:53545
	go func() {
		conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", DNS_PORT))
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for {
			n, clientAddr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			if !cfg.DohEnabled || n < 12 {
				continue
			}

			qCopy := make([]byte, n)
			copy(qCopy, buf[:n])

			go func(q []byte, target net.Addr) {
				resp, err := resolveDoH(q)
				if err == nil && len(resp) > 0 {
					_, _ = conn.WriteTo(resp, target)
				}
			}(qCopy, clientAddr)
		}
	}()

	// TCP DNS Listener on 0.0.0.0:53545
	go func() {
		l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", DNS_PORT))
		if err != nil {
			return
		}
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				qLen := binary.BigEndian.Uint16(lenBuf[:])
				q := make([]byte, qLen)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}

				resp, err := resolveDoH(q)
				if err == nil && len(resp) > 0 {
					var respLenBuf [2]byte
					binary.BigEndian.PutUint16(respLenBuf[:], uint16(len(resp)))
					_, _ = c.Write(respLenBuf[:])
					_, _ = c.Write(resp)
				}
			}(conn)
		}
	}()
}

func loadConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "TARGET_TTL":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val <= 255 {
				cfg.TargetTTL = uint8(val)
			}
		case "TCP_SPLIT":
			cfg.TcpSplit = (v == "1" || strings.ToLower(v) == "true")
		case "SPLIT_POS":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val < 100 {
				cfg.SplitPos = val
			}
		case "BUFFERBLOAT_QOS":
			cfg.BufferbloatQoS = (v == "1" || strings.ToLower(v) == "true")
		case "WIFI_POWER_SAVE_LOCK":
			cfg.WifiPowerSaveLock = (v == "1" || strings.ToLower(v) == "true")
		case "TCP_LOW_LATENCY":
			cfg.TcpLowLatency = (v == "1" || strings.ToLower(v) == "true")
		case "DOH_ENABLED":
			cfg.DohEnabled = (v == "1" || strings.ToLower(v) == "true")
		case "DOH_PROVIDER":
			cfg.DohProvider = v
		case "QUEUE_NUM":
			if val, err := strconv.Atoi(v); err == nil && val > 0 && val < 65535 {
				cfg.QueueNum = uint16(val)
			}
		}
	}
}

func saveConfigToFile(path string, c Config) error {
	content := fmt.Sprintf(`# GKI Hotspot Shield Configuration
TARGET_TTL=%d
TCP_SPLIT=%t
SPLIT_POS=%d
BUFFERBLOAT_QOS=%t
WIFI_POWER_SAVE_LOCK=%t
TCP_LOW_LATENCY=%t
DOH_ENABLED=%t
DOH_PROVIDER=%s
QUEUE_NUM=%d
`, c.TargetTTL, c.TcpSplit, c.SplitPos, c.BufferbloatQoS, c.WifiPowerSaveLock, c.TcpLowLatency, c.DohEnabled, c.DohProvider, c.QueueNum)
	return os.WriteFile(path, []byte(content), 0644)
}

func startHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if len(webUIHTML) > 0 {
			w.Write(webUIHTML)
		} else {
			http.ServeFile(w, r, getWebrootFile())
		}
	})

	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := map[string]interface{}{
			"total_packets":     atomic.LoadUint64(&totalPackets),
			"ipv4_packets":      atomic.LoadUint64(&ipv4Packets),
			"ipv6_packets":      atomic.LoadUint64(&ipv6Packets),
			"ttl_modified":      atomic.LoadUint64(&ttlModified),
			"tcp_split_packets": atomic.LoadUint64(&tcpSplitPkts),
			"doh_queries":       atomic.LoadUint64(&dohQueries),
			"dns_cache_hits":    atomic.LoadUint64(&dnsCacheHits),
			"target_ttl":        cfg.TargetTTL,
			"tcp_split_enabled": cfg.TcpSplit,
			"doh_enabled":       cfg.DohEnabled,
			"doh_provider":      cfg.DohProvider,
			"updated_at":        time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(stats)
	})

	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(cfg)
			return
		}
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			var newCfg map[string]interface{}
			if err := json.Unmarshal(body, &newCfg); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

			if v, ok := newCfg["TARGET_TTL"]; ok {
				if f, ok := v.(float64); ok && f > 0 && f <= 255 {
					cfg.TargetTTL = uint8(f)
				}
			}
			if v, ok := newCfg["TCP_SPLIT"]; ok {
				cfg.TcpSplit = (v == "1" || v == true)
			}
			if v, ok := newCfg["SPLIT_POS"]; ok {
				if f, ok := v.(float64); ok && f > 0 && f < 100 {
					cfg.SplitPos = int(f)
				}
			}
			if v, ok := newCfg["BUFFERBLOAT_QOS"]; ok {
				cfg.BufferbloatQoS = (v == "1" || v == true)
			}
			if v, ok := newCfg["WIFI_POWER_SAVE_LOCK"]; ok {
				cfg.WifiPowerSaveLock = (v == "1" || v == true)
			}
			if v, ok := newCfg["TCP_LOW_LATENCY"]; ok {
				cfg.TcpLowLatency = (v == "1" || v == true)
			}
			if v, ok := newCfg["DOH_ENABLED"]; ok {
				cfg.DohEnabled = (v == "1" || v == true)
			}
			if v, ok := newCfg["DOH_PROVIDER"]; ok {
				if s, ok := v.(string); ok && s != "" {
					cfg.DohProvider = s
				}
			}

			_ = saveConfigToFile(getConfigPath(), cfg)
			w.Write([]byte(`{"status":"ok"}`))
		}
	})

	go func() {
		_ = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", WEB_PORT), nil)
	}()
}

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

func splitAndSendIPv4TCP(rawFd int, payload []byte, splitPos int) bool {
	if len(payload) < 40 {
		return false
	}
	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl+20 {
		return false
	}
	tcphl := int((payload[ihl+12] >> 4) & 0x0F) * 4
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
	pkt1[8] = cfg.TargetTTL
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
	pkt2[8] = cfg.TargetTTL
	pkt2[10], pkt2[11] = 0, 0
	binary.BigEndian.PutUint16(pkt2[10:12], calcChecksum(pkt2[:ihl]))

	pkt2[ihl+16], pkt2[ihl+17] = 0, 0
	tcpCsum2 := calcTCPChecksumIPv4(srcIP, dstIP, pkt2[ihl:])
	binary.BigEndian.PutUint16(pkt2[ihl+16:ihl+18], tcpCsum2)

	sa := &syscall.SockaddrInet4{
		Port: int(dstPort),
		Addr: dstAddr,
	}

	if err := syscall.Sendto(rawFd, pkt1, 0, sa); err != nil {
		return false
	}
	if err := syscall.Sendto(rawFd, pkt2, 0, sa); err != nil {
		return false
	}

	return true
}

func writeStats() {
	jsonContent := fmt.Sprintf(`{
  "total_packets": %d,
  "ipv4_packets": %d,
  "ipv6_packets": %d,
  "ttl_modified": %d,
  "tcp_split_packets": %d,
  "doh_queries": %d,
  "dns_cache_hits": %d,
  "target_ttl": %d,
  "tcp_split_enabled": %v,
  "doh_enabled": %v,
  "doh_provider": "%s",
  "updated_at": "%s"
}`,
		atomic.LoadUint64(&totalPackets),
		atomic.LoadUint64(&ipv4Packets),
		atomic.LoadUint64(&ipv6Packets),
		atomic.LoadUint64(&ttlModified),
		atomic.LoadUint64(&tcpSplitPkts),
		atomic.LoadUint64(&dohQueries),
		atomic.LoadUint64(&dnsCacheHits),
		cfg.TargetTTL,
		cfg.TcpSplit,
		cfg.DohEnabled,
		cfg.DohProvider,
		time.Now().Format(time.RFC3339),
	)
	_ = os.WriteFile(STATS_PATH, []byte(jsonContent), 0644)
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "status" || os.Args[1] == "-status" || os.Args[1] == "--status") {
		data, err := os.ReadFile(STATS_PATH)
		if err != nil {
			fmt.Println("No stats available. Is ttlfixer running?")
			os.Exit(1)
		}
		fmt.Println(string(data))
		os.Exit(0)
	}

	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, -20)

	loadConfig(getConfigPath())

	// Start embedded DoH DNS Interceptor
	startDNSServer()

	// Start embedded HTTP WebUI Config Server
	startHTTPServer()

	fmt.Printf("Starting GKI Hotspot Shield (WebUI: %d, DoH DNS: %d, Target TTL: %d, TCP Split: %v)...\n",
		WEB_PORT, DNS_PORT, cfg.TargetTTL, cfg.TcpSplit)

	rawFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err == nil {
		_ = syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		defer syscall.Close(rawFd)
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Netlink socket creation failed: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
	_ = syscall.SetsockoptInt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		fmt.Fprintf(os.Stderr, "Bind failed: %v\n", err)
		os.Exit(1)
	}

	sendConfig(fd, NFQNL_CFG_CMD_UNBIND, cfg.QueueNum)
	if err := sendConfig(fd, NFQNL_CFG_CMD_BIND, cfg.QueueNum); err != nil {
		fmt.Fprintf(os.Stderr, "Bind to queue %d failed: %v\n", cfg.QueueNum, err)
		os.Exit(1)
	}

	if err := sendCopyMode(fd, cfg.QueueNum, NFQNL_COPY_PACKET, 0xffff); err != nil {
		fmt.Fprintf(os.Stderr, "Set copy mode failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("NFQUEUE initialized successfully. Running...")

	ticker := time.NewTicker(3 * time.Second)
	go func() {
		for range ticker.C {
			writeStats()
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		writeStats()
		sendConfig(fd, NFQNL_CFG_CMD_UNBIND, cfg.QueueNum)
		os.Exit(0)
	}()

	recvBuf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			if err == syscall.ENOBUFS {
				continue
			}
			break
		}

		offset := 0
		for offset < n {
			if offset+16 > n {
				break
			}
			msgLen := int(binary.LittleEndian.Uint32(recvBuf[offset : offset+4]))
			if msgLen < 16 || offset+msgLen > n {
				break
			}

			msgType := binary.LittleEndian.Uint16(recvBuf[offset+4 : offset+6])
			if msgType == uint16((NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET) {
				atomic.AddUint64(&totalPackets, 1)

				attrOffset := offset + 20
				attrEnd := offset + msgLen

				var packetID uint32
				var payload []byte

				for attrOffset+4 <= attrEnd {
					aLen := int(binary.LittleEndian.Uint16(recvBuf[attrOffset : attrOffset+2]))
					aType := binary.LittleEndian.Uint16(recvBuf[attrOffset+2 : attrOffset+4]) & 0x7fff
					if aLen < 4 || attrOffset+aLen > attrEnd {
						break
					}

					data := recvBuf[attrOffset+4 : attrOffset+aLen]
					if aType == NFQA_PACKET_HDR && len(data) >= 4 {
						packetID = binary.BigEndian.Uint32(data[0:4])
					} else if aType == NFQA_PAYLOAD {
						payload = data
					}

					attrOffset += (aLen + 3) & ^3
				}

				if packetID != 0 && len(payload) > 0 {
					version := payload[0] >> 4

					if version == 4 && len(payload) >= 20 {
						atomic.AddUint64(&ipv4Packets, 1)
						ihl := int(payload[0]&0x0F) * 4
						proto := payload[9]

						// CRITICAL FIX: Only apply TCP Split / DPI Evasion to standard Web HTTP/HTTPS ports!
						// BitTorrent and P2P protocols transfer arbitrary binary chunks that can false-positive
						// as HTTP or TLS signatures. Splitting non-web traffic corrupts torrent data blocks!
						if cfg.TcpSplit && proto == 6 && rawFd > 0 && len(payload) > ihl+20 {
							dstPort := binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
							isWebPort := (dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443)

							if isWebPort {
								tcphl := int((payload[ihl+12] >> 4) & 0x0F) * 4
								tcpPayload := payload[ihl+tcphl:]
								if isTLSClientHello(tcpPayload) || isHTTPRequest(tcpPayload) {
									if splitAndSendIPv4TCP(rawFd, payload, cfg.SplitPos) {
										atomic.AddUint64(&tcpSplitPkts, 1)
										atomic.AddUint64(&ttlModified, 1)
										sendVerdict(fd, cfg.QueueNum, packetID, NF_DROP, nil)
										offset += (msgLen + 3) & ^3
										continue
									}
								}
							}
						}

						currentTTL := payload[8]
						if currentTTL != cfg.TargetTTL {
							payload[8] = cfg.TargetTTL
							payload[10] = 0
							payload[11] = 0
							newCsum := calcChecksum(payload[0:ihl])
							binary.BigEndian.PutUint16(payload[10:12], newCsum)
							atomic.AddUint64(&ttlModified, 1)
							sendVerdict(fd, cfg.QueueNum, packetID, NF_ACCEPT, payload)
						} else {
							sendVerdict(fd, cfg.QueueNum, packetID, NF_ACCEPT, nil)
						}
					} else if version == 6 && len(payload) >= 40 {
						atomic.AddUint64(&ipv6Packets, 1)
						currentHL := payload[7]
						if currentHL != cfg.TargetTTL {
							payload[7] = cfg.TargetTTL
							atomic.AddUint64(&ttlModified, 1)
							sendVerdict(fd, cfg.QueueNum, packetID, NF_ACCEPT, payload)
						} else {
							sendVerdict(fd, cfg.QueueNum, packetID, NF_ACCEPT, nil)
						}
					} else {
						sendVerdict(fd, cfg.QueueNum, packetID, NF_ACCEPT, nil)
					}
				}
			}

			offset += (msgLen + 3) & ^3
		}
	}
}
