//go:build linux

package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed index.html
var webUIHTML []byte

const (
	NETLINK_NETFILTER = 12
	NFNL_SUBSYS_QUEUE = 3

	NFQNL_MSG_PACKET  = 0
	NFQNL_MSG_VERDICT = 1
	NFQNL_MSG_CONFIG  = 2

	NFQA_PACKET_HDR  = 1
	NFQA_VERDICT_HDR = 2
	NFQA_PAYLOAD     = 10

	NFQNL_CFG_CMD_BIND   = 1
	NFQNL_CFG_CMD_UNBIND = 2
	NFQNL_COPY_PACKET    = 2

	NF_ACCEPT = 1
	NF_DROP   = 0

	NLM_F_REQUEST = 1

	SOL_NETLINK        = 270
	NETLINK_NO_ENOBUFS = 5

	DEFAULT_CONFIG_PATH = "/data/adb/modules/gki_hotspot_shield/config.conf"
	STATS_PATH          = "/data/local/tmp/ttlfixer_stats.json"
	WEB_PORT            = 64640
	DNS_PORT            = 53545
	MODULE_VERSION      = "v3.5"
	MODULE_VERSION_CODE = 350
)

var (
	totalPackets uint64
	ttlModified  uint64
	tcpSplitPkts uint64
	ipv4Packets  uint64
	ipv6Packets  uint64
	dohQueries   uint64
	dnsCacheHits uint64
)

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

	configureAndroidCertDirs()
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
					aType := binary.LittleEndian.Uint16(recvBuf[attrOffset+2:attrOffset+4]) & 0x7fff
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

				if packetID != 0 {
					handlePacket(fd, rawFd, cfg.QueueNum, packetID, payload)
				}
			}

			offset += (msgLen + 3) & ^3
		}
	}
}
