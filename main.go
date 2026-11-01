//go:build linux

package main

import (
	_ "embed"
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

	DEFAULT_MODULE_DIR  = "/data/adb/modules/gki_hotspot_shield"
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
	if err := writeFileAtomic(getStatsPath(), []byte(jsonContent), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write stats: %v\n", err)
	}
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "status" || os.Args[1] == "-status" || os.Args[1] == "--status") {
		data, err := os.ReadFile(getStatsPath())
		if err != nil {
			fmt.Println("No stats available. Is the daemon running?")
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

	queues, err := openQueues(cfg.QueueNum, NUM_QUEUES)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NFQUEUE setup failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("NFQUEUE initialized on queues %d-%d. Running...\n", cfg.QueueNum, cfg.QueueNum+NUM_QUEUES-1)

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
		closeQueues(queues)
		os.Exit(0)
	}()

	errs := make(chan error, len(queues))
	for _, q := range queues {
		go func(q *queueWorker) { errs <- q.run(rawFd) }(q)
	}
	// Any queue dying means its share of traffic bypasses TTL fixing, so exit
	// and let the supervisor restart the daemon with all queues bound.
	fmt.Fprintf(os.Stderr, "%v\n", <-errs)
	closeQueues(queues)
	os.Exit(1)
}

func openQueues(first uint16, count int) ([]*queueWorker, error) {
	queues := make([]*queueWorker, 0, count)
	for i := 0; i < count; i++ {
		q, err := openQueue(first + uint16(i))
		if err != nil {
			closeQueues(queues)
			return nil, err
		}
		queues = append(queues, q)
	}
	return queues, nil
}

func closeQueues(queues []*queueWorker) {
	for _, q := range queues {
		q.close()
	}
}
