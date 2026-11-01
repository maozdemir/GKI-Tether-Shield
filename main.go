//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

//go:embed index.html
var webUIHTML []byte

// Set at build time from module.prop by scripts/build.sh
// (-X main.moduleVersion=... -X main.moduleVersionCode=...).
var (
	moduleVersion     = "dev"
	moduleVersionCode = "0"
)

// versionCode returns the numeric module version code (0 for dev builds).
func versionCode() int {
	code, err := strconv.Atoi(moduleVersionCode)
	if err != nil {
		return 0
	}
	return code
}

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

	DEFAULT_MODULE_DIR = "/data/adb/modules/gki_hotspot_shield"
	WEB_PORT           = 64640
	DNS_PORT           = 53545
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

// fetchStatus queries the running daemon's stats API and returns them
// pretty-printed. The CLI runs as root, which the API trusts.
func fetchStatus(url string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("daemon not reachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read status: %w", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		return "", fmt.Errorf("decode status: %w", err)
	}
	return pretty.String(), nil
}

func runStatusCommand() {
	out, err := fetchStatus(fmt.Sprintf("http://127.0.0.1:%d/api/stats", WEB_PORT))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v (is the daemon running?)\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "status" || os.Args[1] == "-status" || os.Args[1] == "--status") {
		runStatusCommand()
		return
	}

	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, -20)

	initLogging()
	configureAndroidCertDirs()
	setCfg(loadConfigFile(getConfigPath(), defaultConfig))
	startCfg := cfgSnapshot()

	// Start embedded DoH DNS Interceptor
	startDNSServer()

	// Start embedded HTTP WebUI Config Server
	startHTTPServer()

	logf("Starting %s (WebUI: %d, DoH DNS: %d, Target TTL: %d, TCP Split: %v)",
		moduleVersion, WEB_PORT, DNS_PORT, startCfg.TargetTTL, startCfg.TcpSplit)

	rawFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err == nil {
		_ = syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		defer syscall.Close(rawFd)
	}

	queues, err := openQueues(startCfg.QueueNum, NUM_QUEUES)
	if err != nil {
		logf("NFQUEUE setup failed: %v", err)
		os.Exit(1)
	}
	logf("NFQUEUE initialized on queues %d-%d", startCfg.QueueNum, startCfg.QueueNum+NUM_QUEUES-1)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigs {
			if sig == syscall.SIGHUP {
				// service.sh sends SIGHUP when config.conf changed on disk.
				reloadConfig()
				continue
			}
			closeQueues(queues)
			os.Exit(0)
		}
	}()

	errs := make(chan error, len(queues))
	for _, q := range queues {
		go func(q *queueWorker) { errs <- q.run(rawFd) }(q)
	}
	// Any queue dying means its share of traffic bypasses TTL fixing, so exit
	// and let the service.sh watchdog restart the daemon with all queues bound.
	logf("exiting: %v", <-errs)
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
