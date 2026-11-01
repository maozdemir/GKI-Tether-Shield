//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	logFileName     = "daemon.log"
	logMaxBytes     = 256 * 1024 // per file; one rotated copy is kept
	packetLogMax    = 5          // packet-path messages per window
	packetLogWindow = time.Minute
)

// logger writes timestamped lines; main points it at the module's log file.
// Until then (and in tests) it writes to stderr.
var logger = log.New(os.Stderr, "", log.LstdFlags)

func logf(format string, args ...any) {
	logger.Printf(format, args...)
}

// initLogging sends logs to <module dir>/daemon.log, capped in size.
func initLogging() {
	logger.SetOutput(&rotatingLog{path: filepath.Join(moduleDir(), logFileName), maxBytes: logMaxBytes})
}

// rotatingLog is an append-only file that moves itself to path+".1" once it
// would exceed maxBytes, so the log can never fill the data partition.
type rotatingLog struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	size     int64
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	if l.size > 0 && l.size+int64(len(p)) > l.maxBytes {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *rotatingLog) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log %s: %w", l.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat log %s: %w", l.path, err)
	}
	l.f, l.size = f, info.Size()
	return nil
}

func (l *rotatingLog) rotate() error {
	l.f.Close()
	l.f = nil
	if err := os.Rename(l.path, l.path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate log %s: %w", l.path, err)
	}
	return l.open()
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// logLimiter allows at most max messages per window and counts the rest, so
// per-packet errors triggered by a client cannot flood the log.
type logLimiter struct {
	mu          sync.Mutex
	max         int
	window      time.Duration
	windowStart time.Time
	count       int
	suppressed  int
}

// allow reports whether a message may be logged now and, when a new window
// starts, how many messages the previous window suppressed.
func (l *logLimiter) allow(now time.Time) (ok bool, suppressedBefore int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.windowStart) >= l.window {
		suppressedBefore = l.suppressed
		l.windowStart, l.count, l.suppressed = now, 0, 0
	}
	if l.count >= l.max {
		l.suppressed++
		return false, suppressedBefore
	}
	l.count++
	return true, suppressedBefore
}

var packetLogLimiter = &logLimiter{max: packetLogMax, window: packetLogWindow}

// packetLogf is logf for the per-packet path, rate limited.
func packetLogf(format string, args ...any) {
	ok, suppressed := packetLogLimiter.allow(time.Now())
	if suppressed > 0 {
		logf("(%d similar packet messages suppressed)", suppressed)
	}
	if ok {
		logf(format, args...)
	}
}
