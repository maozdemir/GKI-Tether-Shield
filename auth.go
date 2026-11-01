//go:build linux

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Writes to the config API are limited to trusted callers. Host/Origin checks
// stop web pages, but any app on the phone can open a socket to 127.0.0.1 and
// forge those headers, so the caller's UID is looked up from the kernel's
// socket table instead. The browser fallback (companion app not installed)
// authenticates with a random token that only root can read.

const (
	companionPackage = "com.alperozd.hotspotshield"
	packagesListPath = "/data/system/packages.list"
	webUITokenHeader = "X-Shield-Token"
	webUITokenFile   = ".webui_token"

	uidRoot      = 0
	uidShell     = 2000
	uidPerUserID = 100000 // Android UID = userId*100000 + appId
)

var procNetTCPFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// findSocketUID scans a /proc/net/tcp{,6} table for the socket whose local
// port is localPort and remote port is remotePort, and returns its owner UID.
func findSocketUID(r io.Reader, localPort, remotePort uint16) (uint32, bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		if hexPort(fields[1]) != int(localPort) || hexPort(fields[2]) != int(remotePort) {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			continue
		}
		return uint32(uid), true
	}
	return 0, false
}

// hexPort returns the port of an "ADDR:PORT" /proc/net entry, or -1.
func hexPort(addr string) int {
	_, portHex, ok := strings.Cut(addr, ":")
	if !ok {
		return -1
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return -1
	}
	return int(port)
}

// requestUID returns the UID of the local process that opened r's connection.
func requestUID(r *http.Request) (uint32, bool) {
	_, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return 0, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, false
	}
	for _, path := range procNetTCPFiles {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		uid, ok := findSocketUID(f, uint16(port), WEB_PORT)
		f.Close()
		if ok {
			return uid, true
		}
	}
	return 0, false
}

// companionAppID returns the companion app's appId from packages.list.
func companionAppID(r io.Reader) (uint32, bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != companionPackage {
			continue
		}
		id, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(id), true
	}
	return 0, false
}

func installedCompanionAppID() (uint32, bool) {
	f, err := os.Open(packagesListPath)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	return companionAppID(f)
}

// isTrustedUID accepts root, the adb shell, and the companion app in any
// Android user profile.
func isTrustedUID(uid, appID uint32, appKnown bool) bool {
	if uid == uidRoot || uid == uidShell {
		return true
	}
	return appKnown && uid%uidPerUserID == appID
}

type writeAuthorizer struct {
	token string
	uidOf func(*http.Request) (uint32, bool)
	appID func() (uint32, bool)
}

func newWriteAuthorizer(token string) *writeAuthorizer {
	return &writeAuthorizer{token: token, uidOf: requestUID, appID: installedCompanionAppID}
}

// allowed fails closed: an unknown caller without a valid token is rejected.
func (a *writeAuthorizer) allowed(r *http.Request) bool {
	if got := r.Header.Get(webUITokenHeader); a.token != "" && got != "" &&
		subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1 {
		return true
	}
	uid, ok := a.uidOf(r)
	if !ok {
		return false
	}
	appID, appKnown := uint32(0), false
	if a.appID != nil {
		appID, appKnown = a.appID()
	}
	return isTrustedUID(uid, appID, appKnown)
}

// createWebUIToken writes a fresh random token to the root-only module dir
// for action.sh to hand to the browser fallback.
func createWebUIToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate web UI token: %w", err)
	}
	token := hex.EncodeToString(buf)
	if err := writeFileAtomic(filepath.Join(moduleDir(), webUITokenFile), []byte(token), 0o600); err != nil {
		return "", err
	}
	return token, nil
}
