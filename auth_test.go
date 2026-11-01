//go:build linux

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Excerpt of /proc/net/tcp: the server socket (local :FC80 = 64640) and two
// client sockets connected to it from ports 0xD431 (uid 10234) and 0xA000.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:FC80 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:FC80 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:D431 0100007F:FC80 01 00000000:00000000 00:00000000 00000000 10234        0 1003 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:A000 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 10999        0 1004 1 0000000000000000 20 4 30 10 -1
`

func TestFindSocketUID(t *testing.T) {
	uid, ok := findSocketUID(strings.NewReader(procNetTCP), 0xD431, 64640)
	if !ok || uid != 10234 {
		t.Fatalf("findSocketUID = %d, %v; want 10234, true", uid, ok)
	}
	// Port 0xA000 is connected elsewhere (:8080), not to the web UI.
	if _, ok := findSocketUID(strings.NewReader(procNetTCP), 0xA000, 64640); ok {
		t.Fatal("a socket connected to another port must not match")
	}
	if _, ok := findSocketUID(strings.NewReader("garbage\n  1: x y\n"), 1, 2); ok {
		t.Fatal("malformed input must not match")
	}
}

func TestCompanionAppID(t *testing.T) {
	list := "com.android.chrome 10120 0 /data/user/0/com.android.chrome default:targetSdkVersion=34 3003 0 1 1\n" +
		"com.alperozd.hotspotshield 10234 0 /data/user/0/com.alperozd.hotspotshield default:targetSdkVersion=35 3003 0 1 1\n"
	id, ok := companionAppID(strings.NewReader(list))
	if !ok || id != 10234 {
		t.Fatalf("companionAppID = %d, %v; want 10234, true", id, ok)
	}
	if _, ok := companionAppID(strings.NewReader("com.android.chrome 10120 0 /x\n")); ok {
		t.Fatal("missing companion app must not match")
	}
}

func TestIsTrustedUID(t *testing.T) {
	const appID = 10234
	for _, tt := range []struct {
		uid  uint32
		want bool
	}{
		{0, true},        // root (Magisk action, ttlshield CLI)
		{2000, true},     // adb shell
		{10234, true},    // companion app, user 0
		{1010234, true},  // companion app, work profile (user 10)
		{10235, false},   // another app
		{1010235, false}, // another app in another profile
	} {
		if got := isTrustedUID(tt.uid, appID, true); got != tt.want {
			t.Errorf("isTrustedUID(%d) = %v, want %v", tt.uid, got, tt.want)
		}
	}
	if isTrustedUID(10234, 0, false) {
		t.Error("app UIDs must not be trusted when the companion app is unknown")
	}
}

func TestWriteAuthorizerToken(t *testing.T) {
	a := &writeAuthorizer{token: "s3cret", uidOf: func(*http.Request) (uint32, bool) { return 0, false }}

	r := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	if a.allowed(r) {
		t.Fatal("unknown caller without token must be rejected (fail closed)")
	}
	r.Header.Set(webUITokenHeader, "wrong")
	if a.allowed(r) {
		t.Fatal("wrong token must be rejected")
	}
	r.Header.Set(webUITokenHeader, "s3cret")
	if !a.allowed(r) {
		t.Fatal("valid token must be accepted")
	}

	empty := &writeAuthorizer{token: "", uidOf: func(*http.Request) (uint32, bool) { return 0, false }}
	r.Header.Set(webUITokenHeader, "")
	if empty.allowed(r) {
		t.Fatal("an empty token must never authorize")
	}
}

func TestWriteAuthorizerUID(t *testing.T) {
	a := &writeAuthorizer{
		uidOf: func(*http.Request) (uint32, bool) { return 10234, true },
		appID: func() (uint32, bool) { return 10234, true },
	}
	if !a.allowed(httptest.NewRequest(http.MethodPost, "/api/config", nil)) {
		t.Fatal("companion app must be allowed")
	}
	a.uidOf = func(*http.Request) (uint32, bool) { return 10999, true }
	if a.allowed(httptest.NewRequest(http.MethodPost, "/api/config", nil)) {
		t.Fatal("other apps must be rejected")
	}
}

// TestRequestUIDRealSocket checks the /proc/net/tcp lookup against the real
// kernel socket table: the caller must resolve to this test process's UID.
func TestRequestUIDRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", WEB_PORT))
	if err != nil {
		t.Skipf("port %d unavailable: %v", WEB_PORT, err)
	}
	got := make(chan uint32, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := requestUID(r)
		if !ok {
			uid = ^uint32(0)
		}
		got <- uid
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", WEB_PORT))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("requestUID = %d, want %d", uid, os.Getuid())
	}
}

func TestIndexHandlerAuthenticatesPage(t *testing.T) {
	const token = "0123456789abcdef"
	h := indexHandler(token)
	nonce := "00112233445566778899aabbccddeeff"

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(pageNonceHeader, nonce)
	w := httptest.NewRecorder()
	h(w, r)
	page := w.Body.Bytes()
	if w.Code != http.StatusOK || len(page) == 0 {
		t.Fatalf("status %d, %d bytes", w.Code, len(page))
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("tshield-page:" + nonce + ":"))
	mac.Write(page)
	if got, want := w.Header().Get(pageMACHeader), hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Fatalf("page MAC = %q, want %q", got, want)
	}

	// Browsers send no nonce and get no MAC; invalid nonces get none either.
	for _, nonce := range []string{"", "xyz", "00", strings.Repeat("a", 200)} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if nonce != "" {
			r.Header.Set(pageNonceHeader, nonce)
		}
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusOK || w.Header().Get(pageMACHeader) != "" {
			t.Fatalf("nonce %q: status %d, MAC %q", nonce, w.Code, w.Header().Get(pageMACHeader))
		}
	}

	// Without a token there is nothing to authenticate with.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(pageNonceHeader, nonce)
	w = httptest.NewRecorder()
	indexHandler("")(w, r)
	if w.Header().Get(pageMACHeader) != "" {
		t.Fatal("no MAC must be produced without a token")
	}
}

func TestLoadOrCreateWebUITokenReusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".webui_token")
	first, err := loadOrCreateWebUIToken(path)
	if err != nil || len(first) != 48 {
		t.Fatalf("create: %q, %v", first, err)
	}
	second, err := loadOrCreateWebUIToken(path)
	if err != nil || second != first {
		t.Fatalf("restart must reuse the boot's token: %q vs %q (%v)", second, first, err)
	}
	if err := os.WriteFile(path, []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := loadOrCreateWebUIToken(path)
	if err != nil || third == "not-a-token" || len(third) != 48 {
		t.Fatalf("invalid token file must be replaced: %q, %v", third, err)
	}
}
