//go:build linux

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunCLIConfigSetPostsJSON(t *testing.T) {
	var gotMethod, gotType, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotMethod, gotType, gotBody = r.Method, r.Header.Get("Content-Type"), string(body)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code, handled := runCLI([]string{"config", "set", `{"DOH_ENABLED":"0"}`}, srv.URL, &out, &errOut)
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, errOut.String())
	}
	if gotMethod != http.MethodPost || gotType != "application/json" || gotBody != `{"DOH_ENABLED":"0"}` {
		t.Fatalf("server got %s %q %q", gotMethod, gotType, gotBody)
	}
	if !strings.Contains(out.String(), `"status": "ok"`) {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunCLIConfigGetAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	}))
	defer srv.Close()

	for args, wantPath := range map[string]string{"config get": "/api/config", "status": "/api/stats"} {
		var out, errOut bytes.Buffer
		code, handled := runCLI(strings.Fields(args), srv.URL, &out, &errOut)
		if !handled || code != 0 || !strings.Contains(out.String(), wantPath) {
			t.Fatalf("%s: handled=%v code=%d out=%q err=%q", args, handled, code, out.String(), errOut.String())
		}
	}
}

func TestRunCLIReportsServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusBadRequest, `unknown DOH_PROVIDER "x"`)
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code, _ := runCLI([]string{"config", "set", `{"DOH_PROVIDER":"x"}`}, srv.URL, &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "unknown DOH_PROVIDER") {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestRunCLIUsageAndPassthrough(t *testing.T) {
	var out, errOut bytes.Buffer
	if code, handled := runCLI([]string{"config", "set"}, "http://unused", &out, &errOut); !handled || code != 2 {
		t.Fatalf("missing JSON: handled=%v code=%d", handled, code)
	}
	if _, handled := runCLI([]string{"daemon-mode"}, "http://unused", &out, &errOut); handled {
		t.Fatal("unknown arguments must fall through to normal daemon startup")
	}
}
