//go:build linux

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
)

func TestEBPFSelfTestPassesAndLeavesNoTrace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for BPF and network namespaces")
	}
	before, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()

	var out, errOut bytes.Buffer
	code, handled := runCLI([]string{"ebpf-selftest"}, "", &out, &errOut)
	if !handled || code != 0 || strings.TrimSpace(out.String()) != "ok" {
		t.Fatalf("selftest: handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("selftest printed progress noise: %q", errOut.String())
	}

	// The throwaway namespace lived on its own thread: this one is untouched.
	after, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if !before.Equal(after) {
		t.Fatal("selftest left the caller in another network namespace")
	}
}

func TestEBPFSelfTestFailsWithReasonWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can load BPF")
	}
	var out, errOut bytes.Buffer
	code, _ := runCLI([]string{"ebpf-selftest"}, "", &out, &errOut)
	if code != 1 || out.Len() != 0 || strings.TrimSpace(errOut.String()) == "" {
		t.Fatalf("want exit 1 with a reason, got code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}
