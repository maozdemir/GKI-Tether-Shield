//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimePathsLiveInModuleDir(t *testing.T) {
	dir := moduleDir()
	for name, p := range map[string]string{
		"config":  getConfigPath(),
		"webroot": getWebrootFile(),
		"stats":   getStatsPath(),
	} {
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			t.Errorf("%s path %q is outside the module dir %q", name, p, dir)
		}
		if strings.HasPrefix(p, "/data/local/tmp") {
			t.Errorf("%s path %q is in a shell-writable directory", name, p)
		}
	}
}

func TestWriteFileAtomicReplacesSymlinkInsteadOfFollowingIt(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "stats.json")
	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomic(target, []byte("stats"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	if got, _ := os.ReadFile(victim); string(got) != "original" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
	if got, _ := os.ReadFile(target); string(got) != "stats" {
		t.Fatalf("stats not written: %q", got)
	}
}
