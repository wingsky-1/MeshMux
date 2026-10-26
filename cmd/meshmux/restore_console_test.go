package main

// The D2 gate of #11d Task 7: root must be able to recover a failed Hub
// upgrade without a browser, a session or a live Web process. The documented
// console argv is parsed here, not executed, so docs and the hidden command
// cannot drift.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRestoreConsoleInvocation(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "ACCEPTANCE.zh-CN.md"))
	if err != nil {
		t.Fatal(err)
	}
	const start = "<!-- hub-restore-console:start -->"
	const end = "<!-- hub-restore-console:end -->"
	text := string(body)
	begin := strings.Index(text, start)
	finish := strings.Index(text, end)
	if begin < 0 || finish <= begin {
		t.Fatal("ACCEPTANCE does not carry the marked console invocation")
	}
	block := text[begin+len(start) : finish]
	var line string
	for _, candidate := range strings.Split(block, "\n") {
		candidate = strings.TrimSpace(candidate)
		if strings.HasPrefix(candidate, "/var/lib/meshmux/upgrade/meshmuxd-") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatal("the console block has no staged old-package command")
	}
	replacements := map[string]string{
		"<from_version>":      "1.0.0",
		"<arch>":              runtime.GOARCH,
		"<from_agent_sha256>": strings.Repeat("a", 64),
		"<op32hex>":           strings.Repeat("b", 32),
		"<data-dir>":          "/var/lib/meshmux",
		"<unix>":              "1700000000",
	}
	for placeholder, value := range replacements {
		line = strings.ReplaceAll(line, placeholder, value)
	}
	if strings.Contains(line, "<") || strings.Contains(line, ">") {
		t.Fatalf("console command still carries a placeholder: %s", line)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "/var/lib/meshmux/upgrade/meshmuxd-1.0.0-"+runtime.GOARCH ||
		fields[1] != "__internal-hub-restore" {
		t.Fatalf("console argv shape = %#v", fields)
	}
	cfg, err := parseRestoreArgs(fields[2:])
	if err != nil {
		t.Fatalf("the documented argv is not accepted by the hidden command: %v", err)
	}
	if cfg.OperationID != strings.Repeat("b", 32) || cfg.ExpectedSHA256 != strings.Repeat("a", 64) ||
		cfg.DataDir != "/var/lib/meshmux" {
		t.Fatalf("parsed config = %+v", cfg)
	}
	wantDir := filepath.Join("/var/lib/meshmux", "restore-"+strings.Repeat("b", 32)+"-1700000000")
	if cfg.RestoreDir != wantDir {
		t.Fatalf("restore dir = %q, want the documented derivation %q", cfg.RestoreDir, wantDir)
	}
	// The console path must not depend on the Web or a request directory.
	for _, forbidden := range []string{"curl", "/tasks", "/run/meshmux-hub/requests"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("console command depends on %q", forbidden)
		}
	}
}
