package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestInternalUpdateInstallRequiresRecordedState pins the hidden command's
// input contract: the transient unit always passes --from-recorded-state, so a
// bare invocation is refused before any host work instead of falling back to an
// interactive install.
func TestInternalUpdateInstallRequiresRecordedState(t *testing.T) {
	args := []string{"--target", "1.0.1", "--manifest-sha256", strings.Repeat("a", 64),
		"--expected-sha256", strings.Repeat("b", 64), "--operation-id", strings.Repeat("c", 32)}
	var stdout, stderr bytes.Buffer
	if code := runInternalUpdateInstall(args, &stdout, &stderr); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if got := strings.TrimSpace(stderr.String()); !strings.HasPrefix(got, "UPDATE_INTERACTIVE_REFUSED:") {
		t.Fatalf("stderr = %q, want UPDATE_INTERACTIVE_REFUSED", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("refusal wrote to stdout: %q", stdout.String())
	}
}

// TestInternalUpdateInstallNeverEchoesArguments keeps caller-supplied flags out
// of the parser refusal, matching the other hidden commands and leaving the
// public usage line untouched.
func TestInternalUpdateInstallNeverEchoesArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secret := "--secret-" + strings.Repeat("z", 12)
	if code := runInternalUpdateInstall([]string{secret}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("stderr echoes the argument: %q", stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stderr.String()), "USAGE: meshmux __internal-update-install") {
		t.Fatalf("stderr = %q, want the fixed usage line", stderr.String())
	}
}
