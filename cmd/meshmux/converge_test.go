package main

// The hidden convergence command (#11c-2 Task 5). It is the only /etc writer
// reached from the Agent, and it is reachable only from the fixed systemd-run
// argv of internal/update/converge.go. These tests pin its input contract and
// prove that a refusal is secret-free and leaves no public surface.

import (
	"bytes"
	"strings"
	"testing"
)

// TestInternalUpdateConvergeRequiresFixedArgv pins the input contract: both
// fields are mandatory, unknown flags print only the fixed usage line, and
// every refusal exits non-zero with nothing on stdout.
func TestInternalUpdateConvergeRequiresFixedArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"empty", nil},
		{"missing digest", []string{"--operation-id", strings.Repeat("a", 32)}},
		{"missing operation", []string{"--expected-sha256", strings.Repeat("b", 64)}},
		{"unknown flag", []string{"--operation-id", strings.Repeat("a", 32),
			"--expected-sha256", strings.Repeat("b", 64), "--secret-zzz"}},
		{"positional", []string{"--operation-id", strings.Repeat("a", 32),
			"--expected-sha256", strings.Repeat("b", 64), "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runInternalUpdateConverge(tc.args, &stdout, &stderr); code == 0 {
				t.Fatalf("exit = 0, want a refusal; stderr=%q", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("a refused convergence wrote to stdout: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), "secret") {
				t.Fatalf("stderr echoed the rejected argument: %q", stderr.String())
			}
		})
	}
}

// TestInternalUpdateConvergeIsNotPublic keeps the hidden command out of the
// public usage text.
func TestInternalUpdateConvergeIsNotPublic(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := runWithDependencies(nil, strings.NewReader(""), &stdout, &stderr,
		&fakeNodeRunner{}, &fakeAgentService{}); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	usage := stdout.String() + stderr.String()
	if strings.Contains(usage, "converge") {
		t.Fatalf("public usage mentions the hidden convergence command: %s", usage)
	}
}
