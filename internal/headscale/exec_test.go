package headscale

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRunCommandCapturesBoundOutput exercises the production executor with a real
// child process, so the capture, the scrubbed environment and the lack of a
// shell are verified rather than assumed.
func TestRunCommandCapturesBoundOutput(t *testing.T) {
	printf, err := exec.LookPath("printf")
	if err != nil {
		t.Skip("printf not available")
	}
	stdout, stderr, err := runCommand(context.Background(), printf, []string{"%s", "hello"})
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if string(stdout) != "hello" {
		t.Fatalf("stdout = %q", stdout)
	}
	if len(stderr) != 0 {
		t.Fatalf("stderr = %q", stderr)
	}

	// A value that looks like a shell metacharacter stays one argv value: the
	// child receives it literally because no shell parses the command line.
	stdout, _, err = runCommand(context.Background(), printf, []string{"%s", "$(id); rm -rf /"})
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(string(stdout)) != "$(id); rm -rf /" {
		t.Fatalf("argument was interpreted: %q", stdout)
	}

	// The child environment is the fixed one, not the parent's.
	t.Setenv("MESHMUX_TEST_LEAK", "leaked")
	env, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env not available")
	}
	stdout, _, err = runCommand(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.Contains(string(stdout), "MESHMUX_TEST_LEAK") {
		t.Fatalf("child inherited the parent environment: %q", stdout)
	}
	if !strings.Contains(string(stdout), "LC_ALL=C") {
		t.Fatalf("child environment = %q", stdout)
	}
}

// TestRunCommandDeadlineKillsChild asserts a hung child is killed at the fixed
// deadline instead of outliving the request.
func TestRunCommandDeadlineKillsChild(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = runCommand(ctx, sleep, []string{"30"})
	if err == nil {
		t.Fatal("a killed child must report an error")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context = %v", ctx.Err())
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("child outlived the deadline: %s", elapsed)
	}
}
