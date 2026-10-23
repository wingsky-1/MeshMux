package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestInternalUpdateRefusesWithoutConfirmation pins the hidden command's input
// contract: a terminal, a pipe and /dev/null all refuse, but only a terminal
// reports UPDATE_INTERACTIVE_REFUSED. /dev/null is a character device yet not a
// terminal, which the ioctl-based check must distinguish.
func TestInternalUpdateRefusesWithoutConfirmation(t *testing.T) {
	args := []string{"--target", "1.0.1", "--manifest-sha256", strings.Repeat("a", 64), "--operation-id", strings.Repeat("b", 32)}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeRead.Close()
	defer pipeWrite.Close()
	terminal, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	defer terminal.Close()

	for _, tc := range []struct {
		name string
		in   *os.File
		code string
	}{
		{"terminal", terminal, "UPDATE_INTERACTIVE_REFUSED"},
		{"pipe", pipeRead, "UPDATE_CONFIRM_REQUIRED"},
		{"dev-null", devNull, "UPDATE_CONFIRM_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runInternalUpdate(args, tc.in, &stdout, &stderr); code != 3 {
				t.Fatalf("exit = %d, want 3", code)
			}
			if got := strings.TrimSpace(stderr.String()); !strings.HasPrefix(got, tc.code+":") {
				t.Fatalf("stderr = %q, want prefix %q", got, tc.code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("refusal wrote to stdout: %q", stdout.String())
			}
		})
	}
}

// TestInternalUpdateNeverEchoesArguments keeps caller-supplied flags out of the
// refusal output, matching the other hidden commands.
func TestInternalUpdateNeverEchoesArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	secret := "--secret-" + strings.Repeat("z", 12)
	if code := runInternalUpdate([]string{secret}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("stderr echoes the argument: %q", stderr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(stderr.String()), "USAGE: meshmux __internal-update") {
		t.Fatalf("stderr = %q, want the fixed usage line", stderr.String())
	}
}
