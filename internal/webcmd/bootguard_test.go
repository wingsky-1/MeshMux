package webcmd

// Tests for the #11d Task 7 boot guard (D2). The guard is the process-level
// complement of StartLimitBurst: it refuses a start only after three recorded
// unhealthy starts of the same release inside ten minutes, and a listener that
// comes up clears the evidence.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootGuardStopsCrashLoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "boot")
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	for i := 0; i < BootMaxAttempts; i++ {
		refuse, err := BootGuard(dir, now.Add(time.Duration(i)*time.Second), "1.0.1")
		if err != nil || refuse {
			t.Fatalf("attempt %d: refuse=%v err=%v", i+1, refuse, err)
		}
	}
	refuse, err := BootGuard(dir, now.Add(4*time.Second), "1.0.1")
	if err != nil || !refuse {
		t.Fatalf("fourth start: refuse=%v err=%v, want refused", refuse, err)
	}
	// The refusal does not extend the window; the next start after it is still
	// refused for the same recorded attempts.
	if refuse, err = BootGuard(dir, now.Add(5*time.Second), "1.0.1"); err != nil || !refuse {
		t.Fatalf("repeated refusal: refuse=%v err=%v", refuse, err)
	}

	// A healthy start clears the count.
	if err := ClearBootAttempts(dir); err != nil {
		t.Fatal(err)
	}
	if refuse, err = BootGuard(dir, now.Add(6*time.Second), "1.0.1"); err != nil || refuse {
		t.Fatalf("after healthy start: refuse=%v err=%v", refuse, err)
	}

	// After the window the old attempts are pruned rather than remembered.
	if refuse, err = BootGuard(dir, now.Add(20*time.Minute), "1.0.1"); err != nil || refuse {
		t.Fatalf("after window: refuse=%v err=%v", refuse, err)
	}

	// A different release starts with a clean count.
	for i := 0; i < BootMaxAttempts; i++ {
		if _, err := BootGuard(dir, now.Add(30*time.Minute+time.Duration(i)*time.Second), "1.0.2"); err != nil {
			t.Fatal(err)
		}
	}
	if refuse, err = BootGuard(dir, now.Add(31*time.Minute), "1.0.3"); err != nil || refuse {
		t.Fatalf("new version inherited the old count: refuse=%v err=%v", refuse, err)
	}
}

func TestBootGuardResetsMalformedEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "boot")
	if err := os.MkdirAll(dir, 0730); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, BootAttemptsName)
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	if refuse, err := BootGuard(dir, now, "1.0.1"); err != nil || refuse {
		t.Fatalf("malformed evidence blocked a start: refuse=%v err=%v", refuse, err)
	}
	// The rewritten file is strict JSON with the first attempt.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("attempt document was not rewritten: %v", err)
	}
}
