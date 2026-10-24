package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validUpdateResult(operationID string) UpdateResult {
	return UpdateResult{
		OperationID: operationID,
		Phase:       ResultPhaseInstalledAwaitingRestart,
		ExitCode:    0,
		Digest:      strings.Repeat("b", 64),
		Target:      "1.0.1",
		Timestamp:   1750000000,
	}
}

// TestResultRoundTrip is the result-file contract: the fixed schema survives a
// write/read cycle, the file is 0600 on disk, and every malformed or unsafe
// variant is refused by code rather than accepted silently.
func TestResultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	operationID := strings.Repeat("a", 32)
	path := filepath.Join(dir, operationID+".result.json")
	want := validUpdateResult(operationID)

	if err := WriteResult(path, want); err != nil {
		t.Fatalf("write result: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("result mode = %v, want regular 0600", info.Mode())
	}
	got, err := ReadResult(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}

	// Publishing again replaces the record atomically and keeps the mode.
	want.Phase = ResultPhaseInstalledAwaitingRestart
	want.Digest = strings.Repeat("c", 64)
	if err = WriteResult(path, want); err != nil {
		t.Fatalf("rewrite result: %v", err)
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("rewritten mode = %v, err %v, want 0600", info.Mode(), err)
	}
	if got, err = ReadResult(path); err != nil || got != want {
		t.Fatalf("rewritten record = %+v, %v, want %+v", got, err, want)
	}

	t.Run("invalid records are refused", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*UpdateResult)
		}{
			{"unknown phase", func(r *UpdateResult) { r.Phase = "done" }},
			{"negative exit", func(r *UpdateResult) { r.ExitCode = -1 }},
			{"exit above 255", func(r *UpdateResult) { r.ExitCode = 256 }},
			{"bad digest", func(r *UpdateResult) { r.Digest = "deadbeef" }},
			{"floating target", func(r *UpdateResult) { r.Target = "latest" }},
			{"zero timestamp", func(r *UpdateResult) { r.Timestamp = 0 }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				record := validUpdateResult(operationID)
				tc.mutate(&record)
				if err := WriteResult(path, record); codeOf(err) != "UPDATE_RESULT_INVALID" {
					t.Fatalf("WriteResult code = %q, want UPDATE_RESULT_INVALID (err %v)", codeOf(err), err)
				}
			})
		}
	})

	t.Run("file name must be derived from the operation", func(t *testing.T) {
		if err := WriteResult(filepath.Join(dir, "other.result.json"), want); codeOf(err) != "UPDATE_RESULT_INVALID" {
			t.Fatalf("mismatched name code = %q, want UPDATE_RESULT_INVALID (err %v)", codeOf(err), err)
		}
	})

	t.Run("unknown fields are refused", func(t *testing.T) {
		extra := filepath.Join(dir, strings.Repeat("d", 32)+".result.json")
		body := `{"operation_id":"` + strings.Repeat("d", 32) + `","phase":"staged","exit_code":0,"digest":"` +
			strings.Repeat("b", 64) + `","target":"1.0.1","ts":1,"extra":true}`
		if err := os.WriteFile(extra, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResult(extra); codeOf(err) != "UPDATE_RESULT_INVALID" {
			t.Fatalf("unknown field code = %q, want UPDATE_RESULT_INVALID (err %v)", codeOf(err), err)
		}
	})

	t.Run("unsafe mode is refused", func(t *testing.T) {
		unsafe := filepath.Join(dir, strings.Repeat("e", 32)+".result.json")
		record := validUpdateResult(strings.Repeat("e", 32))
		if err := WriteResult(unsafe, record); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResult(unsafe); codeOf(err) != "UPDATE_RESULT_UNSAFE" {
			t.Fatalf("unsafe mode code = %q, want UPDATE_RESULT_UNSAFE (err %v)", codeOf(err), err)
		}
	})
}
