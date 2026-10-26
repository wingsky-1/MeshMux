package hubupgrade

// Result-file tests of #11d Task 4 (spec §5.5, §5.9). A result is progress
// evidence under a fixed root-owned directory; the Web may read it and never
// treat it as authorization.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	written, err := WriteResult(dir, Result{
		Schema:        ResultSchema,
		OperationID:   testRequestOp,
		Phase:         ResultRestarting,
		TargetVersion: "2.0.0",
		PackageSHA256: strings.Repeat("a", 64),
		UpdatedAt:     time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(written)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("result mode = %o, want 0640", info.Mode().Perm())
	}
	got, ok, err := ReadResult(dir, testRequestOp)
	if err != nil || !ok {
		t.Fatalf("ReadResult = %v, %v", ok, err)
	}
	if got.Phase != ResultRestarting || got.TargetVersion != "2.0.0" {
		t.Fatalf("result round trip changed the document: %+v", got)
	}
}

func TestReadResultMissingAndTrailing(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := ReadResult(dir, testRequestOp); err != nil || ok {
		t.Fatalf("missing result = ok %v err %v, want false/nil", ok, err)
	}
	path := filepath.Join(dir, testRequestOp+".json")
	body := `{"schema":1,"operation_id":"` + testRequestOp + `","phase":"failed","error_code":"HUB_HANDOFF_BUSY","updated_at":"2026-10-26T00:00:00Z"}{}`
	if err := os.WriteFile(path, []byte(body), 0640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadResult(dir, testRequestOp); err == nil {
		t.Fatal("a result with trailing JSON was accepted")
	}
}

func TestWriteResultRejectsUnknownPhaseAndDigest(t *testing.T) {
	dir := t.TempDir()
	base := Result{Schema: ResultSchema, OperationID: testRequestOp, UpdatedAt: time.Unix(1700000000, 0).UTC()}
	bad := base
	bad.Phase = "installed"
	if _, err := WriteResult(dir, bad); err == nil {
		t.Fatal("an unknown result phase was accepted")
	}
	bad = base
	bad.Phase = ResultFailed
	bad.PackageSHA256 = "not-a-digest"
	if _, err := WriteResult(dir, bad); err == nil {
		t.Fatal("a non-SHA-256 package digest was accepted")
	}
}
