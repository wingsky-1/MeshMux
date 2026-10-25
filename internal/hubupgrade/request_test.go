package hubupgrade

// Request-file tests of #11d Task 4 (spec §5.1). The request is an intent, not
// an authorization: its reader must refuse a symlink, a loose mode, a foreign
// owner, trailing JSON and a data_dir that is not a clean absolute path.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRequestOp = "0123456789abcdef0123456789abcdef"

func TestRequestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteRequest(dir, Request{
		Schema:      RequestSchema,
		Kind:        KindUpdate,
		OperationID: testRequestOp,
		DataDir:     "/var/lib/meshmux",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(path); got != testRequestOp+".json" {
		t.Fatalf("request file name = %q, want <op>.json", got)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("request mode = %o, want 0600", info.Mode().Perm())
	}
	req, err := ReadRequest(path, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if req.Schema != RequestSchema || req.Kind != KindUpdate || req.OperationID != testRequestOp || req.DataDir != "/var/lib/meshmux" {
		t.Fatalf("round trip changed the request: %+v", req)
	}
}

func TestRequestRejectsTrailingData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testRequestOp+".json")
	body := `{"schema":1,"kind":"update","operation_id":"` + testRequestOp + `","data_dir":"/var/lib/meshmux"}{}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(path, os.Geteuid()); err == nil {
		t.Fatal("a request with trailing JSON was accepted")
	}
}

func TestRequestRejectsSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(target, validRequestBody(), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, testRequestOp+".json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(link, os.Geteuid()); err == nil {
		t.Fatal("a symlinked request was accepted")
	}
}

func TestRequestRejectsLooseModeAndForeignOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testRequestOp+".json")
	if err := os.WriteFile(path, validRequestBody(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(path, os.Geteuid()); err == nil {
		t.Fatal("a 0644 request was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(path, os.Geteuid()+1); err == nil {
		t.Fatal("a request owned by another account was accepted")
	}
}

func TestWriteRequestRejectsUnsafeDataDir(t *testing.T) {
	dir := t.TempDir()
	for _, dataDir := range []string{"relative/path", "/var/lib/meshmux/../meshmux", "/var/lib/meshmux/", "", "/var/lib/meshmux\n"} {
		_, err := WriteRequest(dir, Request{
			Schema: RequestSchema, Kind: KindUpdate, OperationID: testRequestOp, DataDir: dataDir,
		})
		if err == nil {
			t.Fatalf("data_dir %q was accepted", dataDir)
		}
	}
}

func TestDrainRejectedMovesEveryEntry(t *testing.T) {
	requestDir := t.TempDir()
	doneDir := filepath.Join(t.TempDir(), "requests.done")
	for _, op := range []string{testRequestOp, strings.Repeat("b", 32)} {
		if _, err := WriteRequest(requestDir, Request{
			Schema: RequestSchema, Kind: KindUpdate, OperationID: op, DataDir: "/var/lib/meshmux",
		}); err != nil {
			t.Fatal(err)
		}
	}
	moved, err := DrainRejected(requestDir, doneDir, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 2 {
		t.Fatalf("drained %d entries, want 2", len(moved))
	}
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("request directory is not empty after drain: %v", entries)
	}
	doneEntries, err := os.ReadDir(doneDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(doneEntries) != 2 {
		t.Fatalf("done directory holds %d entries, want 2", len(doneEntries))
	}
	for _, entry := range doneEntries {
		if !strings.HasPrefix(entry.Name(), "rejected-1700000000-") {
			t.Fatalf("drained name %q does not carry the rejected marker", entry.Name())
		}
	}
}

func validRequestBody() []byte {
	return []byte(`{"schema":1,"kind":"update","operation_id":"` + testRequestOp + `","data_dir":"/var/lib/meshmux"}`)
}
