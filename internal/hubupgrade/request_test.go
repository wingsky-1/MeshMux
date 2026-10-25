package hubupgrade

// Request-file tests of #11d Task 4 (spec §5.1). The request is an intent, not
// an authorization: its reader must refuse a symlink, a loose mode, a foreign
// owner, trailing JSON and a data_dir that is not a clean absolute path.

import (
	"go/ast"
	"go/parser"
	"go/token"
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

func TestDrainAtMovesEveryEntry(t *testing.T) {
	requestDir := t.TempDir()
	if err := os.Chmod(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	doneDir := filepath.Join(t.TempDir(), "requests.done")
	if err := os.Mkdir(doneDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{testRequestOp, strings.Repeat("b", 32)} {
		if _, err := WriteRequest(requestDir, Request{
			Schema: RequestSchema, Kind: KindUpdate, OperationID: op, DataDir: "/var/lib/meshmux",
		}); err != nil {
			t.Fatal(err)
		}
	}
	requestHandle, err := OpenRequestDir(requestDir, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer requestHandle.Close()
	doneHandle, err := OpenRequestDoneDir(doneDir, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer doneHandle.Close()
	moved, err := DrainAt(requestHandle, doneHandle, []string{testRequestOp + ".json", strings.Repeat("b", 32) + ".json"}, true, time.Unix(1700000000, 0))
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

// TestWriteRequestDoesNotReadRequestDir is the blocker-1 regression. The watched
// directory is 0730 root:meshmux: the Web has write+execute and no read, so any
// publish path that opens the directory (a directory fsync, a ReadDir) fails
// EACCES *after* the request is already live. The mode-only simulation below
// reproduces exactly that: 0330 removes the read bit from the owner while
// keeping write+execute, which is what the Web's group access looks like.
func TestWriteRequestDoesNotReadRequestDir(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root bypasses the missing read bit, so the mode simulation would be
		// vacuous here; the CI runner is unprivileged and exercises it.
		t.Skip("root can read a 0330 directory; the mode simulation needs an unprivileged uid")
	}
	parent := t.TempDir()
	requestDir := filepath.Join(parent, "requests")
	if err := os.Mkdir(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(requestDir, 0330); err != nil {
		t.Fatal(err)
	}
	// TempDir's cleanup needs read permission back on the directory.
	t.Cleanup(func() { _ = os.Chmod(requestDir, 0730) })
	path, err := WriteRequest(requestDir, Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: testRequestOp, DataDir: "/var/lib/meshmux",
	})
	if err != nil {
		t.Fatalf("publishing into a write-only request directory failed: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("published request = %v, %v", info, err)
	}
	staged, err := os.Lstat(filepath.Join(parent, "staging"))
	if err != nil {
		t.Fatalf("staging directory is not the unwatched sibling: %v", err)
	}
	if !staged.IsDir() {
		t.Fatal("staging sibling is not a directory")
	}
}

// TestWriteRequestNeverOpensWatchedDir is the static half of the blocker-1
// regression: the publish path must not open the watched directory at all (no
// directory fsync, no listing, no relative scratch file), because the Web has
// write+execute but no read on it. The AST check keeps a future "harmless"
// ReadDir or directory Sync from reintroducing the EACCES-after-publish bug.
func TestWriteRequestNeverOpensWatchedDir(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "request.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var publish *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "WriteRequest" {
			publish = fn
		}
	}
	if publish == nil {
		t.Fatal("WriteRequest is not declared in request.go")
	}
	// Lstat/Stat of the directory itself only need execute on its parent, so
	// they are allowed; opening it, listing it or creating a child in it needs
	// read or a directory handle and would fail for the Web.
	forbidden := map[string]bool{
		"Open": true, "OpenFile": true, "ReadDir": true, "ReadFile": true,
		"CreateTemp": true,
	}
	var offenders []string
	ast.Inspect(publish, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !forbidden[selector.Sel.Name] {
			return true
		}
		if ident, ok := call.Args[0].(*ast.Ident); ok && ident.Name == "dir" {
			offenders = append(offenders, "os."+selector.Sel.Name+"(dir, ...)")
		}
		return true
	})
	if len(offenders) > 0 {
		t.Fatalf("WriteRequest opens the watched directory: %v", offenders)
	}
	// The scratch file must be created in the unwatched staging sibling.
	if !strings.Contains(sourceOfTestFile(t), "os.CreateTemp(staging") {
		t.Fatal("WriteRequest no longer stages in the unwatched sibling")
	}
}

// sourceOfTestFile reads this test file back so the staging assertion above stays
// tied to a literal call rather than to renamed variables.
func sourceOfTestFile(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("request.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestWriteRequestStagesOutsideWatchedDir proves the watched directory only ever
// holds completed documents: staging is a sibling, and nothing is left behind.
func TestWriteRequestStagesOutsideWatchedDir(t *testing.T) {
	parent := t.TempDir()
	requestDir := filepath.Join(parent, "requests")
	if err := os.Mkdir(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	path, err := WriteRequest(requestDir, Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: testRequestOp, DataDir: "/var/lib/meshmux",
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("watched directory holds %v, want only the published request", entries)
	}
	stagingEntries, err := os.ReadDir(filepath.Join(parent, "staging"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stagingEntries) != 0 {
		t.Fatalf("staging left scratch residue: %v", stagingEntries)
	}
	// A stale scratch document of the same operation is cleared, never reused.
	if err := os.WriteFile(filepath.Join(parent, "staging", "."+testRequestOp+".json.part-stale"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRequest(requestDir, Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: testRequestOp, DataDir: "/var/lib/meshmux",
	}); err != nil {
		t.Fatal(err)
	}
	stagingEntries, err = os.ReadDir(filepath.Join(parent, "staging"))
	if err != nil || len(stagingEntries) != 0 {
		t.Fatalf("stale scratch survived the next publish: %v, %v", stagingEntries, err)
	}
}

// TestOpenRequestDirPinsShape proves the dispatcher-side directory proof: a
// symlink, a loose mode and a foreign owner are refused.
func TestOpenRequestDirPinsShape(t *testing.T) {
	parent := t.TempDir()
	realDir := filepath.Join(parent, "real")
	if err := os.Mkdir(realDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(realDir, 0730); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenRequestDir(realDir, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()

	link := filepath.Join(parent, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequestDir(link, os.Geteuid()); err == nil {
		t.Fatal("a symlinked request directory was accepted")
	}

	looseDir := filepath.Join(parent, "loose")
	if err := os.Mkdir(looseDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(looseDir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequestDir(looseDir, os.Geteuid()); err == nil {
		t.Fatal("a Web-readable request directory was accepted")
	}

	if _, err := OpenRequestDir(realDir, os.Geteuid()+1); err == nil {
		t.Fatal("a request directory owned by another account was accepted")
	}
}

// TestReadRequestAtRefusesSymlinkInDir proves the fd-relative read cannot be
// redirected by a symlinked child.
func TestReadRequestAtRefusesSymlinkInDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "requests")
	if err := os.Mkdir(dir, 0730); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(target, validRequestBody(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, testRequestOp+".json")); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenRequestDir(dir, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if _, err := ReadRequestAt(int(handle.Fd()), testRequestOp+".json", os.Geteuid()); err == nil {
		t.Fatal("a symlinked request was read through the directory handle")
	}
}
