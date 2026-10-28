package dispatch

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

// TestWriteRequestPinsOperationIDInName makes the writer's own invariant local:
// the published name must parse back to the same operation id with the same
// parser the dispatcher uses. Otherwise the writer could publish a document the
// reader refuses (an accepted WriteRequest that no dispatcher will ever pick
// up), and the mismatch would only surface as a timed-out handoff.
func TestWriteRequestPinsOperationIDInName(t *testing.T) {
	// The reader's parser is the single authority for the name shape; assert the
	// round trip both ways so a change on either side fails here.
	for _, id := range []string{testRequestOp, strings.Repeat("f", 32)} {
		name := id + ".json"
		if parsed, ok := requestNameOperationID(name); !ok || parsed != id {
			t.Fatalf("requestNameOperationID(%q) = %q, %v; the writer and reader disagree", name, parsed, ok)
		}
	}
	// Upper-case hex is accepted by no reader, so the writer must refuse it too.
	upper := strings.ToUpper(testRequestOp)
	if _, err := WriteRequest(t.TempDir(), Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: upper, DataDir: "/var/lib/meshmux",
	}); err == nil {
		t.Fatal("WriteRequest accepted an operation id the reader cannot map to a file name")
	}
	if _, ok := requestNameOperationID(upper + ".json"); ok {
		t.Fatal("the name parser accepts non-lowercase hex")
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
// directory is 0730 root:meshmux: the Web has write+execute and no read, so the
// publish path must not depend on reading it (a required directory fsync or
// listing would fail EACCES after the request is already live). The mode-only
// simulation below reproduces exactly that: 0330 removes the read bit from the
// owner while keeping write+execute, which is what the Web's group access looks
// like. The best-effort leftover cleanup may try to list the directory; its
// failure must stay irrelevant to the publish.
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
	// The scratch file is created in this same write-only directory, so no
	// sibling staging directory may appear: the real unit mounts requests/ and
	// staging/ separately, and a rename between them is EXDEV.
	if _, err := os.Lstat(filepath.Join(parent, "staging")); !os.IsNotExist(err) {
		t.Fatalf("publishing created a staging sibling: %v", err)
	}
	// Restore the read bit only to inspect the result: the scratch document must
	// have become the one published file, leaving nothing beside it.
	if err := os.Chmod(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != testRequestOp+".json" {
		t.Fatalf("write-only request directory holds %v, want only the published request", entries)
	}
}

// TestWriteRequestNeverOpensWatchedDir is the static half of the blocker-1
// regression: the publish path must not require reading the watched directory
// (no directory fsync, no mandatory listing), because the Web has write+execute
// but no read on it. CreateTemp is allowed and required: O_CREAT|O_EXCL in a
// write+execute directory needs no read bit. The leftover cleanup may list the
// directory best-effort, but its failure must not gate publication.
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
	// they are allowed; opening it for a directory fsync or reading a file needs
	// read and would fail for the Web. Creating a child only needs write+execute,
	// so CreateTemp stays.
	forbidden := map[string]bool{
		"Open": true, "OpenFile": true, "ReadFile": true,
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
	// The scratch file must be created in the directory it is renamed into: a
	// sibling staging directory is a different vfsmount in the sandbox and the
	// rename would fail EXDEV.
	source := sourceOfTestFile(t)
	if !strings.Contains(source, "os.CreateTemp(dir,") {
		t.Fatal("WriteRequest does not create its scratch file in the request directory")
	}
	if !strings.Contains(source, "os.Rename(scratchName, target)") {
		t.Fatal("WriteRequest does not rename its scratch file onto the published name")
	}
	if strings.Contains(source, "stagingDirFor") {
		t.Fatal("request.go still carries the retired staging helper")
	}
}

// sourceOfTestFile reads request.go back so the assertions above stay tied to a
// literal call rather than to renamed variables.
func sourceOfTestFile(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("request.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestWriteRequestStagesInTargetDir is the same-directory publish regression.
// The scratch document is created beside its target, so the final rename never
// crosses a mount (the web sandbox mounts requests/ and staging/ separately and
// a cross-directory rename is EXDEV). An unusable staging path proves the
// publish path never touches it, and a stale dot-named scratch document is
// recognised and cleared by the same-operation cleanup.
func TestWriteRequestStagesInTargetDir(t *testing.T) {
	parent := t.TempDir()
	requestDir := filepath.Join(parent, "requests")
	if err := os.Mkdir(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(requestDir, 0730); err != nil {
		t.Fatal(err)
	}
	// A regular file where the retired staging sibling used to be: any
	// MkdirAll, CreateTemp or rename through it would fail ENOTDIR.
	if err := os.WriteFile(filepath.Join(parent, "staging"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(requestDir, "."+testRequestOp+".json.part-stale")
	if err := os.WriteFile(stale, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := WriteRequest(requestDir, Request{
		Schema: RequestSchema, Kind: KindUpdate, OperationID: testRequestOp, DataDir: "/var/lib/meshmux",
	})
	if err != nil {
		t.Fatalf("publishing with an unusable staging path failed: %v", err)
	}
	if filepath.Dir(path) != requestDir {
		t.Fatalf("published %q outside the request directory %q", path, requestDir)
	}
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != testRequestOp+".json" {
		t.Fatalf("request directory holds %v, want only the published request", entries)
	}
	// The stale scratch document of this operation was recognised and cleared;
	// the live scratch document became the request.
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale scratch survived the next publish: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(parent, "staging")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("publishing touched the staging path: %v, %v", info, err)
	}
	// The published document is complete and readable.
	if _, err := ReadRequest(path, os.Geteuid()); err != nil {
		t.Fatalf("published request is not readable: %v", err)
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
	if err := os.Chmod(dir, 0730); err != nil {
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
