package hubupgrade

// The request file of #11d Task 4 (spec §5.1). The Web process writes one
// short-lived intent under /run; the root dispatcher consumes it. The file is
// never an authorization: it only says which frozen operation to look at, and
// every path, target and digest is re-derived on the root side.
//
// A request is completed in a dot-prefixed scratch file *inside* the watched
// directory and renamed to its published name in that same directory. It is
// deliberately not staged in the sibling staging/ directory: the web unit
// declares requests/ and staging/ as two ReadWritePaths, so systemd mounts
// each path separately and a rename between them fails with EXDEV. That is the
// v1.0.0 HUB_HANDOFF_WRITE_FAILED: invisible to tests that share one
// filesystem, guaranteed on a real host. A same-directory rename is atomic and
// mount-local, so the published document is still either absent or complete.
//
// The dot prefix keeps a half-written document out of the dispatcher's way:
// DirectoryNotEmpty ignores dot names and dispatch.go skips them. A crashed
// writer can leave one dot-named scratch document behind; /run is tmpfs and
// clears it on boot, and the best-effort cleanup below removes this
// operation's leftovers whenever the directory is listable. The Web is 0730
// root:meshmux (write+execute, no read), so its cleanup is a silent no-op;
// that residue is inert (dot names), never reused (CreateTemp is O_EXCL) and
// never mistaken for a request.
//
// The publish path deliberately does not fsync the request directory. It is
// 0730 root:meshmux (write+execute, no read for the Web), so the Web cannot open
// it O_RDONLY and a directory fsync would fail with EACCES *after* a successful
// rename, turning a live request into HUB_HANDOFF_WRITE_FAILED. Losing a
// request to a power cut is not load-bearing: the journal is already `queued`,
// and reconciliation turns an unanswered request into HUB_HANDOFF_TIMEOUT.
//
// The reader opens the document O_NOFOLLOW, re-checks the inode it actually
// opened, and refuses a symlink, a loose mode, another account's file, an
// oversized document, trailing JSON and a data_dir that is not a clean absolute
// path.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

const (
	// RequestDir is the fixed, tmpfs-backed request directory the Web writes
	// and the path unit watches. It is deliberately outside the data
	// directory: a restore flips --data-dir but cannot move this unit.
	RequestDir = versions.HubRunDir + "/requests"
	// RequestStagingDir is the sibling the installer still creates and the web
	// unit still declares in ReadWritePaths. The writer no longer stages there:
	// the two paths are separate mounts in the sandbox, so a rename between them
	// is EXDEV. It stays part of the installed layout for compatibility, and no
	// request is ever written to it.
	RequestStagingDir = versions.HubRunDir + "/staging"
	// RequestDoneDir holds consumed requests. It is root:root 0700; the Web
	// can neither read nor replace a dispatched intent.
	RequestDoneDir = versions.HubRunDir + "/requests.done"
	// RequestSchema is the frozen request document schema.
	RequestSchema = 1
	// RequestMaxBytes bounds the one document a reader parses.
	RequestMaxBytes = 1 << 10

	// requestDirMode is the one accepted watched-directory mode: the Web needs
	// write+execute to publish, and must not be able to read (list) what other
	// principals queued.
	requestDirMode = 0730
	// doneDirMode is the dispatcher's private done directory.
	doneDirMode = 0700

	codeRequestWrite = "HUB_HANDOFF_WRITE_FAILED"
)

// Request is one dispatch intent: a kind, the operation whose frozen record and
// journal must be read, and the data directory the Web is currently serving.
type Request struct {
	Schema      int    `json:"schema"`
	Kind        string `json:"kind"`
	OperationID string `json:"operation_id"`
	DataDir     string `json:"data_dir"`
}

// WriteRequest publishes one request under dir as <operation_id>.json. The
// caller is the Web process; the return value is the path the dispatcher reads.
func WriteRequest(dir string, r Request) (string, error) {
	if err := validateRequest(r); err != nil {
		return "", err
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fail(codeRequestWrite, "the request directory is not absolute")
	}
	// The file name is the only key the dispatcher has, so the writer proves its
	// own name before publishing: the same parser the reader uses must map the
	// name back to this operation. A future name change that drifts from the
	// parser fails here instead of producing a request no dispatcher accepts.
	name := r.OperationID + ".json"
	if parsed, ok := requestNameOperationID(name); !ok || parsed != r.OperationID {
		return "", fail(CodeHandoffRequestInvalid, "the request file name does not name the operation")
	}
	if err := os.MkdirAll(dir, requestDirMode); err != nil {
		return "", fail(codeRequestWrite, "the request directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fail(codeRequestWrite, "the request directory is not a real directory")
	}
	// The publish directory is also the scratch directory, so it must be a
	// private directory this account may write: not world-writable, and owned by
	// this account (a fixture) or root (the installed 0730 root:meshmux tree).
	if info.Mode().Perm()&0002 != 0 ||
		(!ownedBy(os.Geteuid(), info) && !ownedBy(0, info)) {
		return "", fail(codeRequestWrite, "the request directory is not a safe publish directory")
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fail(CodeHandoffRequestInvalid, "the request could not be encoded")
	}
	// A crashed writer can leave one scratch document of this operation behind.
	// The watched directory is 0730 root:meshmux, so the Web has write+execute
	// but no read and cannot enumerate it: this cleanup only takes effect where
	// the directory is listable (root/fixture repairs), and the residue is
	// harmless elsewhere. It never matches a published <op32hex>.json.
	if leftovers, err := os.ReadDir(dir); err == nil {
		for _, entry := range leftovers {
			if strings.HasPrefix(entry.Name(), "."+r.OperationID+".json.part-") {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
		}
	}
	target := filepath.Join(dir, name)
	scratch, err := os.CreateTemp(dir, "."+r.OperationID+".json.part-*")
	if err != nil {
		return "", fail(codeRequestWrite, "the request scratch file could not be created")
	}
	scratchName := scratch.Name()
	cleanup := func() {
		_ = scratch.Close()
		_ = os.Remove(scratchName)
	}
	if err := scratch.Chmod(0600); err != nil {
		cleanup()
		return "", fail(codeRequestWrite, "the request could not be made private")
	}
	if _, err := scratch.Write(body); err != nil {
		cleanup()
		return "", fail(codeRequestWrite, "the request could not be written")
	}
	if err := scratch.Sync(); err != nil {
		cleanup()
		return "", fail(codeRequestWrite, "the request could not be flushed")
	}
	if err := scratch.Close(); err != nil {
		_ = os.Remove(scratchName)
		return "", fail(codeRequestWrite, "the request could not be closed")
	}
	if err := os.Rename(scratchName, target); err != nil {
		_ = os.Remove(scratchName)
		return "", fail(codeRequestWrite, "the request could not be published")
	}
	return target, nil
}

// ReadRequest parses one request for the named owner. It never follows a
// symlink and never trusts a pathname after opening it.
func ReadRequest(path string, expectedOwner int) (Request, error) {
	name := filepath.Base(path)
	if _, ok := requestNameOperationID(name); !ok {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request file name is not <op32hex>.json")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request is not a regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request changed while it was being opened")
	}
	return readRequestDocument(file, name, opened, expectedOwner)
}

// ReadRequestAt is the directory-fd relative half the dispatcher uses. The
// request is opened relative to the validated directory handle, so renaming the
// watched path away and substituting a symlink cannot redirect the read.
func ReadRequestAt(dirFD int, name string, expectedOwner int) (Request, error) {
	if _, ok := requestNameOperationID(name); !ok {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request file name is not <op32hex>.json")
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request could not be opened without following a link")
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Request{}, fail(CodeHandoffRequestInvalid, "the request could not be inspected")
	}
	return readRequestDocument(file, name, info, expectedOwner)
}

func readRequestDocument(file *os.File, name string, info os.FileInfo, expectedOwner int) (Request, error) {
	var request Request
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return request, fail(CodeHandoffRequestInvalid, "the request is not a regular file")
	}
	if info.Mode().Perm() != 0600 || !ownedBy(expectedOwner, info) {
		return request, fail(CodeHandoffRequestInvalid, "the request is not a private file of the expected account")
	}
	if info.Size() < 1 || info.Size() > RequestMaxBytes {
		return request, fail(CodeHandoffRequestInvalid, "the request is outside its size bound")
	}
	body, err := io.ReadAll(io.LimitReader(file, RequestMaxBytes+1))
	if err != nil || len(body) > RequestMaxBytes {
		return request, fail(CodeHandoffRequestInvalid, "the request could not be read within its bound")
	}
	if err := decodeStrictDocument(body, &request); err != nil {
		return request, fail(CodeHandoffRequestInvalid, "the request is not valid strict JSON")
	}
	if err := validateRequest(request); err != nil {
		return request, err
	}
	operationID, _ := requestNameOperationID(name)
	if request.OperationID != operationID {
		return request, fail(CodeHandoffRequestInvalid, "the request document and its file name name different operations")
	}
	return request, nil
}

// OpenRequestDir opens the watched directory without following a symlink and
// proves it is the expected account's exact 0730 directory. The returned handle
// is the authority for the rest of one dispatcher pass: children are opened and
// renamed relative to it, so replacing the path with another directory or a
// symlink cannot redirect a read or a drain.
func OpenRequestDir(dir string, expectedOwner int) (*os.File, error) {
	return openDispatchDir(dir, expectedOwner, requestDirMode, CodeHandoffRequestInvalid)
}

// OpenRequestDoneDir is the same proof for the dispatcher's private done
// directory: 0700, root-owned, no symlink.
func OpenRequestDoneDir(dir string, expectedOwner int) (*os.File, error) {
	return openDispatchDir(dir, expectedOwner, doneDirMode, codeRequestWrite)
}

func openDispatchDir(path string, expectedOwner int, mode os.FileMode, code string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fail(code, "the dispatch directory is not absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail(code, "the dispatch directory could not be opened without following a link")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		_ = file.Close()
		return nil, fail(code, "the dispatch directory is not a real directory")
	}
	if info.Mode().Perm() != mode || !ownedBy(expectedOwner, info) {
		_ = file.Close()
		return nil, fail(code, "the dispatch directory is not the expected private directory")
	}
	return file, nil
}

// DrainAt moves the named entries of requestDir into doneDir as
// rejected-<unix>-<name> when rejected is set, or keeps their names otherwise.
// Both handles come from OpenRequestDir/OpenRequestDoneDir, and the rename is
// relative to them, so a swapped directory path cannot capture the move. The
// watched directory must end up empty or the path unit never re-arms.
func DrainAt(requestDir, doneDir *os.File, names []string, rejected bool, now time.Time) ([]string, error) {
	if requestDir == nil || doneDir == nil {
		return nil, fail(codeRequestWrite, "the dispatch directories are not open")
	}
	moved := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return moved, fail(codeRequestWrite, "a request entry name is not a plain file name")
		}
		target := name
		if rejected {
			target = "rejected-" + itoaUnix(now) + "-" + name
		}
		if err := unix.Renameat(int(requestDir.Fd()), name, int(doneDir.Fd()), target); err != nil {
			return moved, fail(codeRequestWrite, "a request could not be drained")
		}
		moved = append(moved, target)
	}
	return moved, nil
}

// RemoveRequest unlinks one request document that was never consumed or whose
// operation timed out (#11d Task 5, spec §5.5). The path unit triggers on
// DirectoryNotEmpty, so a leftover request keeps the unit disarmed for every
// later operation: removing the single named document re-arms it.
//
// It removes exactly <dir>/<op32hex>.json and nothing else. A symlink is
// refused (never followed, and not unlinked either, because its target is not
// ours to touch), a non-regular file and another account's file are refused.
// The watched directory is 0730 root:meshmux, so it can be traversed but not
// listed; that is why this is a path operation on the one known name rather
// than a directory walk. A missing request is success: the dispatcher already
// drained it, or it was never written.
func RemoveRequest(dir, operationID string) error {
	if !opIDRE.MatchString(operationID) {
		return fail(CodeHandoffRequestInvalid, "the operation id is not 32 lowercase hex")
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return fail(CodeHandoffRequestInvalid, "the request directory is not absolute")
	}
	path := filepath.Join(dir, operationID+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fail(CodeHandoffRequestInvalid, "the request could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fail(CodeHandoffRequestInvalid, "the request is not a regular file")
	}
	if !ownedBy(os.Geteuid(), info) {
		return fail(CodeHandoffRequestInvalid, "the request does not belong to this account")
	}
	if err := os.Remove(path); err != nil {
		return fail(codeRequestWrite, "the request could not be removed")
	}
	return nil
}

func validateRequest(request Request) error {
	switch {
	case request.Schema != RequestSchema:
		return fail(CodeHandoffRequestInvalid, "the request does not carry this schema")
	case request.Kind != KindUpdate && request.Kind != KindRestore:
		return fail(CodeHandoffRequestInvalid, "the request kind is not update or restore")
	case !opIDRE.MatchString(request.OperationID):
		return fail(CodeHandoffRequestInvalid, "the request operation id is not 32 lowercase hex")
	case !cleanAbsolutePath(request.DataDir):
		return fail(CodeHandoffRequestInvalid, "the request data directory is not a clean absolute path")
	}
	return nil
}

// requestNameOperationID accepts exactly <op32hex>.json as a request name.
func requestNameOperationID(name string) (string, bool) {
	if !strings.HasSuffix(name, ".json") {
		return "", false
	}
	operationID := strings.TrimSuffix(name, ".json")
	return operationID, opIDRE.MatchString(operationID)
}

// cleanAbsolutePath is the one path rule shared by the request writer, the
// dispatcher and the unit parser: absolute, already clean, and free of control
// bytes that would make a log line or an argv element ambiguous.
func cleanAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00\n\r")
}

func decodeStrictDocument(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func itoaUnix(now time.Time) string {
	return strconv.FormatInt(now.Unix(), 10)
}
