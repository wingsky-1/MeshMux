package hubupgrade

// The request file of #11d Task 4 (spec §5.1). The Web process writes one
// short-lived intent under /run; the root dispatcher consumes it. The file is
// never an authorization: it only says which frozen operation to look at, and
// every path, target and digest is re-derived on the root side.
//
// A request must survive a crash half-way through publication, so it is written
// to a private scratch name, fsynced and renamed into place. The reader opens it
// O_NOFOLLOW, re-checks the inode it actually opened, and refuses a symlink, a
// loose mode, another account's file, an oversized document, trailing JSON and a
// data_dir that is not a clean absolute path.

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
)

const (
	// RequestDir is the fixed, tmpfs-backed request directory the Web writes
	// and the path unit watches. It is deliberately outside the data
	// directory: a restore flips --data-dir but cannot move this unit.
	RequestDir = "/run/meshmux-hub/requests"
	// RequestDoneDir holds consumed requests. It is root:root 0700; the Web
	// can neither read nor replace a dispatched intent.
	RequestDoneDir = "/run/meshmux-hub/requests.done"
	// RequestSchema is the frozen request document schema.
	RequestSchema = 1
	// RequestMaxBytes bounds the one document a reader parses.
	RequestMaxBytes = 1 << 10

	codeRequestInvalid = "HUB_HANDOFF_REQUEST_INVALID"
	codeRequestWrite   = "HUB_HANDOFF_WRITE_FAILED"
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
	if err := os.MkdirAll(dir, 0730); err != nil {
		return "", fail(codeRequestWrite, "the request directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fail(codeRequestWrite, "the request directory is not a real directory")
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fail(codeRequestInvalid, "the request could not be encoded")
	}
	target := filepath.Join(dir, r.OperationID+".json")
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
	if err := syncAllocatedDir(dir); err != nil {
		return "", err
	}
	return target, nil
}

// ReadRequest parses one request for the named owner. It never follows a
// symlink and never trusts a pathname after opening it.
func ReadRequest(path string, expectedOwner int) (Request, error) {
	var request Request
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".json") || !opIDRE.MatchString(strings.TrimSuffix(base, ".json")) {
		return request, fail(codeRequestInvalid, "the request file name is not <op32hex>.json")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return request, fail(codeRequestInvalid, "the request is not a regular file")
	}
	if info.Mode().Perm() != 0600 || !ownedBy(expectedOwner, info) {
		return request, fail(codeRequestInvalid, "the request is not a private file of the expected account")
	}
	if info.Size() < 1 || info.Size() > RequestMaxBytes {
		return request, fail(codeRequestInvalid, "the request is outside its size bound")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return request, fail(codeRequestInvalid, "the request could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return request, fail(codeRequestInvalid, "the request changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, RequestMaxBytes+1))
	if err != nil || len(body) > RequestMaxBytes {
		return request, fail(codeRequestInvalid, "the request could not be read within its bound")
	}
	if err := decodeStrictDocument(body, &request); err != nil {
		return request, fail(codeRequestInvalid, "the request is not valid strict JSON")
	}
	if err := validateRequest(request); err != nil {
		return request, err
	}
	if request.OperationID != strings.TrimSuffix(base, ".json") {
		return request, fail(codeRequestInvalid, "the request document and its file name name different operations")
	}
	return request, nil
}

// DrainRejected moves every entry of requestDir into doneDir as
// rejected-<unix>-<name>. The dispatcher uses it for the >1-request refusal and
// for any single request it refuses: the path unit must see an empty directory
// again or it never re-arms.
func DrainRejected(requestDir, doneDir string, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(requestDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fail(codeRequestWrite, "the request directory could not be read")
	}
	if err := os.MkdirAll(doneDir, 0700); err != nil {
		return nil, fail(codeRequestWrite, "the request done directory is unavailable")
	}
	info, err := os.Lstat(doneDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedBy(os.Geteuid(), info) {
		return nil, fail(codeRequestWrite, "the request done directory is not a private directory of the dispatcher")
	}
	moved := make([]string, 0, len(entries))
	for _, entry := range entries {
		source := filepath.Join(requestDir, entry.Name())
		target := filepath.Join(doneDir, "rejected-"+itoaUnix(now)+"-"+entry.Name())
		if err := os.Rename(source, target); err != nil {
			return moved, fail(codeRequestWrite, "a request could not be drained")
		}
		moved = append(moved, target)
	}
	return moved, nil
}

func validateRequest(request Request) error {
	switch {
	case request.Schema != RequestSchema:
		return fail(codeRequestInvalid, "the request does not carry this schema")
	case request.Kind != KindUpdate && request.Kind != KindRestore:
		return fail(codeRequestInvalid, "the request kind is not update or restore")
	case !opIDRE.MatchString(request.OperationID):
		return fail(codeRequestInvalid, "the request operation id is not 32 lowercase hex")
	case !cleanAbsolutePath(request.DataDir):
		return fail(codeRequestInvalid, "the request data directory is not a clean absolute path")
	}
	return nil
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

func syncAllocatedDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fail(codeRequestWrite, "the request directory could not be opened for flushing")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fail(codeRequestWrite, "the request directory could not be flushed")
	}
	return nil
}

func itoaUnix(now time.Time) string {
	return strconv.FormatInt(now.Unix(), 10)
}
