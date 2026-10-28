package dispatch

// The result file of #11d Task 4 (spec §5.5, §5.9 N3). It is written by the
// root-side executors and read by the Web. It lives under the installer's own
// tree, outside the Web-writable data directory, because a Web process that
// could replace it could forge "accepted/restarting/restored" evidence.
//
// A result is progress evidence only. The one confirmation predicate is the
// running version plus package digest (Op.ConfirmedBy); no reader may authorize
// a write from this file.

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

const (
	// ResultsDir is the fixed result directory: root:meshmux 0750, files 0640
	// root:meshmux. The Web can read it and nothing else.
	ResultsDir = versions.HubUpgradeResultsDir
	// ResultSchema is the frozen result document schema.
	ResultSchema = 1
	// ResultMaxBytes bounds the one document a reader parses.
	ResultMaxBytes = 64 << 10

	codeResultInvalid = "HUB_HANDOFF_RESULT_INVALID"
	codeResultWrite   = "HUB_HANDOFF_RESULT_FAILED"
)

// ResultPhase is one frozen progress phase. It is not the journal state
// machine; the Web reconciles one into the other (Task 5).
type ResultPhase string

const (
	ResultAccepted        ResultPhase = "accepted"
	ResultSwapping        ResultPhase = "swapping"
	ResultRestarting      ResultPhase = "restarting"
	ResultRestartAccepted ResultPhase = "restart-accepted"
	ResultRestored        ResultPhase = "restored"
	ResultFailed          ResultPhase = "failed"
	ResultPartial         ResultPhase = "partial"
)

var errorCodeRE = versions.StableCodePattern

func (phase ResultPhase) valid() bool {
	switch phase {
	case ResultAccepted, ResultSwapping, ResultRestarting, ResultRestartAccepted,
		ResultRestored, ResultFailed, ResultPartial:
		return true
	}
	return false
}

// Result is one progress document under ResultsDir. TargetVersion and
// PackageSHA256 are empty when the failure happened before they were known.
type Result struct {
	Schema        int         `json:"schema"`
	OperationID   string      `json:"operation_id"`
	Phase         ResultPhase `json:"phase"`
	ErrorCode     string      `json:"error_code,omitempty"`
	TargetVersion string      `json:"target_version,omitempty"`
	PackageSHA256 string      `json:"package_sha256,omitempty"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// WriteResult publishes one result atomically as 0640. The directory is
// expected to be the fixed root:meshmux 0750 tree; a missing directory is
// created 0750 so a test fixture needs no systemd-tmpfiles. In production the
// process is root; the group is set to meshmux when that account exists so the
// Web can read the file. A root environment without the account stays
// root:root, which is stricter, not weaker.
func WriteResult(dir string, result Result) (string, error) {
	if err := validateResult(result); err != nil {
		return "", err
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fail(codeResultWrite, "the result directory is not absolute")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fail(codeResultWrite, "the result directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fail(codeResultWrite, "the result directory is not a real directory")
	}
	if os.Geteuid() == 0 {
		if gid, ok := meshmuxGroupID(); ok {
			if err := os.Chown(dir, 0, gid); err != nil {
				return "", fail(codeResultWrite, "the result directory group could not be fixed")
			}
		}
	}
	body, err := marshalIndentNoHTML(result)
	if err != nil {
		return "", fail(codeResultInvalid, "the result could not be encoded")
	}
	target := filepath.Join(dir, result.OperationID+".json")
	scratch, err := os.CreateTemp(dir, "."+result.OperationID+".json.part-*")
	if err != nil {
		return "", fail(codeResultWrite, "the result scratch file could not be created")
	}
	scratchName := scratch.Name()
	cleanup := func() {
		_ = scratch.Close()
		_ = os.Remove(scratchName)
	}
	if err := scratch.Chmod(0640); err != nil {
		cleanup()
		return "", fail(codeResultWrite, "the result could not be made group-readable")
	}
	if _, err := scratch.Write(body); err != nil {
		cleanup()
		return "", fail(codeResultWrite, "the result could not be written")
	}
	if err := scratch.Sync(); err != nil {
		cleanup()
		return "", fail(codeResultWrite, "the result could not be flushed")
	}
	if err := scratch.Close(); err != nil {
		_ = os.Remove(scratchName)
		return "", fail(codeResultWrite, "the result could not be closed")
	}
	if err := os.Rename(scratchName, target); err != nil {
		_ = os.Remove(scratchName)
		return "", fail(codeResultWrite, "the result could not be published")
	}
	if err := os.Chmod(target, 0640); err != nil {
		return "", fail(codeResultWrite, "the result could not keep its mode")
	}
	if os.Geteuid() == 0 {
		if gid, ok := meshmuxGroupID(); ok {
			if err := os.Chown(target, 0, gid); err != nil {
				return "", fail(codeResultWrite, "the result ownership could not be fixed")
			}
		}
	}
	if err := syncDirectory(dir); err != nil {
		return "", fail(codeResultWrite, "the result directory could not be flushed")
	}
	return target, nil
}

// ReadResult returns the progress document of one operation. A missing file is
// (zero, false, nil); a malformed, loose or symlinked one is an error. It is a
// read-only Web input and never an authorization.
func ReadResult(dir, operationID string) (Result, bool, error) {
	var result Result
	if !opIDRE.MatchString(operationID) {
		return result, false, fail(codeResultInvalid, "the operation id is not 32 lowercase hex")
	}
	path := filepath.Join(dir, operationID+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return result, false, nil
	}
	if err != nil {
		return result, false, fail(codeResultInvalid, "the result could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0640 || info.Mode().Perm()&0022 != 0 ||
		info.Size() < 1 || info.Size() > ResultMaxBytes {
		return result, false, fail(codeResultInvalid, "the result is not a private-enough read-only file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, false, fail(codeResultInvalid, "the result could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return result, false, fail(codeResultInvalid, "the result changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, ResultMaxBytes+1))
	if err != nil || len(body) > ResultMaxBytes {
		return result, false, fail(codeResultInvalid, "the result could not be read within its bound")
	}
	if err := decodeStrictDocument(body, &result); err != nil {
		return result, false, fail(codeResultInvalid, "the result is not valid strict JSON")
	}
	if err := validateResult(result); err != nil {
		return result, false, err
	}
	if result.OperationID != operationID {
		return result, false, fail(codeResultInvalid, "the result does not belong to this operation")
	}
	return result, true, nil
}

func validateResult(result Result) error {
	switch {
	case result.Schema != ResultSchema:
		return fail(codeResultInvalid, "the result does not carry this schema")
	case !opIDRE.MatchString(result.OperationID):
		return fail(codeResultInvalid, "the result operation id is not 32 lowercase hex")
	case !result.Phase.valid():
		return fail(codeResultInvalid, "the result phase is not in the frozen set")
	case result.ErrorCode != "" && (len(result.ErrorCode) > 64 || !errorCodeRE.MatchString(result.ErrorCode)):
		return fail(codeResultInvalid, "the result error code is not a stable code")
	case result.TargetVersion != "" && !targetRE.MatchString(result.TargetVersion):
		return fail(codeResultInvalid, "the result target is not a SemVer release")
	case result.PackageSHA256 != "" && !digestRE.MatchString(result.PackageSHA256):
		return fail(codeResultInvalid, "the result package digest is not SHA-256 hex")
	case result.UpdatedAt.IsZero():
		return fail(codeResultInvalid, "the result has no update time")
	}
	return nil
}
