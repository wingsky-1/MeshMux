package update

// The updater result file (#11c-2). The transient unit is the only writer: it
// installs the new release, restarts the Agent and then records what happened
// in <operation_id>.result.json. The Agent never waits for the unit and never
// reads the child's mind; it reconciles the marker from this file on its next
// poll or startup (spec §4.7). Keeping the schema fixed and the file 0600 makes
// that read a narrow, auditable boundary instead of a second protocol.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// resultFileSuffix is derived from the operation, never chosen by a caller.
	resultFileSuffix = ".result.json"
	// resultMaxBytes bounds the read: the fixed schema is far smaller, and the
	// Agent must not parse an attacker-sized file.
	resultMaxBytes = 4096

	// ResultPhaseStaged means the verified package is on disk but no install
	// step has run yet.
	ResultPhaseStaged = "staged"
	// ResultPhaseInstalling means the new package started its install and did
	// not reach a restart decision.
	ResultPhaseInstalling = "installing"
	// ResultPhaseInstalledAwaitingRestart means install succeeded and the unit
	// restarted the Agent; whether the release is healthy is the chain's
	// readback verdict, never this file's claim (spec §4.1).
	ResultPhaseInstalledAwaitingRestart = "installed-awaiting-restart"
)

// UpdateResult is the fixed <operation_id>.result.json schema written by the
// transient updater unit. Fields are deliberately few: operation identity, the
// phase reached, the coarse process exit, the verified package digest, the
// target release and the write time. It carries no error prose and no
// readback claim.
type UpdateResult struct {
	OperationID string `json:"operation_id"`
	Phase       string `json:"phase"`
	ExitCode    int    `json:"exit_code"`
	Digest      string `json:"digest"`
	Target      string `json:"target"`
	Timestamp   int64  `json:"ts"`
}

// ResultPath returns the fixed result path of one operation. Callers still go
// through WriteResult/ReadResult, which enforce the name.
func ResultPath(dir, operationID string) string {
	return filepath.Join(dir, operationID+resultFileSuffix)
}

// WriteResult validates and publishes one result record atomically with mode
// 0600. A crash leaves either the previous file or the complete new one, never
// a truncated record the Agent would have to guess about.
func WriteResult(path string, result UpdateResult) error {
	if err := validateUpdateResult(path, result); err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return fail("UPDATE_RESULT_WRITE_FAILED", "the result record could not be encoded")
	}
	data = append(data, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".result-*.part")
	if err != nil {
		return fail("UPDATE_RESULT_WRITE_FAILED", "the result directory is not writable")
	}
	temp := file.Name()
	defer func() {
		if temp != "" {
			_ = os.Remove(temp)
		}
	}()
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail("UPDATE_RESULT_WRITE_FAILED", "the result record could not be written")
	}
	if err = os.Rename(temp, path); err != nil {
		return fail("UPDATE_RESULT_WRITE_FAILED", "the result record could not be published")
	}
	temp = ""
	return nil
}

// ReadResult reads one fixed-schema result. An unsafe file (symlink, wrong
// owner, not exactly 0600), an unknown field, a malformed value or a name that
// does not derive from its operation is a stable refusal, never a partial
// record.
func ReadResult(path string) (UpdateResult, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return UpdateResult{}, fail("UPDATE_RESULT_UNAVAILABLE", "the result file could not be read")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return UpdateResult{}, fail("UPDATE_RESULT_UNAVAILABLE", "the result file could not be read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || int(stat.Uid) != os.Geteuid() {
		return UpdateResult{}, errors.New("UPDATE_RESULT_UNSAFE: the result file is not a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, resultMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > resultMaxBytes {
		return UpdateResult{}, fail("UPDATE_RESULT_INVALID", "the result file is empty, unreadable or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result UpdateResult
	if err = decoder.Decode(&result); err != nil {
		return UpdateResult{}, fail("UPDATE_RESULT_INVALID", "the result file is not the fixed schema")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return UpdateResult{}, fail("UPDATE_RESULT_INVALID", "the result file has trailing data")
	}
	if err = validateUpdateResult(path, result); err != nil {
		return UpdateResult{}, err
	}
	return result, nil
}

func validateUpdateResult(path string, result UpdateResult) error {
	if filepath.Base(path) != result.OperationID+resultFileSuffix {
		return fail("UPDATE_RESULT_INVALID", "the file name must be <operation_id>.result.json")
	}
	if !opIDRE.MatchString(result.OperationID) {
		return fail("UPDATE_RESULT_INVALID", "operation ID is not 32 lowercase hex")
	}
	switch result.Phase {
	case ResultPhaseStaged, ResultPhaseInstalling, ResultPhaseInstalledAwaitingRestart:
	default:
		return fail("UPDATE_RESULT_INVALID", "phase is not staged, installing or installed-awaiting-restart")
	}
	if result.ExitCode < 0 || result.ExitCode > 255 {
		return fail("UPDATE_RESULT_INVALID", "exit code is outside 0..255")
	}
	if !digestRE.MatchString(result.Digest) {
		return fail("UPDATE_RESULT_INVALID", "digest is not 64 lowercase hex")
	}
	if !targetRE.MatchString(result.Target) {
		return fail("UPDATE_RESULT_INVALID", "target is not a pinned SemVer release")
	}
	if result.Timestamp < 1 {
		return fail("UPDATE_RESULT_INVALID", "ts is not a positive Unix timestamp")
	}
	return nil
}
