// Package backup is the neutral owner of the upgrade rollback record (#11d
// Task 1r, spec C1-C3/C9/C18). It holds the frozen 11c-3 record schema 1, its
// single encoder, and the one per-operation store both the Node and the Hub use:
// one 0700 directory per operation under the rollback root, holding record.json
// and a copied payload tree or database copy. The record is the same bytes for
// either producer; only its payload_path and payload digest differ.
//
// The record is metadata only: no key, token or subscription URL is ever written
// into it. The payload may contain secrets (Reality keys, the subscription
// credential block, the active sing-box configuration, the Hub database), so it
// is 0700/0600, owned by the writer and never leaves the host.
//
// The package imports the standard library only: it is a leaf both the Agent's
// update executor and the Hub's Web process can depend on without creating a
// module cycle (spec C17).
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// RecordSchema is the on-disk schema of one rollback record. The field set
	// below is frozen for 11c-3: Task 3 writes State/ConfirmedAt, 11d/Task 5
	// writes the irreversible approval bit, and Task 4's revert reads every
	// anchor verbatim. A new field requires a schema bump.
	RecordSchema = 1

	// RecordName is the fixed metadata file inside a holding directory.
	RecordName = "record.json"
	// RecordPart is the scratch file a record is staged in before the rename.
	RecordPart = "record.json.part"
	// PayloadDir is the fixed payload directory inside a holding directory.
	PayloadDir = "payload"
	// PayloadPart is the producer's scratch payload directory inside the
	// operation directory. A single-database producer VACUUMs the database copy
	// here and Write verifies and publishes it.
	PayloadPart = "payload.part"
	// SingleDBName is the one database copy of a PayloadSingleDB payload.
	SingleDBName = "meshmux.db"

	// RecordMaxBytes bounds the metadata file a reader will parse.
	RecordMaxBytes = 64 << 10

	// KeepConfirmed is N-1 for the Node store: after a confirmed upgrade it
	// keeps the single newest confirmed generation, because that is the release
	// a revert must be able to go back to. Failed and staged records are always
	// retained (D1, spec §4.20). The Hub passes keep=2 at its call site
	// (spec C18); this package keeps the count caller-supplied.
	KeepConfirmed = 1

	// TreeFileMaxBytes bounds one file of a copied payload tree. It mirrors the
	// staged-package bound of the update fetch path: a tree payload is an
	// installer snapshot of package-sized binaries. A single-database payload is
	// streamed without this bound, because the Hub database is sized by the
	// deployment, not by the package cap.
	TreeFileMaxBytes = 128 << 20
)

// Record states. The record is written staged and only a confirmed readback may
// release an older generation to GC.
const (
	StateStaged    = "staged"
	StateConfirmed = "confirmed"
	StateFailed    = "failed"
)

// Stable error codes. The record layer keeps the 11c-3 vocabulary: the Web gate
// and the Agent's receipt answer with the same codes, so neither changes when
// the record moves into this package.
const (
	// CodeMissing means no record (or no store) exists at all.
	CodeMissing = "UPDATE_BACKUP_MISSING"
	// CodeCorrupt means a record or payload exists but is not the private,
	// verified shape this package writes.
	CodeCorrupt = "UPDATE_BACKUP_CORRUPT"
	// CodeMismatch means the record exists but names another installed state or
	// another operation identity.
	CodeMismatch = "UPDATE_BACKUP_MISMATCH"
	// CodeOperationInvalid means an operation ID is not 32 lowercase hex.
	CodeOperationInvalid = "OPERATION_ID_INVALID"
	// CodeTargetInvalid means a target version is not a SemVer release.
	CodeTargetInvalid = "UPDATE_TARGET_INVALID"
	// CodeDigestInvalid means a digest is not 64 lowercase hex.
	CodeDigestInvalid = "UPDATE_DIGEST_INVALID"
	// CodeConfirmRefused means a record exists but is not a confirmable staged
	// source.
	CodeConfirmRefused = "UPDATE_CONFIRM_REFUSED"
)

// PayloadKind selects how the payload bytes reach the store.
type PayloadKind int

const (
	// PayloadTree copies a snapshot directory file by file and digests the tree.
	PayloadTree PayloadKind = iota
	// PayloadSingleDB publishes one staged database copy and digests the raw
	// file, which is what a restore re-hashes before it opens anything.
	PayloadSingleDB
)

// Record is the metadata anchor of one rollback source. It is written before the
// package fetch and re-verified before the handoff; restore reads the payload
// through PayloadPath and checks PayloadSHA256 before applying any byte.
//
// The field order, tags and JSON encoding are frozen by 11c-3 (schema 1); the
// payload kind is not a field, so only PayloadPath and the payload digest differ
// between a tree payload and a single-database payload.
type Record struct {
	Schema        int    `json:"schema"`
	OperationID   string `json:"operation_id"`
	FromVersion   string `json:"from_version"`
	TargetVersion string `json:"target_version"`
	// DBSchema is the installed database schema (user_version) the payload was
	// taken from; a Node records 0 because it owns no database.
	DBSchema int64 `json:"db_schema"`
	// PolicySchema is the stored route policy schema (upgrade.PolicySchema),
	// deliberately distinct from DBSchema (spec §4.13).
	PolicySchema   int    `json:"policy_schema"`
	ManifestSHA256 string `json:"manifest_sha256"`
	PackageSHA256  string `json:"package_sha256"`
	// FromPackageSHA256 and FromAgentSHA256 anchor the replaced package and
	// Agent binary; restore only trusts a package that matches them. Either is
	// empty when the host did not record it (legacy install).
	FromPackageSHA256 string `json:"from_package_sha256"`
	FromAgentSHA256   string `json:"from_agent_sha256"`
	// PayloadPath is the absolute 0700 directory holding the copied payload.
	PayloadPath   string `json:"payload_path"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadFiles  int    `json:"payload_files"`
	// IntegrityOK records the post-copy readback of this payload. A Hub DB
	// backup sets it only after PRAGMA integrity_check (Task 5/11d).
	IntegrityOK bool       `json:"integrity_ok"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	// IrreversibleApproved is the Web confirm bit for an irreversible DB
	// migration, stored on the record and never bypassed by a flag (spec
	// §4.15). Metadata only; Task 5 writes it.
	IrreversibleApproved bool `json:"irreversible_approved,omitempty"`
}

// RollbackComplete reports whether the record actually holds files to restore.
// A record written before the installer snapshot retention lands (11c-3 Task 4)
// has an empty payload: it proves the record exists, not that a revert can run.
// The handoff gate requires this, so an empty record never counts as a rollback
// source.
func (record Record) RollbackComplete() bool {
	return record.IntegrityOK && record.PayloadFiles > 0
}

// Spec is one operation's rollback source as the caller knows it.
type Spec struct {
	OperationID       string
	FromVersion       string
	TargetVersion     string
	DBSchema          int64
	PolicySchema      int
	ManifestSHA256    string
	PackageSHA256     string
	FromPackageSHA256 string
	FromAgentSHA256   string
	// SnapshotDir is the installer-provided snapshot the Node copies into its
	// per-operation payload. It is retained for the frozen update.BackupSpec
	// alias; Write takes the payload source from Payload, so a caller that still
	// fills this field must mirror it there.
	SnapshotDir string
	// Now is the clock seam. A nil Now means time.Now.
	Now func() time.Time
}

// Payload is the bytes one operation stores.
type Payload struct {
	Kind PayloadKind
	// SnapshotDir is the source tree of a PayloadTree. An empty value is a real
	// 11c-3 state: the record then covers an empty payload and still verifies.
	SnapshotDir string
	// Check validates the staged payload before it is published. A
	// PayloadSingleDB without Check is refused: the store cannot prove the copy
	// it is about to make authoritative.
	Check func(payloadDir string) error
}

// Paths returns the record and payload paths inside one operation directory. It
// is the only place the two fixed names are joined, so every caller agrees on
// <dir>/record.json and <dir>/payload.
func Paths(dir string) (recordPath, payloadPath string) {
	return filepath.Join(dir, RecordName), filepath.Join(dir, PayloadDir)
}

func (spec Spec) validate() error {
	switch {
	case !opIDRE.MatchString(spec.OperationID):
		return fail(CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	case spec.FromVersion == "" || len(spec.FromVersion) > 128 || strings.ContainsAny(spec.FromVersion, "\x00\n\r/"):
		return fail(CodeCorrupt, "from version is not a plain release string")
	case !targetRE.MatchString(spec.TargetVersion):
		return fail(CodeTargetInvalid, "target is not a SemVer release")
	case spec.DBSchema < 0:
		return fail(CodeCorrupt, "database schema is negative")
	case spec.PolicySchema < 1:
		return fail(CodeCorrupt, "policy schema is not recorded")
	case !digestRE.MatchString(spec.ManifestSHA256):
		return fail(CodeDigestInvalid, "manifest SHA-256 is not 64 lowercase hex")
	case !digestRE.MatchString(spec.PackageSHA256):
		return fail(CodeDigestInvalid, "package SHA-256 is not 64 lowercase hex")
	}
	for _, digest := range []string{spec.FromPackageSHA256, spec.FromAgentSHA256} {
		if digest != "" && !digestRE.MatchString(digest) {
			return fail(CodeCorrupt, "from-* digest is not 64 lowercase hex")
		}
	}
	return nil
}

func (spec Spec) now() time.Time {
	if spec.Now != nil {
		return spec.Now().UTC()
	}
	return time.Now().UTC()
}

func (record Record) sameIdentity(spec Spec) bool {
	return record.OperationID == spec.OperationID && record.FromVersion == spec.FromVersion &&
		record.TargetVersion == spec.TargetVersion && record.DBSchema == spec.DBSchema &&
		record.PolicySchema == spec.PolicySchema && record.ManifestSHA256 == spec.ManifestSHA256 &&
		record.PackageSHA256 == spec.PackageSHA256 &&
		record.FromPackageSHA256 == spec.FromPackageSHA256 && record.FromAgentSHA256 == spec.FromAgentSHA256
}

// newRecord builds the staged record of one written payload. It is the only
// place a Record literal is created, so the frozen schema and the initial state
// cannot drift between the Node and Hub producers.
func newRecord(spec Spec, payloadPath, digest string, files int, now time.Time) Record {
	return Record{
		Schema: RecordSchema, OperationID: spec.OperationID,
		FromVersion: spec.FromVersion, TargetVersion: spec.TargetVersion,
		DBSchema: spec.DBSchema, PolicySchema: spec.PolicySchema,
		ManifestSHA256: spec.ManifestSHA256, PackageSHA256: spec.PackageSHA256,
		FromPackageSHA256: spec.FromPackageSHA256, FromAgentSHA256: spec.FromAgentSHA256,
		PayloadPath: payloadPath, PayloadSHA256: digest, PayloadFiles: files,
		IntegrityOK: true, State: StateStaged, CreatedAt: now,
	}
}

// encodeRecord is the single encoder of the frozen schema (spec C2). Every writer
// in this package and every caller that updates a record in place goes through
// it, so the bytes on disk are a function of the Record value alone.
func encodeRecord(record Record) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fail(CodeCorrupt, "the rollback record could not be encoded")
	}
	return data, nil
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

var (
	// targetRE mirrors upgrade's unexported releaseVersion; keep the two in step.
	targetRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opIDRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

var errPayloadUnsafe = errors.New("payload tree is unsafe")

// ownedBy reports whether info is owned by the named account. Ownership is part
// of the read contract, never a side effect of being able to open the file
// (spec §5.9): a root dispatcher reads a meshmux-owned record by naming meshmux,
// and a caller that names another account is refused.
func ownedBy(owner int, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == owner
}

// syncDir flushes one directory entry after a rename. A failed sync is reported
// rather than ignored: a record that is not on disk is not a rollback source.
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func unixSuffix(t time.Time) string {
	return fmt.Sprintf("%d", t.Unix())
}
