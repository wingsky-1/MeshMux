package jobs

import (
	"errors"
	"regexp"
)

var (
	operationID    = regexp.MustCompile(`^[a-f0-9]{32}$`)
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateOperationID requires the correlation id every revision carries. An
// empty value is a missing correlation, never a valid default.
func ValidateOperationID(id string) error {
	if id == "" {
		return errors.New("OPERATION_ID_REQUIRED: every task revision needs an operation_id")
	}
	if !operationID.MatchString(id) {
		return errors.New("OPERATION_ID_INVALID: need 32 lowercase hex")
	}
	return nil
}

// Target names the release a task record converges a node to. ManifestSHA256
// pins the exact manifest document, so a record never trusts a mutable version
// string alone; CandidateRevision names the candidate revision it maps to.
type Target struct {
	Version           string
	ManifestSHA256    string
	PolicySchema      int
	CandidateRevision int64
}

// Validate refuses a target this binary cannot describe: a floating version, an
// unpinned manifest digest, a missing policy schema or a missing staged revision.
func (t Target) Validate() error {
	switch {
	case !releaseVersion.MatchString(t.Version):
		return errors.New("TARGET_VERSION_INVALID: target is not a SemVer release")
	case !digestSHA256.MatchString(t.ManifestSHA256):
		return errors.New("TARGET_MANIFEST_INVALID: manifest digest is not pinned")
	case t.PolicySchema < 1:
		return errors.New("TARGET_POLICY_SCHEMA_INVALID: policy schema must be positive")
	case t.CandidateRevision < 1:
		return errors.New("TARGET_REVISION_INVALID: target needs a staged candidate revision")
	}
	return nil
}
