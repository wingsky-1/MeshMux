package jobs

import (
	"errors"
	"regexp"
)

// Phase is the persisted lifecycle of one task revision. The set matches the
// frozen Agent result statuses and adds rolled_back.
type Phase string

const (
	PhasePending    Phase = "pending"
	PhaseApplying   Phase = "applying"
	PhaseVerifying  Phase = "verifying"
	PhaseHealthy    Phase = "healthy"
	PhasePartial    Phase = "partial"
	PhaseFailed     Phase = "failed"
	PhaseRolledBack Phase = "rolled_back"
)

// RetryLimit bounds the attempts one failure may consume. A retry is a new
// revision with a new operation_id; the failed record is never rewritten.
const RetryLimit = 3

var (
	operationID    = regexp.MustCompile(`^[a-f0-9]{32}$`)
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Valid reports whether p is one of the seven persisted phases.
func (p Phase) Valid() bool {
	switch p {
	case PhasePending, PhaseApplying, PhaseVerifying, PhaseHealthy, PhasePartial, PhaseFailed, PhaseRolledBack:
		return true
	default:
		return false
	}
}

// Final reports whether p ends the revision.
func (p Phase) Final() bool {
	return p == PhaseHealthy || p == PhasePartial || p == PhaseFailed || p == PhaseRolledBack
}

// Retryable reports whether the phase may be retried in a new revision. A
// partial run is retryable because some targets already finished.
func Retryable(p Phase) bool { return p == PhasePartial || p == PhaseFailed }

// Transition validates one phase change. Repeating the current phase is the
// idempotent replay the Agent result path already accepts; anything else must
// move forward, and a final phase never changes.
func Transition(current, next Phase) error {
	if !current.Valid() || !next.Valid() {
		return errors.New("PHASE_UNKNOWN: unknown task phase")
	}
	if current == next {
		return nil
	}
	switch current {
	case PhasePending:
		if next == PhaseApplying || next == PhaseVerifying || next == PhaseHealthy ||
			next == PhasePartial || next == PhaseFailed {
			return nil
		}
	case PhaseApplying:
		if next == PhaseVerifying || next.Final() {
			return nil
		}
	case PhaseVerifying:
		if next.Final() {
			return nil
		}
	}
	return errors.New("PHASE_TRANSITION_INVALID: phase cannot move backwards")
}

// NextAttempt returns the next attempt, bounded by RetryLimit. The caller
// allocates a new operation_id and revision for it.
func NextAttempt(attempt int) (int, error) {
	if attempt < 1 || attempt >= RetryLimit {
		return 0, errors.New("TASK_RETRY_EXHAUSTED: no attempt left")
	}
	return attempt + 1, nil
}

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
