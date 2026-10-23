package jobs

import (
	"strings"
	"testing"
)

// TestTransitionRejectsIllegalMoves pins the forward-only phase machine.
func TestTransitionRejectsIllegalMoves(t *testing.T) {
	legal := [][2]Phase{
		{PhasePending, PhaseApplying}, {PhasePending, PhaseVerifying}, {PhasePending, PhaseHealthy},
		{PhasePending, PhasePartial}, {PhasePending, PhaseFailed},
		{PhaseApplying, PhaseVerifying}, {PhaseApplying, PhaseHealthy}, {PhaseApplying, PhasePartial},
		{PhaseApplying, PhaseFailed}, {PhaseApplying, PhaseRolledBack},
		{PhaseVerifying, PhaseHealthy}, {PhaseVerifying, PhasePartial}, {PhaseVerifying, PhaseFailed},
		{PhaseVerifying, PhaseRolledBack}, {PhaseHealthy, PhaseHealthy}, {PhasePending, PhasePending},
	}
	for _, move := range legal {
		if err := Transition(move[0], move[1]); err != nil {
			t.Fatalf("%s -> %s rejected: %v", move[0], move[1], err)
		}
	}
	illegal := [][2]Phase{
		{PhasePending, PhaseRolledBack}, {PhaseApplying, PhasePending}, {PhaseVerifying, PhaseApplying},
		{PhaseHealthy, PhaseApplying}, {PhaseFailed, PhasePending}, {PhaseRolledBack, PhaseHealthy},
		{Phase("done"), PhasePending}, {PhasePending, Phase("started")},
	}
	for _, move := range illegal {
		if err := Transition(move[0], move[1]); err == nil {
			t.Fatalf("%s -> %s accepted", move[0], move[1])
		}
	}
}

// TestOperationIDAndTargetAreMandatory keeps a record from existing without a
// correlation id or with a target this binary cannot act on.
func TestOperationIDAndTargetAreMandatory(t *testing.T) {
	if err := ValidateOperationID(""); err == nil || !strings.Contains(err.Error(), "OPERATION_ID_REQUIRED") {
		t.Fatalf("empty operation_id = %v", err)
	}
	for _, id := range []string{"abc", strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		if err := ValidateOperationID(id); err == nil || !strings.Contains(err.Error(), "OPERATION_ID_INVALID") {
			t.Fatalf("operation_id %q = %v", id, err)
		}
	}
	if err := ValidateOperationID(strings.Repeat("ab", 16)); err != nil {
		t.Fatalf("valid operation_id rejected: %v", err)
	}
	target := Target{Version: "1.0.0", ManifestSHA256: strings.Repeat("ab", 32), PolicySchema: 9, CandidateRevision: 3}
	if err := target.Validate(); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Target){
		"floating version":      func(t *Target) { t.Version = "latest" },
		"unpinned manifest":     func(t *Target) { t.ManifestSHA256 = "not-a-digest" },
		"foreign policy schema": func(t *Target) { t.PolicySchema = 0 },
		"no staged revision":    func(t *Target) { t.CandidateRevision = 0 },
	} {
		bad := target
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestRetrySemanticsAreBounded pins retryable phases and the attempt limit.
func TestRetrySemanticsAreBounded(t *testing.T) {
	if !Retryable(PhasePartial) || !Retryable(PhaseFailed) {
		t.Fatal("partial and failed must be retryable")
	}
	for _, p := range []Phase{PhasePending, PhaseApplying, PhaseVerifying, PhaseHealthy, PhaseRolledBack} {
		if Retryable(p) {
			t.Fatalf("%s must not be retryable", p)
		}
	}
	if next, err := NextAttempt(1); err != nil || next != 2 {
		t.Fatalf("attempt 1 -> %d err=%v", next, err)
	}
	if _, err := NextAttempt(RetryLimit); err == nil || !strings.Contains(err.Error(), "TASK_RETRY_EXHAUSTED") {
		t.Fatalf("attempt at the limit = %v", err)
	}
}
