package jobs

import (
	"strings"
	"testing"
)

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
