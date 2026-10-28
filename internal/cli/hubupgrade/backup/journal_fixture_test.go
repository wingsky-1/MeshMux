package backup

// The journal fixture shared by the producer tests. The real journal type and
// writers live in the sibling ledger package; this helper builds one valid
// document in the same shape journal_test uses there, so the producer can be
// exercised without starting a second copy of the journal grammar.

import (
	"strings"
	"testing"
	"time"
)

func journalOp(t *testing.T, operationID string, state State) Op {
	t.Helper()
	return Op{
		Schema: 1, OperationID: operationID, Kind: KindUpdate, State: state,
		TargetVersion: "1.0.1", FromVersion: "1.0.0",
		ManifestSHA256:   strings.Repeat("a", 64),
		PackageSHA256:    strings.Repeat("b", 64),
		DBSchema:         10,
		BackupGeneration: 1,
		UpdatedAt:        time.Unix(1700000000, 0).UTC(),
	}
}
