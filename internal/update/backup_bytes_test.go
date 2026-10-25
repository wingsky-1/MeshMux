package update

// The 11c-3 record bytes are frozen: this test pins the exact JSON the old
// in-package writer produced, so moving the encoder into internal/backup cannot
// silently change a single byte of a record that is already on disk.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRecordBytesFrozen(t *testing.T) {
	root := t.TempDir()
	spec := fixtureBackupSpec(t)
	spec.SnapshotDir = ""
	recordPath, err := WriteBackupRecord(root, spec)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	var record BackupRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("record is not JSON: %v", err)
	}
	empty := sha256.Sum256(nil)
	// The layout owns payload_path; the rest is the frozen 11c-3 shape, in the
	// frozen key order, with the empty payload still recorded honestly.
	want := `{
  "schema": 1,
  "operation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "from_version": "1.0.0",
  "target_version": "1.0.1",
  "db_schema": 0,
  "policy_schema": 8,
  "manifest_sha256": "` + strings.Repeat("b", 64) + `",
  "package_sha256": "` + strings.Repeat("c", 64) + `",
  "from_package_sha256": "` + strings.Repeat("d", 64) + `",
  "from_agent_sha256": "` + strings.Repeat("e", 64) + `",
  "payload_path": "` + filepath.Join(root, spec.OperationID, "payload") + `",
  "payload_sha256": "` + hex.EncodeToString(empty[:]) + `",
  "payload_files": 0,
  "integrity_ok": true,
  "state": "staged",
  "created_at": "` + record.CreatedAt.Format(time.RFC3339Nano) + `"
}`
	if string(raw) != want {
		t.Fatalf("record bytes changed:\n got:\n%s\nwant:\n%s", raw, want)
	}
	if record.ConfirmedAt != nil {
		t.Fatalf("a staged record carries confirmed_at: %+v", record)
	}
}
