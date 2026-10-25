package backup

// The record is the frozen 11c-3 schema 1 anchor. These tests pin the parts of
// the contract that the new layout parameter must not disturb: one encoder, one
// field order, one byte stream, and a payload_path that is decided by the layout
// and then pinned on the record (spec C2/N4).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRecordByteCompatAcrossLayouts is the single-encoder property: the layout
// only decides where the record and its payload live, never how the record is
// encoded. The same Spec and the same payload bytes therefore produce the same
// record bytes under both layouts, except the one field the layout owns
// (payload_path), and the frozen 11c-3 key order is untouched.
func TestRecordByteCompatAcrossLayouts(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	spec := testSpec(op)
	spec.Now = func() time.Time { return now }
	db := []byte("SQLite format 3\x00fixture database bytes\n")

	perOpDir := filepath.Join(root, op)
	stageDB(t, perOpDir, db)
	perOp, err := Write(root, spec, LayoutPerOp, Payload{Kind: PayloadSingleDB, Check: noCheck})
	if err != nil {
		t.Fatalf("per-op write: %v", err)
	}
	flatRoot := filepath.Join(root, "flat")
	flat := writeDB(t, flatRoot, spec, db)

	perOpRecordPath, perOpPayloadPath := Paths(perOpDir, LayoutPerOp)
	flatRecordPath, flatPayloadPath := Paths(flatRoot, LayoutFlat)
	if perOp.PayloadPath != perOpPayloadPath {
		t.Fatalf("per-op payload_path = %q, want %q", perOp.PayloadPath, perOpPayloadPath)
	}
	if flat.PayloadPath != flatPayloadPath {
		t.Fatalf("flat payload_path = %q, want %q", flat.PayloadPath, flatPayloadPath)
	}

	perOpBytes, err := os.ReadFile(perOpRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	flatBytes, err := os.ReadFile(flatRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(raw []byte, payloadPath string) []byte {
		return bytes.ReplaceAll(raw, []byte(payloadPath), []byte("<payload>"))
	}
	if !bytes.Equal(normalize(perOpBytes, perOpPayloadPath), normalize(flatBytes, flatPayloadPath)) {
		t.Fatalf("record bytes differ beyond payload_path:\nper-op:\n%s\nflat:\n%s", perOpBytes, flatBytes)
	}

	// Everything else is the same identity tuple: the layout only chooses where
	// the record and payload live.
	if perOp.OperationID != flat.OperationID || perOp.FromVersion != flat.FromVersion ||
		perOp.TargetVersion != flat.TargetVersion || perOp.DBSchema != flat.DBSchema ||
		perOp.PolicySchema != flat.PolicySchema || perOp.ManifestSHA256 != flat.ManifestSHA256 ||
		perOp.PackageSHA256 != flat.PackageSHA256 || perOp.FromPackageSHA256 != flat.FromPackageSHA256 ||
		perOp.FromAgentSHA256 != flat.FromAgentSHA256 || perOp.PayloadSHA256 != flat.PayloadSHA256 ||
		perOp.PayloadFiles != flat.PayloadFiles || perOp.State != flat.State ||
		!perOp.CreatedAt.Equal(flat.CreatedAt) {
		t.Fatalf("identity tuple differs across layouts:\nper-op: %+v\nflat: %+v", perOp, flat)
	}

	// The frozen 11c-3 key order: a reordering would change the bytes of every
	// record already on disk and break the byte-compat promise.
	wantOrder := []string{
		`"schema"`, `"operation_id"`, `"from_version"`, `"target_version"`, `"db_schema"`,
		`"policy_schema"`, `"manifest_sha256"`, `"package_sha256"`, `"from_package_sha256"`,
		`"from_agent_sha256"`, `"payload_path"`, `"payload_sha256"`, `"payload_files"`,
		`"integrity_ok"`, `"state"`, `"created_at"`,
	}
	position := 0
	for _, key := range wantOrder {
		index := bytes.Index(perOpBytes[position:], []byte(key))
		if index < 0 {
			t.Fatalf("record lost the frozen key %s or reordered it:\n%s", key, perOpBytes)
		}
		position += index + len(key)
	}

	// The encoder is the only writer: the bytes Write published are exactly the
	// bytes the encoder produces for the record it returned.
	encoded, err := encodeRecord(flat)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, flatBytes) {
		t.Fatalf("published bytes are not the encoder's output:\npublished:\n%s\nencoded:\n%s", flatBytes, encoded)
	}
}

// TestFlatPayloadPathPinned pins the Hub slot: <root>/payload, 0700, holding one
// 0600 database copy next to a 0600 record.json in the slot root.
func TestFlatPayloadPathPinned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "database-backup")
	record := writeDB(t, root, testSpec(strings.Repeat("a", 32)), []byte("fixture database\n"))
	if want := filepath.Join(root, PayloadDir); record.PayloadPath != want {
		t.Fatalf("payload_path = %q, want %q", record.PayloadPath, want)
	}
	requireMode(t, record.PayloadPath, 0700)
	requireMode(t, filepath.Join(record.PayloadPath, SingleDBName), 0600)
	requireMode(t, filepath.Join(root, RecordName), 0600)
	if record.PayloadFiles != 1 {
		t.Fatalf("payload_files = %d, want 1", record.PayloadFiles)
	}
}

// TestFlatRejectsPerOpResidue pins the layout split: a flat store never adopts
// (or migrates) a per-operation directory. A refused write leaves the current
// generation byte-identical, and the reader never looks into the residue.
func TestFlatRejectsPerOpResidue(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	writeDB(t, root, testSpec(op), []byte("fixture database\n"))
	recordPath := filepath.Join(root, RecordName)
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(root, strings.Repeat("f", 32))
	if err := os.MkdirAll(residue, 0700); err != nil {
		t.Fatal(err)
	}
	stageDB(t, root, []byte("another fixture database\n"))
	_, err = Write(root, testSpec(strings.Repeat("c", 32)), LayoutFlat, Payload{Kind: PayloadSingleDB, Check: noCheck})
	if codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
		t.Fatalf("flat write with per-op residue = %v, want UPDATE_BACKUP_CORRUPT", err)
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused flat write changed the record")
	}
	if _, statErr := os.Lstat(residue); statErr != nil {
		t.Fatalf("the per-op residue was migrated away: %v", statErr)
	}
	// Every entry point refuses the mixed layout: it is never adopted, never
	// migrated, and never silently read past.
	if _, err := Read(root, op, LayoutFlat, os.Geteuid()); codeOf(err) != CodeCorrupt {
		t.Fatalf("flat read with per-op residue = %v, want %s", err, CodeCorrupt)
	}
	if _, err := Verify(root, op, "1.0.0", 10, testPolicySchema, LayoutFlat, os.Geteuid()); codeOf(err) != CodeCorrupt {
		t.Fatalf("flat verify with per-op residue = %v, want %s", err, CodeCorrupt)
	}
	if _, err := Confirm(root, op, "1.0.1", strings.Repeat("c", 64), LayoutFlat, time.Now().UTC()); codeOf(err) != CodeCorrupt {
		t.Fatalf("flat confirm with per-op residue = %v, want %s", err, CodeCorrupt)
	}
}

// TestReadRejectsUnknownFieldAndTrailingData pins the strict decoder in both
// layouts: a future field is never silently truncated into today's semantics and
// trailing bytes are corruption, not a second record.
func TestReadRejectsUnknownFieldAndTrailingData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layout Layout
		write  func(t *testing.T, root string) (string, string)
	}{
		{"per-op", LayoutPerOp, func(t *testing.T, root string) (string, string) {
			op := strings.Repeat("a", 32)
			writeTree(t, root, testSpec(op))
			path, _ := Paths(filepath.Join(root, op), LayoutPerOp)
			return path, op
		}},
		{"flat", LayoutFlat, func(t *testing.T, root string) (string, string) {
			op := strings.Repeat("b", 32)
			writeDB(t, root, testSpec(op), []byte("fixture database\n"))
			path, _ := Paths(root, LayoutFlat)
			return path, op
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			recordPath, op := tc.write(t, root)
			original, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}

			var fields map[string]any
			if err := json.Unmarshal(original, &fields); err != nil {
				t.Fatal(err)
			}
			fields["caller_selected"] = true
			unknown, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, unknown, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(root, op, tc.layout, os.Geteuid()); codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
				t.Fatalf("unknown field = %v, want UPDATE_BACKUP_CORRUPT", err)
			}

			trailing := append(append([]byte{}, original...), []byte("\n{\"schema\":1}")...)
			if err := os.WriteFile(recordPath, trailing, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(root, op, tc.layout, os.Geteuid()); codeOf(err) != "UPDATE_BACKUP_CORRUPT" {
				t.Fatalf("trailing data = %v, want UPDATE_BACKUP_CORRUPT", err)
			}
		})
	}
}

// TestSingleDBPayloadSHA256IsFileDigest pins the single-database payload: the
// recorded digest is the raw SHA-256 of meshmux.db (what a restore re-hashes
// before touching anything), never a tree digest, and it covers one file.
func TestSingleDBPayloadSHA256IsFileDigest(t *testing.T) {
	root := t.TempDir()
	db := []byte("SQLite format 3\x00fixture database bytes\n")
	record := writeDB(t, root, testSpec(strings.Repeat("a", 32)), db)

	sum := sha256.Sum256(db)
	if want := hex.EncodeToString(sum[:]); record.PayloadSHA256 != want {
		t.Fatalf("payload_sha256 = %q, want the raw file digest %q", record.PayloadSHA256, want)
	}
	if record.PayloadFiles != 1 {
		t.Fatalf("payload_files = %d, want 1", record.PayloadFiles)
	}
	treeDigest, treeFiles, err := hashPayloadTree(record.PayloadPath, true, 0, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if treeDigest == record.PayloadSHA256 {
		t.Fatalf("payload_sha256 is the tree digest %q, want the raw file digest", treeDigest)
	}
	if treeFiles != 1 {
		t.Fatalf("payload tree holds %d files, want the single database copy", treeFiles)
	}
}
