package backup

// The record is the frozen 11c-3 schema 1 anchor. These tests pin the parts of
// the contract the per-operation store must not disturb: one encoder, one field
// order, one byte stream, and a payload_path that is always
// <root>/<op32hex>/payload (spec C2/N4, 11d Task 1r).

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

// TestRecordByteCompatNodeAndHub pins the single-encoder rule across the two
// producers that share schema 1: the Node writes a PayloadTree, the Hub writes a
// PayloadSingleDB, and the payload kind is not a record field. With the same
// Spec, clock, operation id and a one-file payload on both sides, the records
// differ only in the two values derived from the payload itself: the
// root-qualified payload_path and the payload digest (tree digest versus raw
// database-file digest). The frozen 11c-3 key order is untouched.
func TestRecordByteCompatNodeAndHub(t *testing.T) {
	nodeRoot := t.TempDir()
	hubRoot := t.TempDir()
	op := strings.Repeat("a", 32)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	spec := testSpec(op)
	spec.Now = func() time.Time { return now }
	db := []byte("SQLite format 3\x00fixture database bytes\n")

	source := filepath.Join(t.TempDir(), "snapshot")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, SingleDBName), db, 0600); err != nil {
		t.Fatal(err)
	}
	node, err := Write(nodeRoot, spec, Payload{Kind: PayloadTree, SnapshotDir: source})
	if err != nil {
		t.Fatalf("node write: %v", err)
	}
	hub := writePerOpDB(t, hubRoot, spec, db)

	nodeRecordPath, nodePayloadPath := Paths(filepath.Join(nodeRoot, op))
	hubRecordPath, hubPayloadPath := Paths(filepath.Join(hubRoot, op))
	if node.PayloadPath != nodePayloadPath {
		t.Fatalf("node payload_path = %q, want %q", node.PayloadPath, nodePayloadPath)
	}
	if hub.PayloadPath != hubPayloadPath {
		t.Fatalf("hub payload_path = %q, want %q", hub.PayloadPath, hubPayloadPath)
	}

	nodeBytes, err := os.ReadFile(nodeRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	hubBytes, err := os.ReadFile(hubRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(raw []byte, payloadPath, digest string) []byte {
		raw = bytes.ReplaceAll(raw, []byte(payloadPath), []byte("<payload>"))
		return bytes.ReplaceAll(raw, []byte(digest), []byte("<payload-sha256>"))
	}
	if !bytes.Equal(normalize(nodeBytes, nodePayloadPath, node.PayloadSHA256), normalize(hubBytes, hubPayloadPath, hub.PayloadSHA256)) {
		t.Fatalf("record bytes differ beyond the payload values:\nnode:\n%s\nhub:\n%s", nodeBytes, hubBytes)
	}

	// The payload kind is not a record field: every metadata value agrees.
	if node.Schema != hub.Schema || node.OperationID != hub.OperationID ||
		node.FromVersion != hub.FromVersion || node.TargetVersion != hub.TargetVersion ||
		node.DBSchema != hub.DBSchema || node.PolicySchema != hub.PolicySchema ||
		node.ManifestSHA256 != hub.ManifestSHA256 || node.PackageSHA256 != hub.PackageSHA256 ||
		node.FromPackageSHA256 != hub.FromPackageSHA256 || node.FromAgentSHA256 != hub.FromAgentSHA256 ||
		node.PayloadFiles != hub.PayloadFiles || node.IntegrityOK != hub.IntegrityOK ||
		node.State != hub.State || !node.CreatedAt.Equal(hub.CreatedAt) ||
		node.ConfirmedAt != nil || hub.ConfirmedAt != nil || node.IrreversibleApproved || hub.IrreversibleApproved {
		t.Fatalf("metadata differs across producers:\nnode: %+v\nhub: %+v", node, hub)
	}
	// The digests are the only payload-derived difference: the Hub records the
	// raw file digest a restore re-hashes, the Node records the tree digest.
	sum := sha256.Sum256(db)
	if want := hex.EncodeToString(sum[:]); hub.PayloadSHA256 != want {
		t.Fatalf("hub payload_sha256 = %q, want the raw file digest %q", hub.PayloadSHA256, want)
	}
	if node.PayloadSHA256 == hub.PayloadSHA256 {
		t.Fatalf("tree digest equals the raw file digest: %q", node.PayloadSHA256)
	}
	if node.PayloadFiles != 1 || hub.PayloadFiles != 1 {
		t.Fatalf("payload_files = %d/%d, want one each", node.PayloadFiles, hub.PayloadFiles)
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
		index := bytes.Index(nodeBytes[position:], []byte(key))
		if index < 0 {
			t.Fatalf("record lost the frozen key %s or reordered it:\n%s", key, nodeBytes)
		}
		position += index + len(key)
	}

	// The encoder is the only writer: the bytes Write published are exactly the
	// bytes the encoder produces for the record it returned.
	for _, tc := range []struct {
		name   string
		record Record
		stored []byte
	}{{"node", node, nodeBytes}, {"hub", hub, hubBytes}} {
		encoded, err := encodeRecord(tc.record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, tc.stored) {
			t.Fatalf("%s published bytes are not the encoder's output:\npublished:\n%s\nencoded:\n%s", tc.name, tc.stored, encoded)
		}
	}
}

// TestReadRejectsUnknownFieldAndTrailingData pins the strict decoder: a future
// field is never silently truncated into today's semantics and trailing bytes
// are corruption, not a second record.
func TestReadRejectsUnknownFieldAndTrailingData(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	writeTree(t, root, testSpec(op))
	recordPath, _ := Paths(filepath.Join(root, op))
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
	if _, err := Read(root, op, os.Geteuid()); codeOf(err) != CodeCorrupt {
		t.Fatalf("unknown field = %v, want %s", err, CodeCorrupt)
	}

	trailing := append(append([]byte{}, original...), []byte("\n{\"schema\":1}")...)
	if err := os.WriteFile(recordPath, trailing, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, op, os.Geteuid()); codeOf(err) != CodeCorrupt {
		t.Fatalf("trailing data = %v, want %s", err, CodeCorrupt)
	}
}
