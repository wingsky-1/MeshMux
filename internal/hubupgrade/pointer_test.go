package hubupgrade

// Flat-pointer tests of #11d Task 3r (spec §5.2.1): the existence-only copy an
// old binary's schemaTooNew check can name. Nothing in 11d reads it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/backup"
)

// TestPublishFlatPointer pins the flat pointer as a byte copy of the committed
// per-operation record, with the stale scratch path cleared first.
func TestPublishFlatPointer(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	opDir, err := backup.Dir(root, op)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := backup.Spec{
		OperationID: op, FromVersion: "1.0.0", TargetVersion: "1.0.1",
		DBSchema: 10, PolicySchema: 8,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
	}
	if _, err := backup.Write(root, spec, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(opDir, backup.RecordName))
	if err != nil {
		t.Fatal(err)
	}
	// A crash left a scratch pointer behind; the publisher must replace it
	// rather than fail on O_EXCL.
	if err := os.WriteFile(filepath.Join(root, PointerName)+".part", []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PublishFlatPointer(root, op); err != nil {
		t.Fatalf("PublishFlatPointer: %v", err)
	}
	pointer, err := os.ReadFile(filepath.Join(root, PointerName))
	if err != nil {
		t.Fatal(err)
	}
	if string(pointer) != string(committed) {
		t.Fatal("the pointer is not a byte copy of the committed record")
	}
	info, err := os.Lstat(filepath.Join(root, PointerName))
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("pointer mode %v, %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(root, PointerName) + ".part"); !os.IsNotExist(err) {
		t.Fatal("the pointer scratch file survived a publish")
	}
}

// TestPublishFlatPointerRefusesUnreadableRecord pins the failure path: no
// committed record means no pointer and the stable code, never a guess.
func TestPublishFlatPointerRefusesUnreadableRecord(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("a", 32)
	err := PublishFlatPointer(root, op)
	if err == nil || codeOf(err) != "HUB_BACKUP_POINTER_STALE" {
		t.Fatalf("missing record = %v, want HUB_BACKUP_POINTER_STALE", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, PointerName)); !os.IsNotExist(statErr) {
		t.Fatal("a refused publish left a pointer")
	}
	if err := PublishFlatPointer("relative/path", op); err == nil || codeOf(err) != "HUB_BACKUP_POINTER_STALE" {
		t.Fatalf("relative root = %v", err)
	}
	if err := PublishFlatPointer(root, "../"+op); err == nil || codeOf(err) != "HUB_BACKUP_POINTER_STALE" {
		t.Fatalf("malformed operation id = %v", err)
	}
}
