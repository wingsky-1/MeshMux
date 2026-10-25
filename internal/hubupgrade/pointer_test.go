package hubupgrade

// Flat-pointer tests of #11d Task 3r (spec §5.2.1): the existence-only copy an
// old binary's schemaTooNew check can name. Nothing in 11d reads it.

import (
	"errors"
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

// TestPublishFlatPointerValidatesTheSource pins the read path: the pointer is
// copied from a record the record layer accepts, so a symlink, a loose mode,
// trailing data or a record naming another operation never reaches the flat path.
func TestPublishFlatPointerValidatesTheSource(t *testing.T) {
	// seedRecord writes one clean per-operation generation into a fresh store and
	// returns the store root, the operation id and the record path.
	seedRecord := func(t *testing.T) (string, string, string) {
		t.Helper()
		root := t.TempDir()
		op := strings.Repeat("d", 32)
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
		return root, op, filepath.Join(opDir, backup.RecordName)
	}

	t.Run("clean source", func(t *testing.T) {
		root, op, _ := seedRecord(t)
		if err := PublishFlatPointer(root, op); err != nil {
			t.Fatalf("a clean generation was refused: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root, op, recordPath string)
	}{
		{"loose mode", func(t *testing.T, _, _ string, recordPath string) {
			if err := os.Chmod(recordPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, _, _ string, recordPath string) {
			body, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			target := recordPath + ".real"
			if err := os.WriteFile(target, body, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(recordPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, recordPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"trailing data", func(t *testing.T, _, _ string, recordPath string) {
			body, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, append(body, []byte("{}")...), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"another operation", func(t *testing.T, _, _ string, recordPath string) {
			body, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			// A record whose operation_id names a different operation is not a
			// source for this one, even though it decodes.
			other := strings.Repeat("e", 32)
			if err := os.WriteFile(recordPath, []byte(strings.Replace(string(body), `"`+strings.Repeat("d", 32)+`"`, `"`+other+`"`, 1)), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, op, recordPath := seedRecord(t)
			tc.mutate(t, root, op, recordPath)
			err := PublishFlatPointer(root, op)
			if err == nil || codeOf(err) != codePointerStale {
				t.Fatalf("%s source = %v, want %s", tc.name, err, codePointerStale)
			}
			if _, statErr := os.Lstat(filepath.Join(root, PointerName)); !os.IsNotExist(statErr) {
				t.Fatalf("%s source published a pointer", tc.name)
			}
		})
	}
}

// TestPublishFlatPointerUnflushedIsDistinct pins the post-rename failure: the
// pointer is visible on disk, so reporting it as "stale" would tell an operator
// nothing was published. The distinct code keeps the honest fact and stays
// non-fatal.
func TestPublishFlatPointerUnflushedIsDistinct(t *testing.T) {
	root := t.TempDir()
	op := strings.Repeat("e", 32)
	opDir, err := backup.Dir(root, op)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(opDir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("copy"), 0600); err != nil {
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

	old := pointerRootSync
	pointerRootSync = func(string) error { return errors.New("sync failed") }
	defer func() { pointerRootSync = old }()

	err = PublishFlatPointer(root, op)
	if err == nil || codeOf(err) != codePointerUnflushed {
		t.Fatalf("unflushed publish = %v, want %s", err, codePointerUnflushed)
	}
	// The rename already happened: the pointer is present and complete.
	if _, statErr := os.Lstat(filepath.Join(root, PointerName)); statErr != nil {
		t.Fatalf("the published pointer is missing: %v", statErr)
	}
	if code := pointerLogCode(err); code != codePointerUnflushed {
		t.Fatalf("logged code = %s, want %s", code, codePointerUnflushed)
	}
}
