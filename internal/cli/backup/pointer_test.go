package backup

// Reader tests of the flat "latest" pointer: the one chain a downgraded binary's
// SCHEMA_TOO_NEW guidance and the installer's rollback note resolve.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type flatPointerFixture struct {
	root        string
	operationID string
	dir         string
	record      Record
}

func newFlatPointerFixture(t *testing.T) *flatPointerFixture {
	t.Helper()
	f := &flatPointerFixture{
		root:        filepath.Join(t.TempDir(), "database-backup"),
		operationID: strings.Repeat("a", 32),
	}
	dir, err := Dir(f.root, f.operationID)
	if err != nil {
		t.Fatal(err)
	}
	f.dir = dir
	part := filepath.Join(dir, PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, SingleDBName), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := Write(f.root, Spec{
		OperationID: f.operationID, FromVersion: "1.0.0", TargetVersion: "1.1.0",
		DBSchema: 16, PolicySchema: 8,
		ManifestSHA256: strings.Repeat("b", 64), PackageSHA256: strings.Repeat("c", 64),
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, Payload{Kind: PayloadSingleDB, Check: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.record = record
	return f
}

// publish writes the byte-identical flat copy the Hub pointer publisher writes.
func (f *flatPointerFixture) publish(t *testing.T) {
	t.Helper()
	body, err := ReadRecordBytes(f.dir, f.operationID, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, RecordName), body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReadFlatPointerResolvesTheCommittedGeneration(t *testing.T) {
	f := newFlatPointerFixture(t)
	f.publish(t)
	pointer, err := ReadFlatPointer(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if pointer.RecordPath != filepath.Join(f.root, RecordName) {
		t.Fatalf("record path = %s", pointer.RecordPath)
	}
	if pointer.PayloadPath != filepath.Join(f.dir, PayloadDir, SingleDBName) {
		t.Fatalf("payload path = %s", pointer.PayloadPath)
	}
	if pointer.Record.OperationID != f.operationID || pointer.Record.DBSchema != 16 || pointer.Record.FromVersion != "1.0.0" {
		t.Fatalf("record = %+v", pointer.Record)
	}
}

func TestReadFlatPointerRefusesMissingAndDamagedChains(t *testing.T) {
	t.Run("missing pointer", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		if _, err := ReadFlatPointer(f.root, os.Geteuid()); err == nil || !strings.HasPrefix(err.Error(), CodeMissing) {
			t.Fatalf("missing pointer = %v", err)
		}
	})
	t.Run("damaged pointer", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		if err := os.WriteFile(filepath.Join(f.root, RecordName), []byte("not a record"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFlatPointer(f.root, os.Geteuid()); err == nil || !strings.HasPrefix(err.Error(), CodeCorrupt) {
			t.Fatalf("damaged pointer = %v", err)
		}
	})
	t.Run("collected generation", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		f.publish(t)
		if err := os.RemoveAll(f.dir); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFlatPointer(f.root, os.Geteuid()); err == nil || !strings.HasPrefix(err.Error(), CodeCorrupt) {
			t.Fatalf("collected generation = %v", err)
		}
	})
	t.Run("missing payload", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		f.publish(t)
		if err := os.Remove(filepath.Join(f.dir, PayloadDir, SingleDBName)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFlatPointer(f.root, os.Geteuid()); err == nil || !strings.HasPrefix(err.Error(), CodeCorrupt) {
			t.Fatalf("missing payload = %v", err)
		}
	})
	t.Run("stale flat copy", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		f.publish(t)
		// A hand-edited pointer that still parses: its from_version disagrees
		// with the committed generation, so it is not the generation it names.
		body, err := ReadRecordBytes(f.dir, f.operationID, os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		mutated := strings.Replace(string(body), `"from_version": "1.0.0"`, `"from_version": "0.9.0"`, 1)
		if mutated == string(body) {
			t.Fatal("fixture did not mutate the pointer")
		}
		if err := os.WriteFile(filepath.Join(f.root, RecordName), []byte(mutated), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFlatPointer(f.root, os.Geteuid()); err == nil || !strings.HasPrefix(err.Error(), CodeCorrupt) {
			t.Fatalf("stale flat copy = %v", err)
		}
	})
	t.Run("foreign owner", func(t *testing.T) {
		f := newFlatPointerFixture(t)
		f.publish(t)
		if _, err := ReadFlatPointer(f.root, os.Geteuid()+1); err == nil || !strings.HasPrefix(err.Error(), CodeCorrupt) {
			t.Fatalf("foreign owner = %v", err)
		}
	})
}
