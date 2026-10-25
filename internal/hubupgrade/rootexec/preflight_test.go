package rootexec

// Tests for the pre-flight database trial of #11d Task 6 (spec §5.6 step 5).
// The copy is opened read-only and immutable: it can prove readability,
// integrity and the schema version, and it can never migrate or write the
// evidence it is judging.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightDatabaseAcceptsMatchingSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshmux.db")
	createSQLite(t, path, 10)
	if err := PreflightDatabase(path, 10); err != nil {
		t.Fatalf("matching copy refused: %v", err)
	}
}

func TestPreflightDatabaseRejectsForeignSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshmux.db")
	createSQLite(t, path, 11)
	if err := PreflightDatabase(path, 10); err == nil || codeOfError(err) != codePreflight {
		t.Fatalf("foreign schema error = %v", err)
	}
}

func TestPreflightDatabaseRejectsCorruptCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshmux.db")
	if err := os.WriteFile(path, []byte("this is not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightDatabase(path, 10); err == nil || codeOfError(err) != codePreflight {
		t.Fatalf("corrupt copy error = %v", err)
	}
}

func TestPreflightDatabaseRejectsMissingCopy(t *testing.T) {
	if err := PreflightDatabase(filepath.Join(t.TempDir(), "missing.db"), 10); err == nil || codeOfError(err) != codePreflight {
		t.Fatalf("missing copy error = %v", err)
	}
}
