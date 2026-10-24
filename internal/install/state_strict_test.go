package install

// The installer ledger is a local trust boundary: a hand-edited or
// newer-writer field must fail closed instead of being silently dropped by a
// lenient decoder. #11c-3 spec §4.12 aligns `readStateAt` with the Agent state
// reader: unknown fields, trailing documents and a foreign schema are all
// `INSTALL_STATE_INVALID`; the directory/file permission checks stay separate.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLedger writes one ledger document at the fixed installer path under an
// isolated root with the private modes ReadState requires.
func writeLedger(t *testing.T, root string, data []byte) {
	t.Helper()
	path := rooted(root, installerStatePath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func validLedgerJSON(t *testing.T) []byte {
	t.Helper()
	state := InstallState{
		Schema: 1, OperationID: strings.Repeat("a", 32), Status: "installed",
		Stage: "verify", Architecture: "amd64",
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireStateInvalid(t *testing.T, root string) {
	t.Helper()
	_, exists, err := ReadState(root)
	if err == nil || !strings.HasPrefix(err.Error(), "INSTALL_STATE_INVALID") {
		t.Fatalf("ledger accepted: exists=%v err=%v", exists, err)
	}
}

func TestLedgerStrictReadRefusesUnknownFields(t *testing.T) {
	t.Run("current schema still reads", func(t *testing.T) {
		root := t.TempDir()
		writeLedger(t, root, validLedgerJSON(t))
		state, exists, err := ReadState(root)
		if err != nil || !exists || state.OperationID != strings.Repeat("a", 32) {
			t.Fatalf("valid ledger: %+v exists=%v err=%v", state, exists, err)
		}
	})

	t.Run("unknown top-level field", func(t *testing.T) {
		root := t.TempDir()
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(validLedgerJSON(t), &doc); err != nil {
			t.Fatal(err)
		}
		doc["future_writer_field"] = json.RawMessage(`"silently-dropped-before"`)
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		writeLedger(t, root, data)
		requireStateInvalid(t, root)
	})

	t.Run("unknown nested node field", func(t *testing.T) {
		root := t.TempDir()
		// Only the fields ReadState itself requires plus a node object carrying a
		// field this build cannot interpret.
		writeLedger(t, root, []byte(`{"schema":1,"operation_id":"`+strings.Repeat("b", 32)+
			`","status":"installed","node":{"future_node_field":true}}`))
		requireStateInvalid(t, root)
	})

	t.Run("trailing document", func(t *testing.T) {
		root := t.TempDir()
		writeLedger(t, root, append(validLedgerJSON(t), []byte("\n{\"schema\":1}")...))
		requireStateInvalid(t, root)
	})

	t.Run("foreign schema unchanged", func(t *testing.T) {
		root := t.TempDir()
		writeLedger(t, root, []byte(`{"schema":2,"operation_id":"`+strings.Repeat("c", 32)+`","status":"installed"}`))
		requireStateInvalid(t, root)
	})
}
