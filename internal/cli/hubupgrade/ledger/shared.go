package ledger

// The small shared helpers that belong to the operation grammar rather than to
// one of its consumers: the journal-to-backup error mapping, the fixed metadata
// encoder, the Web group lookup and the two directory flush shapes.

import (
	"encoding/json"
	"os"
	"os/user"
	"strconv"
)

// backupJournalError maps the journal's own corruption code onto the backup
// group the operator sees on this route. The mapping is by code, never by text.
func backupJournalError(err error) error {
	if codeOf(err) == codeJournalCorrupt {
		return fail("HUB_BACKUP_JOURNAL_FAILED", "the operation journal is not readable")
	}
	return err
}

// marshalIndentNoHTML encodes one fixed metadata document. The exact bytes are
// not a trust anchor, but the indented form keeps the root-written evidence
// readable to an operator without a second decoder.
func marshalIndentNoHTML(document any) ([]byte, error) {
	return json.MarshalIndent(document, "", "  ")
}

// meshmuxGroupID resolves the Web account's group for the claim and result
// files. A missing account means the caller is a test fixture or a broken
// install; the file then stays root:root, which the Web cannot read (stricter,
// not weaker).
func meshmuxGroupID() (int, bool) {
	group, err := user.LookupGroup("meshmux")
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}

// syncDirectory flushes a directory and returns the raw error.
func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
