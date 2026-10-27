package rootexec

// The pre-flight database trial of #11d Task 6 (spec §5.6 step 5, second oracle
// carry).
//
// Before a byte of the running installation moves, the new executor opens the
// frozen backup copy exactly as the new Hub would have to open it: read-only,
// immutable, after an integrity check, and it reads the copy's own
// user_version. A target binary that cannot open the database it is about to
// run against is refused here, while every earlier state is still intact —
// instead of after the Web restart, where only a restore is left.
//
// The copy is opened with mode=ro&immutable=1, the same contract the Web
// producer used, so this check can never write or migrate the evidence it is
// judging.

import (
	"context"
	"database/sql"
	"net/url"
	"os"

	_ "modernc.org/sqlite"
)

// PreflightDatabase proves that copyPath is a readable SQLite database whose
// user_version equals wantSchema. Every failure is HUB_UPDATE_PREFLIGHT_FAILED.
func PreflightDatabase(copyPath string, wantSchema int64) error {
	info, err := os.Lstat(copyPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 {
		return fail(codePreflight, "the frozen database copy is not a regular file")
	}
	u := url.URL{Scheme: "file", Path: copyPath}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1")
	if err != nil {
		return fail(codePreflight, "the frozen database copy could not be opened")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fail(codePreflight, "integrity_check could not run on the database copy")
	}
	if integrity != "ok" {
		return fail(codePreflight, "the database copy did not pass integrity_check")
	}
	var version int64
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fail(codePreflight, "the database copy's user_version could not be read")
	}
	if version != wantSchema {
		return fail(codePreflight, "the database copy's schema does not match the frozen record")
	}
	return nil
}
