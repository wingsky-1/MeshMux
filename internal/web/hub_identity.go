package web

// Read-only Hub identity readback for #11d (spec §5.3, §5.4).
//
// Two facts about this build stay visibly distinct:
//
//   - `/healthz` answers "can the database answer SELECT 1". It carries no
//     identity semantics and never writes, so Caddy and the installer keep the
//     exact contract they depend on.
//   - The management surface answers "does this database belong to this
//     build". It consumes `PRAGMA user_version` and the single
//     `database_versions` row and produces one of the three spec §5.4 events:
//     SCHEMA_READBACK_FAILED, DATABASE_UNCONFIRMED or DATABASE_VERSION_MISMATCH.
//     A confirmed identity produces no event.
//
// The readback is a consumer only. It refreshes one in-memory snapshot every 30
// seconds and never writes: `database_versions` is written exactly once per
// start, by confirmDatabaseVersion, after the migration committed. A mismatch is
// not a refusal to serve — the service is running, it just cannot claim its own
// identity yet (spec C7: the row is a downgrade hint, not a migration gate).

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
)

const (
	// codeSchemaReadbackFailed is the management event for a database whose
	// user_version is not the schema this binary owns, or one whose identity
	// could not be read. /healthz still answers 200 while SQLite answers
	// SELECT 1: the storage is readable, the identity is not confirmed.
	codeSchemaReadbackFailed = "SCHEMA_READBACK_FAILED"
	// codeDatabaseUnconfirmed means the schema matches and no started binary
	// has confirmed this database. It is a management event, never a startup
	// refusal.
	codeDatabaseUnconfirmed = "DATABASE_UNCONFIRMED"
	// codeDatabaseVersionMismatch means the row exists but names another
	// version or schema, or names a different target than a verifying upgrade
	// operation. Reported, never rewritten.
	codeDatabaseVersionMismatch = "DATABASE_VERSION_MISMATCH"
)

// hubIdentityRefreshInterval is the bounded refresh period. A test may shorten
// it through Server.identityInterval; production never changes it, and no
// request drives the refresh.
const hubIdentityRefreshInterval = 30 * time.Second

// databaseIdentity is one read-only observation of the database identity: the
// storage schema and the single last-known-good row, when it exists. A missing
// row stays distinct from a row naming an empty release.
type databaseIdentity struct {
	UserVersion int
	Row         databaseVersion
	HasRow      bool
}

// opTargetFunc is the read-only bridge to the #11d operation journal (Task 5).
// It returns the target version and package digest recorded for an operation.
//
// Task 2 has no journal and leaves the seam nil. The operation id is empty when
// the caller has none: the journal admits at most one verifying operation, so
// the adapter resolves that one and may ignore the argument.
type opTargetFunc func(operationID string) (version, digest string, ok bool)

// hubOpTarget is the Task 5 journal adapter of that seam. It resolves the one
// verifying update operation (single-flight means at most one) and returns the
// target and package digest frozen by its backup. It reads only: a corrupt
// journal yields ok=false, because the readback is advisory and must not turn
// an unreadable operation record into a confirmed identity.
func (app *Server) hubOpTarget(operationID string) (version, digest string, ok bool) {
	ops, err := hubupgrade.ListOps(app.store.dir, os.Geteuid())
	if err != nil {
		return "", "", false
	}
	for _, op := range ops {
		if op.Kind != hubupgrade.KindUpdate || op.State != hubupgrade.StateVerifying {
			continue
		}
		if operationID != "" && op.OperationID != operationID {
			continue
		}
		return op.TargetVersion, op.PackageSHA256, true
	}
	return "", "", false
}

// hubIdentitySnapshot is the management view of this build's identity. Code is
// empty when the identity is confirmed; otherwise it is exactly one of the
// spec §5.4 codes.
type hubIdentitySnapshot struct {
	Version     string
	Schema      int
	UserVersion int
	Row         databaseVersion
	HasRow      bool
	Code        string
	CheckedAt   time.Time
}

// Confirmed reports whether this database proved it belongs to the running
// build. It is true only when no event applies and a readback has actually
// happened: the zero value is "not primed yet", not "confirmed".
func (s hubIdentitySnapshot) Confirmed() bool { return s.Code == "" && !s.CheckedAt.IsZero() }

// readDatabaseIdentityFrom reads the two identity facts over an explicit
// handle. The row comes from the existing lastGoodDatabaseVersion reader, so
// there is exactly one place that parses `database_versions`; both calls are
// queries, so the readback cannot write. The test replays it through a
// `mode=ro` connection, which refuses every write, so success proves the
// statements are read-only rather than merely quiet on this fixture.
func readDatabaseIdentityFrom(db *sql.DB) (databaseIdentity, error) {
	var out databaseIdentity
	if err := db.QueryRow("PRAGMA user_version").Scan(&out.UserVersion); err != nil {
		return databaseIdentity{}, errIdentityRead
	}
	row, ok, err := lastGoodDatabaseVersionFrom(db)
	if err != nil {
		return databaseIdentity{}, errIdentityRead
	}
	out.Row, out.HasRow = row, ok
	return out, nil
}

// readDatabaseIdentity is the store's entry point. It is the only identity read
// path: a second one would be a second chance to write.
func (s *store) readDatabaseIdentity() (databaseIdentity, error) {
	return readDatabaseIdentityFrom(s.db)
}

// errIdentityRead marks an identity read that failed. The caller reports
// SCHEMA_READBACK_FAILED and never the SQL text, so a path or statement cannot
// reach a page or a log line.
var errIdentityRead = errors.New(codeSchemaReadbackFailed)

// hubOpTarget is one resolved upgrade target: the release the journal says is
// being verified. Both halves are compared, because a release is proved by the
// running version and package digest together, never by either alone.
type hubOpTarget struct {
	Version string
	Digest  string
}

// judgeHubIdentity applies the spec §5.4 matrix. The first matching row wins,
// so a schema anomaly is never reported as a version mismatch.
//
// The optional target is the journal's verifying operation (Task 5). When one
// exists, the row and the running package digest must both name it: a release
// is proved by version and digest together, never by either alone.
func judgeHubIdentity(ident databaseIdentity, target *hubOpTarget, runningDigest string) string {
	if ident.UserVersion != databaseSchemaVersion {
		return codeSchemaReadbackFailed
	}
	if !ident.HasRow {
		return codeDatabaseUnconfirmed
	}
	if target != nil {
		// A verifying operation that cannot name its target cannot confirm
		// anything; guessing would confirm or reject a release the Hub has no
		// record of. A nil target means no verifying operation exists, so there
		// is nothing to compare against and the build's own identity stands.
		if target.Version == "" || target.Digest == "" {
			return codeDatabaseVersionMismatch
		}
		if ident.Row.Version != target.Version || runningDigest == "" || runningDigest != target.Digest {
			return codeDatabaseVersionMismatch
		}
	}
	if ident.Row.Version != buildinfo.Version || ident.Row.Schema != databaseSchemaVersion {
		return codeDatabaseVersionMismatch
	}
	return ""
}

// hubIdentity is the management readback. It is read-only by construction: the
// only store calls it makes are queries, and the snapshot it produces lives in
// memory.
func (app *Server) hubIdentity(now time.Time) hubIdentitySnapshot {
	return app.hubIdentityAt(now, app.opTarget)
}

// hubIdentityAt is hubIdentity with an explicit journal seam: Task 2 passes
// nil, Task 5 passes the journal adapter. It returns the snapshot and publishes
// nothing, so a page render is a pure read and only the refresher writes memory.
func (app *Server) hubIdentityAt(now time.Time, opTarget opTargetFunc) hubIdentitySnapshot {
	snapshot := hubIdentitySnapshot{Version: buildinfo.Version, Schema: databaseSchemaVersion, CheckedAt: now.UTC()}
	ident, err := app.store.readDatabaseIdentity()
	if err != nil {
		snapshot.Code = codeSchemaReadbackFailed
		return snapshot
	}
	snapshot.UserVersion = ident.UserVersion
	snapshot.Row = ident.Row
	snapshot.HasRow = ident.HasRow
	// The seam resolves the one verifying operation; ok=false means there is
	// none, so the matrix stops at this build's own identity. Task 2 leaves the
	// seam nil and every readback takes that branch.
	var target *hubOpTarget
	if opTarget != nil {
		if version, digest, ok := opTarget(""); ok {
			target = &hubOpTarget{Version: version, Digest: digest}
		}
	}
	snapshot.Code = judgeHubIdentity(ident, target, app.runningDigest(target))
	return snapshot
}

// runningDigest returns the running executable's digest, hashed at most once per
// process. Only a verifying-operation comparison needs it, so an ordinary
// readback never pays for hashing the image, and a digest failure cannot turn a
// confirmed identity into a mismatch.
func (app *Server) runningDigest(target *hubOpTarget) string {
	if target == nil {
		return ""
	}
	app.digestOnce.Do(func() {
		app.digest, app.digestErr = buildinfo.Digest()
	})
	if app.digestErr != nil {
		return ""
	}
	return app.digest
}

// currentHubIdentity returns the last published snapshot without touching the
// database. It never waits for a refresh beyond the mutex.
func (app *Server) currentHubIdentity() hubIdentitySnapshot {
	app.identityMu.RLock()
	defer app.identityMu.RUnlock()
	return app.identity
}

// publishHubIdentity takes one readback and stores it as the published
// snapshot. It is the only writer of app.identity, and it writes memory, never
// SQLite.
func (app *Server) publishHubIdentity(now time.Time, opTarget opTargetFunc) hubIdentitySnapshot {
	snapshot := app.hubIdentityAt(now, opTarget)
	app.identityMu.Lock()
	app.identity = snapshot
	app.identityMu.Unlock()
	return snapshot
}

// refreshHubIdentity publishes one readback now, so a page or a test can advance
// the snapshot without waiting for the ticker. It is still read-only.
func (app *Server) refreshHubIdentity() hubIdentitySnapshot {
	return app.publishHubIdentity(app.now(), app.opTarget)
}

// startHubIdentityRefresh starts the one bounded refresher. Observation does not
// depend on a browser: the snapshot advances on its own after start, and Close
// stops it. now is captured here so a test that replaces app.now cannot race
// the goroutine.
func (app *Server) startHubIdentityRefresh(ctx context.Context) {
	// A second start replaces the first loop instead of leaving it behind.
	app.stopHubIdentityRefresh()
	now := app.now
	interval := hubIdentityRefreshInterval
	if app.identityInterval > 0 {
		interval = app.identityInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	app.identityMu.Lock()
	app.identityCancel, app.identityDone = cancel, done
	app.identityMu.Unlock()
	go func() {
		defer close(done)
		// Prime once so the management snapshot never waits for the first tick.
		app.publishHubIdentity(now(), app.opTarget)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				app.publishHubIdentity(now(), app.opTarget)
			}
		}
	}()
}

// stopHubIdentityRefresh cancels the refresher and waits for the goroutine to
// leave its current bounded read, so the store is never closed under it. It is
// safe to call more than once and when no refresher was started.
func (app *Server) stopHubIdentityRefresh() {
	app.identityMu.Lock()
	cancel, done := app.identityCancel, app.identityDone
	app.identityCancel, app.identityDone = nil, nil
	app.identityMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
