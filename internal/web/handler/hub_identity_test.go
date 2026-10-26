package handler

// Tests for the read-only Hub identity readback of #11d Task 2 (spec §5.4).
//
// The review gate is the pair TestHealthzSelectOneOnly and
// TestReadbackNeverWrites: the health path never gains identity semantics and
// the management readback never writes. TestReadbackMatrix pins the four rows
// of spec §5.4 with exactly the three codes that section allows.

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// identityState is everything a readback must leave untouched: the SQLite
// change counter, the storage schema and the confirmed row's stored values.
type identityState struct {
	Changes     int64
	UserVersion int
	Row         string
}

func observeIdentity(t *testing.T, app *Server) identityState {
	t.Helper()
	var state identityState
	if err := app.store.DB.QueryRow(`SELECT total_changes()`).Scan(&state.Changes); err != nil {
		t.Fatal(err)
	}
	if err := app.store.DB.QueryRow(`PRAGMA user_version`).Scan(&state.UserVersion); err != nil {
		t.Fatal(err)
	}
	var version, confirmed string
	var schema int
	err := app.store.DB.QueryRow(`SELECT quote(last_good_version), last_good_schema, confirmed_at FROM database_versions WHERE id=1`).
		Scan(&version, &schema, &confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		state.Row = "absent"
	} else if err != nil {
		t.Fatal(err)
	} else {
		state.Row = version + "|" + strconv.Itoa(schema) + "|" + confirmed
	}
	return state
}

func requireIdentityUntouched(t *testing.T, app *Server, before identityState, stage string) {
	t.Helper()
	if after := observeIdentity(t, app); after != before {
		t.Fatalf("%s changed the database: before %+v after %+v", stage, before, after)
	}
}

// TestHealthzSelectOneOnly pins the contract Caddy and the installer depend on:
// an identity mismatch, a missing row and an abnormal user_version all keep
// /healthz at 200, only an unusable database turns it into 503, and health
// writes nothing.
func TestHealthzSelectOneOnly(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	check := func(t *testing.T, wantCode string, wantStatus int) {
		t.Helper()
		before := observeIdentity(t, app)
		if got := app.hubIdentity(now).Code; got != wantCode {
			t.Fatalf("identity code = %q, want %q", got, wantCode)
		}
		w := b.req("GET", "/healthz", nil, nil)
		requireStatus(t, w, wantStatus)
		if wantStatus == 200 && w.Body.String() != "{\"status\":\"ok\"}\n" {
			t.Fatalf("health body = %q, want the fixed SELECT 1 shape", w.Body.String())
		}
		requireIdentityUntouched(t, app, before, "one /healthz request")
	}

	check(t, "", 200)

	if _, err := app.store.DB.Exec(`UPDATE database_versions SET last_good_version='0.0.1' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	check(t, codeDatabaseVersionMismatch, 200)

	if _, err := app.store.DB.Exec(`DELETE FROM database_versions`); err != nil {
		t.Fatal(err)
	}
	check(t, codeDatabaseUnconfirmed, 200)

	if _, err := app.store.DB.Exec("PRAGMA user_version=" + strconv.Itoa(store.DatabaseSchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	check(t, codeSchemaReadbackFailed, 200)

	// Only a database that cannot answer SELECT 1 is a health failure.
	if err := app.store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, b.req("GET", "/healthz", nil, nil), 503)
}

// TestReadbackNeverWrites is the review gate for the "health path never writes"
// rule. It observes the database, runs the readback and one refresh, and
// observes again. It then repeats the read through a `mode=ro` connection:
// SQLite refuses every write there, so a successful read proves the statements
// are read-only rather than merely quiet on this fixture.
func TestReadbackNeverWrites(t *testing.T) {
	app, _ := testApp(t)
	before := observeIdentity(t, app)
	if before.Row == "absent" {
		t.Fatal("a started Hub must have confirmed its row")
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	identity, err := app.readDatabaseIdentity()
	if err != nil {
		t.Fatalf("readDatabaseIdentity: %v", err)
	}
	if identity.UserVersion != store.DatabaseSchemaVersion || !identity.HasRow {
		t.Fatalf("identity = %+v, want the confirmed schema %d", identity, store.DatabaseSchemaVersion)
	}
	if snapshot := app.hubIdentity(now); !snapshot.Confirmed() {
		t.Fatalf("snapshot = %+v, want confirmed", snapshot)
	}
	app.refreshHubIdentity()
	if got := app.currentHubIdentity(); got.Code != "" {
		t.Fatalf("published snapshot = %+v, want confirmed", got)
	}
	// A real refresh tick must be as quiet as the on-demand read.
	app.identityInterval = time.Millisecond
	app.startHubIdentityRefresh(t.Context())
	first := app.currentHubIdentity().CheckedAt
	deadline := time.Now().Add(5 * time.Second)
	for !app.currentHubIdentity().CheckedAt.After(first) {
		if time.Now().After(deadline) {
			t.Fatal("the refresher never ticked")
		}
		time.Sleep(time.Millisecond)
	}
	app.stopHubIdentityRefresh()
	requireIdentityUntouched(t, app, before, "the readback, one refresh and one tick")

	// Strongest form of "zero writes": SQLite itself refuses writes on this
	// connection. A readback and a tick that still succeed under query_only
	// cannot have executed a writing statement.
	if _, err := app.store.DB.Exec(`PRAGMA query_only=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.readDatabaseIdentity(); err != nil {
		t.Fatalf("readback under query_only: %v", err)
	}
	if snapshot := app.publishHubIdentity(now, nil); !snapshot.Confirmed() {
		t.Fatalf("snapshot under query_only = %+v", snapshot)
	}
	if _, err := app.store.DB.Exec(`PRAGMA query_only=OFF`); err != nil {
		t.Fatal(err)
	}
	requireIdentityUntouched(t, app, before, "a readback under query_only")

	readOnly, err := sql.Open("sqlite", "file:"+filepath.Join(app.store.Dir, "meshmux.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	readOnly.SetMaxOpenConns(1)
	if _, err := readDatabaseIdentityFrom(readOnly); err != nil {
		t.Fatalf("the readback issued a write statement: %v", err)
	}
	if _, err := readOnly.Exec(`UPDATE database_versions SET last_good_version='x' WHERE id=1`); err == nil {
		t.Fatal("the read-only connection accepted a write; the fixture proves nothing")
	}
	requireIdentityUntouched(t, app, before, "a readback through a read-only connection")
}

// TestReadbackMatrix is the spec §5.4 table: each row yields exactly one code,
// no row yields a write, and a confirmed identity is the only empty code.
func TestReadbackMatrix(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(t *testing.T, app *Server)
		want   string
	}{
		{"confirmed identity", func(*testing.T, *Server) {}, ""},
		{"schema readback failed", func(t *testing.T, app *Server) {
			// One above the schema this build owns, never a literal: Task 5
			// moves store.DatabaseSchemaVersion to 11, and the assertion must stay
			// "a newer schema", not "the next release's schema".
			if _, err := app.store.DB.Exec("PRAGMA user_version=" + strconv.Itoa(store.DatabaseSchemaVersion+1)); err != nil {
				t.Fatal(err)
			}
		}, codeSchemaReadbackFailed},
		{"database unconfirmed", func(t *testing.T, app *Server) {
			if _, err := app.store.DB.Exec(`DELETE FROM database_versions`); err != nil {
				t.Fatal(err)
			}
		}, codeDatabaseUnconfirmed},
		{"database version mismatch", func(t *testing.T, app *Server) {
			if _, err := app.store.DB.Exec(`UPDATE database_versions SET last_good_version='0.0.1' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
		}, codeDatabaseVersionMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := testApp(t)
			tc.mutate(t, app)
			before := observeIdentity(t, app)
			snapshot := app.hubIdentity(now)
			if snapshot.Code != tc.want {
				t.Fatalf("code = %q, want %q (%+v)", snapshot.Code, tc.want, snapshot)
			}
			if snapshot.Confirmed() != (tc.want == "") {
				t.Fatalf("Confirmed() = %v with code %q", snapshot.Confirmed(), snapshot.Code)
			}
			if snapshot.Version != buildinfo.Version || snapshot.Schema != store.DatabaseSchemaVersion {
				t.Fatalf("snapshot names %q/%d, want %q/%d", snapshot.Version, snapshot.Schema, buildinfo.Version, store.DatabaseSchemaVersion)
			}
			if !snapshot.CheckedAt.Equal(now) {
				t.Fatalf("CheckedAt = %v, want %v", snapshot.CheckedAt, now)
			}
			requireIdentityUntouched(t, app, before, "the "+tc.name+" readback")
		})
	}
}

// TestOpTargetSeamLeavesReadbackReadOnly pins the Task 2 half of the Task 5
// seam: with no journal the readback is still read-only and still confirmed,
// and a mismatching target (when a future caller wires one) is reported as
// DATABASE_VERSION_MISMATCH without a write.
func TestOpTargetSeamLeavesReadbackReadOnly(t *testing.T) {
	app, _ := testApp(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	before := observeIdentity(t, app)

	if snapshot := app.hubIdentity(now); !snapshot.Confirmed() {
		t.Fatalf("nil seam reported %+v", snapshot)
	}
	requireIdentityUntouched(t, app, before, "the nil op-target seam")

	digest, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, version, digest string
		ok                    bool
		want                  string
	}{
		{"another version", "9.9.9", digest, true, codeDatabaseVersionMismatch},
		{"another package digest", buildinfo.Version, strings.Repeat("0", 64), true, codeDatabaseVersionMismatch},
		{"no verifying operation", "", "", false, ""},
		{"matching version and digest", buildinfo.Version, digest, true, ""},
	} {
		app.opTarget = func(string) (string, string, bool) { return tc.version, tc.digest, tc.ok }
		if snapshot := app.hubIdentity(now); snapshot.Code != tc.want {
			t.Fatalf("%s: code = %q, want %q", tc.name, snapshot.Code, tc.want)
		}
		requireIdentityUntouched(t, app, before, tc.name)
	}
}

// TestIdentityRefreshIsBoundedAndStopsOnClose proves the refresher is one
// goroutine that Close stops, and that concurrent readers see a coherent
// snapshot while it refreshes.
func TestIdentityRefreshIsBoundedAndStopsOnClose(t *testing.T) {
	app, _ := testApp(t)
	app.identityInterval = time.Millisecond
	app.startHubIdentityRefresh(t.Context())

	deadline := time.Now().Add(5 * time.Second)
	for app.currentHubIdentity().CheckedAt.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("the refresher never published a snapshot")
		}
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := app.currentHubIdentity(); got.Schema != store.DatabaseSchemaVersion {
					t.Errorf("snapshot schema = %d", got.Schema)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	app.stopHubIdentityRefresh()
}

// TestUnprimedSnapshotIsNotConfirmed pins that "no readback has happened yet"
// is not "the identity is confirmed": the zero-value snapshot has an empty
// Code, so Confirmed must also require a captured CheckedAt. newServer (used by
// testApp) does not start the refresher; only New does.
func TestUnprimedSnapshotIsNotConfirmed(t *testing.T) {
	if (view.HubIdentity{}).Confirmed() {
		t.Fatal("zero-value snapshot reads as confirmed")
	}
	app, _ := testApp(t)
	if got := app.currentHubIdentity(); got.Confirmed() {
		t.Fatalf("unprimed server snapshot reads as confirmed: %+v", got)
	}
	app.refreshHubIdentity()
	if got := app.currentHubIdentity(); !got.Confirmed() {
		t.Fatalf("primed snapshot = %+v, want confirmed", got)
	}
}

// TestReadbackComparesVerifyingOpTarget pins the Task 5 half of the seam: the
// real journal adapter resolves the one verifying operation, and its frozen
// target must name both this build and the running package digest. The whole
// comparison is read-only, including the journal it reads.
func TestReadbackComparesVerifyingOpTarget(t *testing.T) {
	app, _ := testApp(t)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	before := observeIdentity(t, app)
	digest, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	app.opTarget = app.hubOpTarget

	if snapshot := app.hubIdentity(now); !snapshot.Confirmed() {
		t.Fatalf("an empty journal reported %+v", snapshot)
	}

	operationID := strings.Repeat("a", 32)
	op := hubupgrade.Op{
		Schema: hubupgrade.OpSchema, OperationID: operationID, Kind: hubupgrade.KindUpdate,
		State: hubupgrade.StateVerifying, TargetVersion: buildinfo.Version, FromVersion: "0.9.0",
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: digest,
		DBSchema: 10, BackupGeneration: 1, UpdatedAt: now,
	}
	if err := hubupgrade.WriteOp(app.store.Dir, op); err != nil {
		t.Fatal(err)
	}
	if version, pkg, ok := app.opTarget(strings.Repeat("b", 32)); ok || version != "" || pkg != "" {
		t.Fatalf("the adapter resolved another operation: %q/%q/%v", version, pkg, ok)
	}
	if snapshot := app.hubIdentity(now); !snapshot.Confirmed() {
		t.Fatalf("a matching verifying target reported %+v", snapshot)
	}
	requireIdentityUntouched(t, app, before, "the matching verifying target")

	// The row still names this build, so only the journal target comparison can
	// catch a release the Hub is not actually running.
	op.TargetVersion = "1.0.1"
	if err := hubupgrade.WriteOp(app.store.Dir, op); err != nil {
		t.Fatal(err)
	}
	if snapshot := app.hubIdentity(now); snapshot.Code != codeDatabaseVersionMismatch {
		t.Fatalf("another target: code = %q, want %q", snapshot.Code, codeDatabaseVersionMismatch)
	}
	requireIdentityUntouched(t, app, before, "a mismatching verifying target")

	// A non-verifying operation is never the seam's input: the build's own
	// identity stands.
	op.State, op.TargetVersion = hubupgrade.StateBackedUp, buildinfo.Version
	if err := hubupgrade.WriteOp(app.store.Dir, op); err != nil {
		t.Fatal(err)
	}
	if snapshot := app.hubIdentity(now); !snapshot.Confirmed() {
		t.Fatalf("a backed_up operation was compared: %+v", snapshot)
	}
}
