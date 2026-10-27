// Package upgrade owns the read-only upgrade view and the gated paths around it:
// the /tasks page, the explicit release check and per-node approval, the two
// read-only Agent channels (release manifest and stamped upgrade target), the Hub
// backup/handoff/restore mutations, the journal state machine, and the read-only
// Hub identity readback.
//
// Two facts stay visibly distinct: /healthz answers "can the database answer
// SELECT 1", while the identity readback answers "does this database belong to
// this build". The readback is a consumer only: it refreshes one in-memory
// snapshot and never writes.
package upgrade

import (
	"context"
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// AgentAuth is the Bearer identity check the two Agent channels use. The node
// domain owns it, so the root package passes it in rather than this package
// importing node.
type AgentAuth interface {
	AgentAuth(w http.ResponseWriter, r *http.Request) (store.Node, bool)
	AgentFail(w http.ResponseWriter, r *http.Request, status int, code, message, next string)
}

// Server is the upgrade domain: the runtime, the Agent identity seam and the
// background-pass handles only this domain starts.
type Server struct {
	*infra.Runtime
	// nodeAuth is the Bearer identity check shared with the node domain.
	nodeAuth AgentAuth
	// identity is the read-only Hub identity snapshot of #11d (spec §5.4). It is
	// refreshed by one bounded ticker started in Start and stopped in Close; a
	// page reads it without touching the database. identityMu guards the snapshot
	// and the refresher handles.
	identityMu       sync.RWMutex
	identity         view.HubIdentity
	identityCancel   context.CancelFunc
	identityDone     chan struct{}
	identityInterval time.Duration
	// opTarget is the read-only journal seam for the identity readback. The
	// projection must be wired before the refresher starts: the goroutine reads
	// the field every tick, so assigning it afterwards would both race and leave
	// published snapshots uncompared.
	opTarget opTargetFunc
	// digest is the running executable's SHA-256, computed at most once and only
	// when a verifying operation needs it. It is read-only identity, not a pin.
	digestOnce sync.Once
	digest     string
	digestErr  error
	// hubBackup is the producer seam of the Hub backup route (#11d Task 3r).
	// Production leaves it nil so hubupgrade.CreateBackup always runs; an HTTP
	// test replaces it to prove the boundary and receipt without a root-owned
	// manifest. It is never a caller-supplied callback.
	hubBackup func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error)
	// hubApply is the handoff seam of the Hub apply route (#11d Task 5). Same rule
	// as hubBackup: production leaves it nil, a test replaces it.
	hubApply func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error)
	// reconcileMu guards the reconcile ticker handles. The ticker runs one
	// journal pass every 30s; only the startup pass may judge identity and
	// confirm (spec §5.5).
	reconcileMu       sync.Mutex
	reconcileCancel   context.CancelFunc
	reconcileDone     chan struct{}
	reconcileInterval time.Duration
	// hubRequestDir is the watched request directory unless a test points it at a
	// private fixture. It is not a configuration option: the path unit watches
	// only /run/meshmux-hub/requests.
	hubRequestDir string
	// hubResultsDir is the fixed root:meshmux result tree unless a test points it
	// at a private fixture.
	hubResultsDir string
	// releaseSource is the explicit release check's upstream. Production leaves it
	// nil so the fixed GitHub releases endpoint is read; tests inject a
	// deterministic tag without a network. It never approves anything.
	releaseSource func(context.Context) (string, error)
}

// New builds the upgrade domain over one runtime and the Agent identity seam.
func New(rt *infra.Runtime, nodeAuth AgentAuth) *Server {
	return &Server{Runtime: rt, nodeAuth: nodeAuth}
}

// SetOpTarget wires the journal adapter. The root package must call it before
// Start, so the first published snapshot already compares against the journal.
func (s *Server) SetOpTarget(target func(string) (version, digest string, ok bool)) {
	s.opTarget = target
}

// OpTarget returns the installed journal adapter, or nil.
func (s *Server) OpTarget() func(string) (version, digest string, ok bool) { return s.opTarget }

// SetHubBackup replaces the backup producer. Production never calls it.
func (s *Server) SetHubBackup(fn func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error)) {
	s.hubBackup = fn
}

// SetHubApply replaces the handoff. Production never calls it.
func (s *Server) SetHubApply(fn func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error)) {
	s.hubApply = fn
}

// SetReleaseSource replaces the release-check upstream. Production never calls it.
func (s *Server) SetReleaseSource(fn func(context.Context) (string, error)) { s.releaseSource = fn }

// SetHubRequestDir points the request directory at a test fixture.
func (s *Server) SetHubRequestDir(dir string) { s.hubRequestDir = dir }

// SetHubResultsDir points the result tree at a test fixture.
func (s *Server) SetHubResultsDir(dir string) { s.hubResultsDir = dir }

// SetIdentityInterval shortens the identity refresh for a test.
func (s *Server) SetIdentityInterval(interval time.Duration) { s.identityInterval = interval }

// SetReconcileInterval shortens the reconcile tick for a test.
func (s *Server) SetReconcileInterval(interval time.Duration) { s.reconcileInterval = interval }

// identityIntervalOr is the configured refresh period, or the production bound.
func (s *Server) identityIntervalOr() time.Duration {
	if s.identityInterval > 0 {
		return s.identityInterval
	}
	return hubIdentityRefreshInterval
}

// reconcileIntervalOr is the configured reconcile period, or the production bound.
func (s *Server) reconcileIntervalOr() time.Duration {
	if s.reconcileInterval > 0 {
		return s.reconcileInterval
	}
	return hubUpgradeReconcileInterval
}

// Start runs the startup reconcile pass and starts both bounded loops. It is the
// only caller that may judge an identity: a ticker in the old process cannot tell
// "not swapped yet" from "swapped and failed", so the startup pass runs before
// the refresher publishes its first snapshot.
func (s *Server) Start(ctx context.Context) {
	s.reconcileHubUpgrade(ctx, true)
	s.startHubIdentityRefresh(ctx)
	s.startHubUpgradeReconcile(ctx)
}

// Stop ends both bounded loops and waits for their goroutines to leave their
// current read, so the store is never closed under them.
func (s *Server) Stop() {
	s.stopHubUpgradeReconcile()
	s.stopHubIdentityRefresh()
}

// RegisterRoutes registers /tasks, the release check and approval, the two
// read-only Agent channels, and the Hub backup/handoff/restore mutations.
//
// /tasks is the read-only upgrade view of issue #11a: the release manifest plus
// each node's staged vs active readback. #11c-1 adds the explicit "check new
// version" query and the gated per-node approval; the check is a GET (it stores
// nothing) and the approval is a CSRF-protected POST.
//
// The Hub mutations never wait for the upgrade and never claim one: backup stages
// a verified per-operation backup, apply queues one request under /run, restore
// queues the old package's restore executor.
func (s *Server) RegisterRoutes(r chi.Router, jsonAPI func(http.HandlerFunc) http.HandlerFunc, authenticated func(func(http.ResponseWriter, *http.Request, infra.Session)) http.HandlerFunc, mutation func(func(http.ResponseWriter, *http.Request, infra.Session), bool) http.HandlerFunc) {
	r.Get("/tasks", authenticated(s.tasksPage))
	r.Get("/tasks/check", authenticated(s.tasksCheck))
	r.Post("/tasks/approve", jsonAPI(mutation(s.tasksApprove, true)))
	r.Post("/tasks/hub-upgrade/backup", jsonAPI(mutation(s.tasksHubUpgradeBackup, true)))
	r.Post("/tasks/hub-upgrade/apply", jsonAPI(mutation(s.tasksHubUpgradeApply, true)))
	r.Post("/tasks/hub-upgrade/restore", jsonAPI(mutation(s.tasksHubUpgradeRestore, true)))
	// The two read-only Agent channels of the restricted executor (#11c-1). The
	// stamped target and the manifest body are never stuffed into frozen config.*
	// task params.
	r.Get("/api/agent/upgrade-target/{operationID}", jsonAPI(s.agentUpgradeTarget))
	r.Get("/api/agent/manifest", jsonAPI(s.agentManifest))
}

// The exported seams below exist for the root package's HTTP tests, which drive
// the upgrade routes through the assembled router but must still reach the
// domain's in-memory state. Each one is a plain accessor: no branch, no write
// and no behavior of its own.
func (s *Server) SetIdentityIntervalForTest(d time.Duration)  { s.identityInterval = d }
func (s *Server) SetReconcileIntervalForTest(d time.Duration) { s.reconcileInterval = d }
func (s *Server) SetHubRequestDirForTest(dir string)          { s.hubRequestDir = dir }
func (s *Server) SetHubResultsDirForTest(dir string)          { s.hubResultsDir = dir }
func (s *Server) SetHubBackupForTest(fn func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error)) {
	s.hubBackup = fn
}
func (s *Server) SetHubApplyForTest(fn func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error)) {
	s.hubApply = fn
}
func (s *Server) SetReleaseSourceForTest(fn func(context.Context) (string, error)) {
	s.releaseSource = fn
}
func (s *Server) SetOpTargetForTest(fn func(string) (string, string, bool)) { s.opTarget = fn }
func (s *Server) OpTargetForTest() func(string) (string, string, bool)      { return s.opTarget }
func (s *Server) HubIdentity(now time.Time) view.HubIdentity                { return s.hubIdentity(now) }
func (s *Server) CurrentHubIdentity() view.HubIdentity                      { return s.currentHubIdentity() }
func (s *Server) RefreshHubIdentity() view.HubIdentity                      { return s.refreshHubIdentity() }
func (s *Server) PublishHubIdentity(now time.Time, target func(string) (string, string, bool)) view.HubIdentity {
	return s.publishHubIdentity(now, target)
}
func (s *Server) ReadDatabaseIdentity() (DatabaseIdentity, error)         { return s.readDatabaseIdentity() }
func (s *Server) StartHubIdentityRefresh(ctx context.Context)             { s.startHubIdentityRefresh(ctx) }
func (s *Server) StopHubIdentityRefresh()                                 { s.stopHubIdentityRefresh() }
func (s *Server) StartHubUpgradeReconcile(ctx context.Context)            { s.startHubUpgradeReconcile(ctx) }
func (s *Server) StopHubUpgradeReconcile()                                { s.stopHubUpgradeReconcile() }
func (s *Server) UpgradeView(now time.Time) (view.UpgradeSnapshot, error) { return s.upgradeView(now) }
func (s *Server) HubRequestDirValueForTest() string                       { return s.hubRequestDirValue() }
func (s *Server) HubResultsDirValueForTest() string                       { return s.hubResultsDirValue() }

// ReadDatabaseIdentityFromForTest replays the identity read over an explicit
// handle, so a test can prove the statements are read-only through a mode=ro
// connection instead of trusting the production handle.
func ReadDatabaseIdentityFromForTest(db *sql.DB) (DatabaseIdentity, error) {
	return readDatabaseIdentityFrom(db)
}
