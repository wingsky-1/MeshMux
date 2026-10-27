package handler

import (
	"context"
	"embed"
	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	*infra.Runtime
	// mesh is the narrow Headscale control-plane adapter behind the mesh
	// pages. The production value is the fixed local CLI runner; HTTP tests
	// replace it with a fake so no Headscale binary or socket is required.
	mesh meshnet.Client
	// publishRunner is the fixed process boundary of the publish gate. It is
	// nil in production (node.ExecRunner) and replaced by a fixture runner in
	// tests so no kernel binary is required to exercise the gate.
	publishRunner node.CommandRunner
	// publishGate replaces the whole gate in tests. Production leaves it nil
	// so the real kernel verifier is always built from the deployment
	// configuration; it exists so a unit test never needs a kernel install.
	publishGate func() (store.PublishVerifier, error)
	// releaseSource is the explicit release check's upstream. Production leaves
	// it nil so the fixed GitHub releases endpoint is read; tests inject a
	// deterministic tag without a network. It never approves anything.
	releaseSource func(context.Context) (string, error)
	// identity is the read-only Hub identity snapshot of #11d (spec §5.4). It
	// is refreshed by one bounded 30s ticker started in New and stopped in
	// Close; a page reads it without touching the database. identityMu guards
	// the snapshot and the refresher handles.
	identityMu       sync.RWMutex
	identity         view.HubIdentity
	identityCancel   context.CancelFunc
	identityDone     chan struct{}
	identityInterval time.Duration
	// opTarget is the read-only journal seam for the identity readback. Task 2
	// leaves it nil (no journal yet); Task 5 wires it. It is a field rather
	// than a parameter so the ticker and a page render compare against the
	// same source. Task 5 must inject it before startHubIdentityRefresh starts
	// the refresher: the goroutine reads the field every tick, so assigning it
	// afterwards would both race and leave published snapshots uncompared.
	opTarget opTargetFunc
	// digest is the running executable's SHA-256, computed at most once and
	// only when a verifying operation needs it. It is read-only identity, not
	// a pin.
	digestOnce sync.Once
	digest     string
	digestErr  error
	// hubBackup is the producer seam of the Hub backup route (#11d Task 3r).
	// Production leaves it nil so hubupgrade.CreateBackup always runs; an HTTP
	// test replaces it to prove the boundary and receipt without a root-owned
	// manifest. It is never a caller-supplied callback.
	hubBackup func(context.Context, hubupgrade.BackupConfig) (hubupgrade.BackupReceipt, error)
	// hubApply is the handoff seam of the Hub apply route (#11d Task 5). Same
	// rule as hubBackup: production leaves it nil, a test replaces it.
	hubApply func(context.Context, hubupgrade.HandoffConfig) (hubupgrade.HandoffReceipt, error)
	// reconcileMu guards the reconcile ticker handles. The ticker runs one
	// journal pass every 30s; only the startup pass may judge identity and
	// confirm (spec §5.5).
	reconcileMu       sync.Mutex
	reconcileCancel   context.CancelFunc
	reconcileDone     chan struct{}
	reconcileInterval time.Duration
	// hubRequestDir is the watched request directory unless a test points it
	// at a private fixture. It is not a configuration option: the path unit
	// watches only /run/meshmux-hub/requests.
	hubRequestDir string
	// hubResultsDir is the fixed root:meshmux result tree unless a test
	// points it at a private fixture.
	hubResultsDir string
}

// Config aliases the runtime configuration, so internal/web keeps converting
// into handler.Config without a second copy of the fields.
type Config = infra.Config

// InstallArtifact is the same-origin CLI binary the Nodes page renders.
type InstallArtifact = infra.InstallArtifact

// InstallArtifactMaxBytes bounds the configured CLI artifact and its response;
// web.Config.validate reuses this constant.
const InstallArtifactMaxBytes = infra.InstallArtifactMaxBytes

// session is the handler-local alias of the store session, threaded through the
// authentication wrappers without naming store internals.
type session = infra.Session

// New validates the operator configuration and builds the handler runtime.
// HTTP tests use newServer directly (no lifecycle); the executable must go
// through web.New (validation first).
func New(c Config, logger *slog.Logger) (*Server, error) {
	app, err := newServer(c, logger)
	if err != nil {
		return nil, err
	}
	// The journal adapter must exist before the identity refresher starts: the
	// refresher compares every snapshot against the verifying operation, so a
	// seam assigned later would race it (Task 2 carry). It is a read-only
	// adapter over the same journal the reconcile pass advances.
	app.opTarget = app.hubOpTarget
	// The startup pass is the only one allowed to judge an identity and confirm
	// (spec §5.5): a ticker in the old process cannot tell "not swapped yet"
	// from "swapped and failed". It runs before the refresher so the first
	// published snapshot already sees the confirmed journal state.
	app.reconcileHubUpgrade(context.Background(), true)
	// The read-only identity refresher of #11d (spec §5.4) runs for the life of
	// the process and stops in Close. Observation never depends on a browser
	// request, and the refresher never gates /healthz and never writes: the
	// confirmed row was written once, by openStore, before this point.
	app.startHubIdentityRefresh(context.Background())
	// The journal state machine advances on its own 30s bound (spec §5.5); it
	// never confirms, because only a startup pass may.
	app.startHubUpgradeReconcile(context.Background())
	return app, nil
}

// newServer is also used by HTTP tests; the executable must go through New.
func newServer(c Config, logger *slog.Logger) (*Server, error) {
	rt, err := infra.NewRuntime(c, logger)
	if err != nil {
		return nil, err
	}
	app := &Server{Runtime: rt, mesh: meshnet.NewCLIRunner()}
	r := chi.NewRouter()
	// The public download boundary runs before the management boundary: a
	// bearer download never carries an admin session and never touches the
	// login rate limit.
	r.Use(app.route)
	r.Use(app.Boundary)
	r.Get("/healthz", infra.JSONAPI(app.Health))
	static, _ := fs.Sub(assets, "assets")
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.FS(static))))
	r.Get("/login", app.LoginPage)
	r.Get("/setup", app.SetupPage)
	r.Post("/login", app.Mutation(app.KDFGuard(app.Login), false))
	r.Post("/setup", app.Mutation(app.KDFGuard(app.Setup), false))
	r.Post("/logout", app.Mutation(app.Logout, true))
	r.Post("/password", app.Mutation(app.KDFGuard(app.Password), true))
	r.Get("/api/status", infra.JSONAPI(app.Authenticated(app.Status)))
	r.Get("/status", app.Authenticated(app.StatusFragment))
	r.Get("/nodes", app.Authenticated(func(w http.ResponseWriter, r *http.Request, sess session) {
		app.nodesPage(w, r, sess, nil, "")
	}))
	r.Post("/nodes", app.Mutation(app.nodesCreate, true))
	r.Post("/nodes/reconcile", app.Mutation(app.nodesReconcile, true))
	r.Post("/nodes/reissue", app.Mutation(app.nodesReissue, true))
	r.Post("/nodes/revoke", app.Mutation(app.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/reconcile", app.Mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/recheck", app.Mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/retry", app.Mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/rollback-lkg", app.Mutation(app.nodesRollbackLKG, true))
	r.Post("/nodes/{nodeID}/reissue", app.Mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/reissue-pairing", app.Mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/revoke", app.Mutation(app.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/revoke-identity", app.Mutation(app.nodesRevoke, true))
	// Out management. The binding endpoints are gone with the binding table
	// (Task 5): selecting an Out is a subscription edit. Their paths stay
	// registered and answer one stable "retired" code, so an old client learns
	// where the action moved instead of reading a bare 404 as a typo.
	// Delete is still an Out lifecycle action, not a subscription choice.
	// These are a JSON management API whose paths live under /nodes; they are
	// marked as JSON here, at registration, so the error writer never has to
	// recognise their path.
	r.Post("/nodes/out/bind", infra.JSONAPI(app.Mutation(app.outBindingAPIRetired, true)))
	r.Post("/nodes/out/unbind", infra.JSONAPI(app.Mutation(app.outBindingAPIRetired, true)))
	r.Post("/nodes/out/delete", infra.JSONAPI(app.Mutation(app.outDelete, true)))
	r.Post("/nodes/out/preview", infra.JSONAPI(app.Mutation(app.outPreview, true)))
	// The nodes-page Out actions are the HTML twins of the transport and delete
	// mutations above: same store calls, same session + CSRF boundary, but they
	// re-render the list instead of answering JSON.
	r.Post("/nodes/out-transport", app.Mutation(app.outTransportSet, true))
	r.Post("/nodes/out-unbind", app.Mutation(app.outUnbindPage, true))
	r.Post("/nodes/out-delete", app.Mutation(app.outDeletePage, true))
	// The JSON management routes declare their failure representation here, next
	// to the route. The error writer never infers it from the URL, so moving an
	// endpoint cannot silently change its failure body.
	r.Get("/api/nodes", infra.JSONAPI(app.Authenticated(app.nodesList)))
	r.Get("/api/nodes/cli", infra.JSONAPI(app.Authenticated(app.installArtifactDownload)))
	// Agent endpoints use Bearer identity, not admin session + browser Origin.
	r.Post("/api/agent/pair", infra.JSONAPI(app.pairAgent))
	r.Get("/api/agent/node", infra.JSONAPI(app.agentMetadata))
	r.Get("/api/agent/config/{revision}", infra.JSONAPI(app.agentCandidate))
	// The stamped upgrade target of one stage row (#11c-1): the read-only
	// channel the Agent uses instead of stuffing a target into frozen config.*
	// params.
	r.Get("/api/agent/upgrade-target/{operationID}", infra.JSONAPI(app.agentUpgradeTarget))
	// The read-only release manifest of the restricted executor (#11c-1): the
	// body never travels as config.* params.
	r.Get("/api/agent/manifest", infra.JSONAPI(app.agentManifest))
	r.Get("/api/agent/tasks", infra.JSONAPI(app.agentTasks))
	r.Post("/api/agent/heartbeat", infra.JSONAPI(app.agentHeartbeat))
	r.Post("/api/agent/result", infra.JSONAPI(app.agentResult))
	// The subscriber and Line routes are registered before the generic
	// navigation loop, so the real subscriber page owns its path.
	app.registerSubscriberRoutes(r)
	// The mesh device routes own "/mesh" for the same reason.
	app.registerMeshRoutes(r)
	// /policies is a snapshot, two read-only helpers, four intent writes and
	// the publication gate. Writes persist intent through the 10d-1 store;
	// /policies/publish assembles, gates and stores a candidate revision.
	r.Get("/policies", app.Authenticated(app.policiesPage))
	r.Get("/policies/explain", app.Authenticated(app.policiesExplain))
	r.Post("/policies/validate", infra.JSONAPI(app.Mutation(app.policiesValidate, true)))
	r.Post("/policies/server/preview", infra.JSONAPI(app.Mutation(app.policiesServerPreview, true)))
	r.Post("/policies", infra.JSONAPI(app.Mutation(app.policiesCreate, true)))
	r.Post("/policies/revise", infra.JSONAPI(app.Mutation(app.policiesRevise, true)))
	r.Post("/policies/activate", infra.JSONAPI(app.Mutation(app.policiesActivate, true)))
	r.Post("/policies/revoke", infra.JSONAPI(app.Mutation(app.policiesRevoke, true)))
	// Publication is the gated pipeline: assemble the active revisions, check
	// them with the pinned kernels and store one immutable candidate revision
	// per Line. It is never a bare render-to-response.
	r.Post("/policies/publish", infra.JSONAPI(app.Mutation(app.policiesPublish, true)))
	// /rules is the Task-3 rule library: the read-only list, the create and
	// revise mutations (new versions only), and the two-step delete with
	// used-by protection. Like the nodes-page Out twins, the mutations are
	// HTML forms that re-render the list instead of answering JSON.
	r.Get("/rules", app.Authenticated(app.rulesLibraryPage))
	r.Post("/rules", app.Mutation(app.rulesLibraryCreate, true))
	r.Post("/rules/revise", app.Mutation(app.rulesLibraryRevise, true))
	r.Post("/rules/delete", app.Mutation(app.rulesLibraryDelete, true))
	// /tasks is the read-only upgrade view of issue #11a: the release manifest
	// plus each node's staged vs active readback. #11c-1 adds the explicit
	// "check new version" query and the gated per-node approval; the check is a
	// GET (it stores nothing) and the approval is a CSRF-protected POST.
	r.Get("/tasks", app.Authenticated(app.tasksPage))
	r.Get("/tasks/check", app.Authenticated(app.tasksCheck))
	r.Post("/tasks/approve", infra.JSONAPI(app.Mutation(app.tasksApprove, true)))
	// The irreversible database migration confirmation (11c-3): it stores the
	// explicit operator bit on the Hub database backup record consumed by 11d.
	// It performs no migration and no database edit.
	r.Post("/tasks/db-migration/approve", infra.JSONAPI(app.Mutation(app.tasksDatabaseMigrationApprove, true)))
	// The Hub backup producer (#11d Task 3r): one authenticated mutation that
	// reads a root-owned target manifest and commits one per-operation verified
	// database backup plus its existence-only flat pointer. Apply/restore are
	// Task 5/7; this route never hands off and never upgrades.
	r.Post("/tasks/hub-upgrade/backup", infra.JSONAPI(app.Mutation(app.tasksHubUpgradeBackup, true)))
	// The Hub handoff (#11d Task 5): one authenticated mutation that re-verifies
	// a backed-up operation, stages the root-pinned target package and queues one
	// request under /run. It never waits for the upgrade and never claims one.
	r.Post("/tasks/hub-upgrade/apply", infra.JSONAPI(app.Mutation(app.tasksHubUpgradeApply, true)))
	// The Hub restore (#11d Task 7): one authenticated mutation that queues the
	// old package's restore executor. The receipt is "restoring" — a request
	// exists, not a restored host; the result and the restored marker are the
	// evidence. Root can run the same executor from a console without the Web.
	r.Post("/tasks/hub-upgrade/restore", infra.JSONAPI(app.Mutation(app.tasksHubUpgradeRestore, true)))
	// Route approval is a separate, explicit action: the page's read-only
	// snapshot never moves a prefix to approved on its own.
	r.Post("/mesh/routes/approve", app.Mutation(app.meshRouteApprove, true))
	r.Post("/mesh/routes/revoke", app.Mutation(app.meshRouteRevoke, true))
	for _, page := range view.Navigation {
		if page.Path == "/nodes" || page.Path == "/subscribers" || page.Path == "/mesh" || page.Path == "/policies" || page.Path == "/rules" || page.Path == "/tasks" {
			continue
		}
		p := page
		r.Get(p.Path, app.Authenticated(func(w http.ResponseWriter, r *http.Request, sess session) {
			app.Render(w, r, 200, view.Dashboard(view.PageData{Title: p.Title, Path: p.Path, CSRF: sess.CSRF, Dev: app.Cfg.DevHTTP, DirectProxy: app.Cfg.DirectProxy}))
		}))
	}
	// The fallbacks cover requests that matched no route, so no handler exists to
	// declare a representation. Only here does the router consult the declared
	// JSON namespaces; every matched route declares its own shape.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		app.FailAs(w, r, 404, "NOT_FOUND", "页面不存在。", "请使用控制台导航。", infra.JSONNamespace(r.URL.Path))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		app.FailAs(w, r, 405, "METHOD_NOT_ALLOWED", "此操作不支持该请求方式。", "请重新打开页面。", infra.JSONNamespace(r.URL.Path))
	})
	app.SetHandler(r)
	return app, nil
}

func (s *Server) Close() error {
	s.stopHubUpgradeReconcile()
	s.stopHubIdentityRefresh()
	return s.Store.Close()
}
