package handler

import (
	"context"
	"embed"
	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	subcore "github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	meshh "github.com/wingsky-1/MeshMux/internal/web/handler/mesh"
	"github.com/wingsky-1/MeshMux/internal/web/handler/node"
	"github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscriber"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscription"
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
	// subscriptionServer is the public download boundary. It runs before the
	// management boundary, so a bearer download never carries a session.
	subscriptionServer *subscription.Server
	// nodeServer is the node lifecycle and Agent channel.
	nodeServer *node.Server
	// meshServer is the Mesh device, enrollment and subnet-route domain.
	meshServer *meshh.Server
	// subscriberServer is the subscriber workspace and the subscription wizard.
	subscriberServer *subscriber.Server
	// policyServer is the route-policy, rule-library and publication domain.
	policyServer *policy.Server
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
	subscriptionServer := subscription.New(rt)
	app := &Server{
		Runtime:            rt,
		subscriptionServer: subscriptionServer,
		nodeServer:         node.New(rt),
		meshServer:         meshh.New(rt, meshnet.NewCLIRunner()),
	}
	app.policyServer = policy.New(rt, policy.Backends{MeshModel: app.meshModelForPolicy})
	app.subscriberServer = subscriber.New(rt, subscriber.Backends{
		RuleLibrary:     app.policyServer.RuleLibrary,
		PublishVerifier: app.policyServer.PublishVerifier,
		Downloads:       subscriptionServer,
	})
	r := chi.NewRouter()
	// The public download boundary runs before the management boundary: a
	// bearer download never carries an admin session and never touches the
	// login rate limit.
	r.Use(app.subscriptionServer.Route)
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
	app.nodeServer.RegisterRoutes(r, infra.JSONAPI, app.Authenticated, app.Mutation)
	// The two read-only Agent channels of the restricted executor (#11c-1) sit
	// with the upgrade domain, but authenticate exactly like the node channel.
	r.Get("/api/agent/upgrade-target/{operationID}", infra.JSONAPI(app.agentUpgradeTarget))
	r.Get("/api/agent/manifest", infra.JSONAPI(app.agentManifest))
	// The subscriber and Line routes are registered before the generic
	// navigation loop, so the real subscriber page owns its path.
	app.subscriberServer.RegisterRoutes(r, app.Authenticated, app.Mutation)
	// The mesh device routes own "/mesh" for the same reason. They include the
	// route approve/revoke pair, which is a separate explicit action.
	app.meshServer.RegisterRoutes(r, app.Authenticated, app.Mutation)
	app.policyServer.RegisterRoutes(r, infra.JSONAPI, app.Authenticated, app.Mutation)
	// /tasks is the read-only upgrade view of issue #11a: the release manifest
	// plus each node's staged vs active readback. #11c-1 adds the explicit
	// "check new version" query and the gated per-node approval; the check is a
	// GET (it stores nothing) and the approval is a CSRF-protected POST.
	r.Get("/tasks", app.Authenticated(app.tasksPage))
	r.Get("/tasks/check", app.Authenticated(app.tasksCheck))
	r.Post("/tasks/approve", infra.JSONAPI(app.Mutation(app.tasksApprove, true)))
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

// meshModelForPolicy is the narrow bridge the policy snapshot uses: it resolves
// one device's read-only mesh model through the Mesh domain and reports whether
// the result carries usable Line labels. It mints no Headscale key.
func (app *Server) meshModelForPolicy(record store.MeshDeviceRecord, now time.Time) (subcore.MeshConfigModel, bool) {
	plan, err := app.meshServer.MeshConfigPreflight(record, now)
	if err != nil || len(plan.Model.LineLabels) == 0 {
		return subcore.MeshConfigModel{}, false
	}
	return plan.Model, true
}
