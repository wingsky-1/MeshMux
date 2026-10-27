package handler

import (
	"context"
	"embed"
	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	meshh "github.com/wingsky-1/MeshMux/internal/web/handler/mesh"
	"github.com/wingsky-1/MeshMux/internal/web/handler/node"
	"github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscriber"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/upgrade"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"io/fs"
	"log/slog"
	"net/http"
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
	// upgradeServer is the upgrade view, release approval, Agent upgrade
	// channels and the Hub backup/handoff/restore domain.
	upgradeServer *upgrade.Server
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
	// seam assigned later would race it. The startup pass is the only one allowed
	// to judge an identity and confirm; the read-only refresher then runs for the
	// life of the process. Both stop before Close releases the store.
	app.upgradeServer.SetOpTarget(app.upgradeServer.HubOpTarget)
	app.upgradeServer.Start(context.Background())
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
	app.upgradeServer = upgrade.New(rt, app.nodeServer)
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
	// The subscriber and Line routes are registered before the generic
	// navigation loop, so the real subscriber page owns its path.
	app.subscriberServer.RegisterRoutes(r, app.Authenticated, app.Mutation)
	// The mesh device routes own "/mesh" for the same reason. They include the
	// route approve/revoke pair, which is a separate explicit action.
	app.meshServer.RegisterRoutes(r, app.Authenticated, app.Mutation)
	app.policyServer.RegisterRoutes(r, infra.JSONAPI, app.Authenticated, app.Mutation)
	app.upgradeServer.RegisterRoutes(r, infra.JSONAPI, app.Authenticated, app.Mutation)
	for _, page := range view.Navigation {
		if page.Path == "/nodes" || page.Path == "/subscribers" || page.Path == "/mesh" || page.Path == "/policies" || page.Path == "/rules" || page.Path == "/tasks" || page.Path == "/logs" {
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
	s.upgradeServer.Stop()
	return s.Store.Close()
}
