package handler

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/meshnet"
	"github.com/wingsky-1/MeshMux/internal/node"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	cfg     Config
	store   *store.Store
	log     *slog.Logger
	handler http.Handler
	now     func() time.Time
	// kdfSlot bounds the password KDF: at most one Argon2id operation (64 MiB)
	// runs at a time, so a burst of login/setup/password requests cannot
	// multiply the hash memory. It is deliberately held by those three routes
	// only: a publication that gates kernels for minutes used to keep the slot,
	// turning an unrelated node creation into a 429.
	kdfSlot chan struct{}
	// pairing is the unauthenticated pairing budget (see pair_limiter.go). It is
	// process-local on purpose: the store has one connection, and a shared
	// database counter on this path would either contend that connection or let
	// an anonymous flood spend the administrator's login budget.
	pairing pairLimiter
	// formKey signs the stateless CSRF token of the unauthenticated login and
	// setup forms (see form_token.go). It is process-local, so a restart only
	// invalidates forms that were open across it.
	formKey []byte
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

type requestKey int

const operationKey requestKey = 0

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
	c = sanitizeInstallArtifact(c)
	s, err := store.OpenStore(c.DataDir)
	if err != nil {
		return nil, err
	}
	if err = s.PrepareBootstrap(time.Now()); err != nil {
		s.Close()
		return nil, err
	}
	app := &Server{cfg: c, store: s, log: logger, now: time.Now, kdfSlot: make(chan struct{}, 1), mesh: meshnet.NewCLIRunner(), formKey: []byte(store.RandomToken())}
	r := chi.NewRouter()
	// The public download boundary runs before the management boundary: a
	// bearer download never carries an admin session and never touches the
	// login rate limit.
	r.Use(app.route)
	r.Use(app.boundary)
	r.Get("/healthz", jsonAPI(app.health))
	static, _ := fs.Sub(assets, "assets")
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.FS(static))))
	r.Get("/login", app.loginPage)
	r.Get("/setup", app.setupPage)
	r.Post("/login", app.mutation(app.kdfGuard(app.login), false))
	r.Post("/setup", app.mutation(app.kdfGuard(app.setup), false))
	r.Post("/logout", app.mutation(app.logout, true))
	r.Post("/password", app.mutation(app.kdfGuard(app.password), true))
	r.Get("/api/status", jsonAPI(app.authenticated(app.status)))
	r.Get("/status", app.authenticated(app.statusFragment))
	r.Get("/nodes", app.authenticated(func(w http.ResponseWriter, r *http.Request, sess session) {
		app.nodesPage(w, r, sess, nil, "")
	}))
	r.Post("/nodes", app.mutation(app.nodesCreate, true))
	r.Post("/nodes/reconcile", app.mutation(app.nodesReconcile, true))
	r.Post("/nodes/reissue", app.mutation(app.nodesReissue, true))
	r.Post("/nodes/revoke", app.mutation(app.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/reconcile", app.mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/recheck", app.mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/retry", app.mutation(app.nodesReconcile, true))
	r.Post("/nodes/{nodeID}/rollback-lkg", app.mutation(app.nodesRollbackLKG, true))
	r.Post("/nodes/{nodeID}/reissue", app.mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/reissue-pairing", app.mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/revoke", app.mutation(app.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/revoke-identity", app.mutation(app.nodesRevoke, true))
	// Out management. The binding endpoints are gone with the binding table
	// (Task 5): selecting an Out is a subscription edit. Their paths stay
	// registered and answer one stable "retired" code, so an old client learns
	// where the action moved instead of reading a bare 404 as a typo.
	// Delete is still an Out lifecycle action, not a subscription choice.
	// These are a JSON management API whose paths live under /nodes; they are
	// marked as JSON here, at registration, so the error writer never has to
	// recognise their path.
	r.Post("/nodes/out/bind", jsonAPI(app.mutation(app.outBindingAPIRetired, true)))
	r.Post("/nodes/out/unbind", jsonAPI(app.mutation(app.outBindingAPIRetired, true)))
	r.Post("/nodes/out/delete", jsonAPI(app.mutation(app.outDelete, true)))
	r.Post("/nodes/out/preview", jsonAPI(app.mutation(app.outPreview, true)))
	// The nodes-page Out actions are the HTML twins of the transport and delete
	// mutations above: same store calls, same session + CSRF boundary, but they
	// re-render the list instead of answering JSON.
	r.Post("/nodes/out-transport", app.mutation(app.outTransportSet, true))
	r.Post("/nodes/http-proxy", app.mutation(app.httpProxySet, true))
	r.Post("/nodes/out-unbind", app.mutation(app.outUnbindPage, true))
	r.Post("/nodes/out-delete", app.mutation(app.outDeletePage, true))
	// The JSON management routes declare their failure representation here, next
	// to the route. The error writer never infers it from the URL, so moving an
	// endpoint cannot silently change its failure body.
	r.Get("/api/nodes", jsonAPI(app.authenticated(app.nodesList)))
	r.Get("/api/nodes/cli", jsonAPI(app.authenticated(app.installArtifactDownload)))
	// Agent endpoints use Bearer identity, not admin session + browser Origin.
	r.Post("/api/agent/pair", jsonAPI(app.pairAgent))
	r.Get("/api/agent/node", jsonAPI(app.agentMetadata))
	r.Get("/api/agent/config/{revision}", jsonAPI(app.agentCandidate))
	// The stamped upgrade target of one stage row (#11c-1): the read-only
	// channel the Agent uses instead of stuffing a target into frozen config.*
	// params.
	r.Get("/api/agent/upgrade-target/{operationID}", jsonAPI(app.agentUpgradeTarget))
	// The read-only release manifest of the restricted executor (#11c-1): the
	// body never travels as config.* params.
	r.Get("/api/agent/manifest", jsonAPI(app.agentManifest))
	r.Get("/api/agent/tasks", jsonAPI(app.agentTasks))
	r.Post("/api/agent/heartbeat", jsonAPI(app.agentHeartbeat))
	r.Post("/api/agent/result", jsonAPI(app.agentResult))
	// The subscriber and Line routes are registered before the generic
	// navigation loop, so the real subscriber page owns its path.
	app.registerSubscriberRoutes(r)
	// The mesh device routes own "/mesh" for the same reason.
	app.registerMeshRoutes(r)
	// /policies is a snapshot, two read-only helpers, four intent writes and
	// the publication gate. Writes persist intent through the 10d-1 store;
	// /policies/publish assembles, gates and stores a candidate revision.
	r.Get("/policies", app.authenticated(app.policiesPage))
	r.Get("/policies/explain", app.authenticated(app.policiesExplain))
	r.Post("/policies/validate", jsonAPI(app.mutation(app.policiesValidate, true)))
	r.Post("/policies/server/preview", jsonAPI(app.mutation(app.policiesServerPreview, true)))
	r.Post("/policies", jsonAPI(app.mutation(app.policiesCreate, true)))
	r.Post("/policies/revise", jsonAPI(app.mutation(app.policiesRevise, true)))
	r.Post("/policies/activate", jsonAPI(app.mutation(app.policiesActivate, true)))
	r.Post("/policies/revoke", jsonAPI(app.mutation(app.policiesRevoke, true)))
	// Publication is the gated pipeline: assemble the active revisions, check
	// them with the pinned kernels and store one immutable candidate revision
	// per Line. It is never a bare render-to-response.
	r.Post("/policies/publish", jsonAPI(app.mutation(app.policiesPublish, true)))
	// /rules is the Task-3 rule library: the read-only list, the create and
	// revise mutations (new versions only), and the two-step delete with
	// used-by protection. Like the nodes-page Out twins, the mutations are
	// HTML forms that re-render the list instead of answering JSON.
	r.Get("/rules", app.authenticated(app.rulesLibraryPage))
	r.Post("/rules", app.mutation(app.rulesLibraryCreate, true))
	r.Post("/rules/revise", app.mutation(app.rulesLibraryRevise, true))
	r.Post("/rules/delete", app.mutation(app.rulesLibraryDelete, true))
	// /tasks is the read-only upgrade view of issue #11a: the release manifest
	// plus each node's staged vs active readback. #11c-1 adds the explicit
	// "check new version" query and the gated per-node approval; the check is a
	// GET (it stores nothing) and the approval is a CSRF-protected POST.
	r.Get("/tasks", app.authenticated(app.tasksPage))
	r.Get("/tasks/check", app.authenticated(app.tasksCheck))
	r.Post("/tasks/approve", jsonAPI(app.mutation(app.tasksApprove, true)))
	// The irreversible database migration confirmation (11c-3): it stores the
	// explicit operator bit on the Hub database backup record consumed by 11d.
	// It performs no migration and no database edit.
	r.Post("/tasks/db-migration/approve", jsonAPI(app.mutation(app.tasksDatabaseMigrationApprove, true)))
	// The Hub backup producer (#11d Task 3r): one authenticated mutation that
	// reads a root-owned target manifest and commits one per-operation verified
	// database backup plus its existence-only flat pointer. Apply/restore are
	// Task 5/7; this route never hands off and never upgrades.
	r.Post("/tasks/hub-upgrade/backup", jsonAPI(app.mutation(app.tasksHubUpgradeBackup, true)))
	// The Hub handoff (#11d Task 5): one authenticated mutation that re-verifies
	// a backed-up operation, stages the root-pinned target package and queues one
	// request under /run. It never waits for the upgrade and never claims one.
	r.Post("/tasks/hub-upgrade/apply", jsonAPI(app.mutation(app.tasksHubUpgradeApply, true)))
	// The Hub restore (#11d Task 7): one authenticated mutation that queues the
	// old package's restore executor. The receipt is "restoring" — a request
	// exists, not a restored host; the result and the restored marker are the
	// evidence. Root can run the same executor from a console without the Web.
	r.Post("/tasks/hub-upgrade/restore", jsonAPI(app.mutation(app.tasksHubUpgradeRestore, true)))
	// Route approval is a separate, explicit action: the page's read-only
	// snapshot never moves a prefix to approved on its own.
	r.Post("/mesh/routes/approve", app.mutation(app.meshRouteApprove, true))
	r.Post("/mesh/routes/revoke", app.mutation(app.meshRouteRevoke, true))
	for _, page := range view.Navigation {
		if page.Path == "/nodes" || page.Path == "/subscribers" || page.Path == "/mesh" || page.Path == "/policies" || page.Path == "/rules" || page.Path == "/tasks" {
			continue
		}
		p := page
		r.Get(p.Path, app.authenticated(func(w http.ResponseWriter, r *http.Request, sess session) {
			app.render(w, r, 200, view.Dashboard(view.PageData{Title: p.Title, Path: p.Path, CSRF: sess.CSRF, Dev: app.cfg.DevHTTP, DirectProxy: app.cfg.DirectProxy}))
		}))
	}
	// The fallbacks cover requests that matched no route, so no handler exists to
	// declare a representation. Only here does the router consult the declared
	// JSON namespaces; every matched route declares its own shape.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		app.failAs(w, r, 404, "NOT_FOUND", "页面不存在。", "请使用控制台导航。", jsonNamespace(r.URL.Path))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		app.failAs(w, r, 405, "METHOD_NOT_ALLOWED", "此操作不支持该请求方式。", "请重新打开页面。", jsonNamespace(r.URL.Path))
	})
	app.handler = r
	return app, nil
}

func (s *Server) Close() error {
	s.stopHubUpgradeReconcile()
	s.stopHubIdentityRefresh()
	return s.store.Close()
}
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) boundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := store.RandomToken()[:22]
		r = r.WithContext(context.WithValue(r.Context(), operationKey, op))
		h := w.Header()
		h.Set("X-Operation-ID", op)
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// no-referrer turns native form POST Origin into null in browsers.
		// same-origin preserves strict Origin validation without leaking URLs off-site.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		// The boundary runs before any route handler, so no handler has declared
		// a representation yet. It consults the same declared JSON namespaces the
		// router fallbacks use; the failure writer itself never inspects a path.
		jsonBody := jsonNamespace(r.URL.Path)
		defer func() {
			if recovered := recover(); recovered != nil {
				// http.ErrAbortHandler is the documented way for a handler to
				// abandon a response whose bytes already started, such as a
				// streamed artifact that stopped matching its pinned digest.
				// Re-panic it so net/http closes the connection instead of this
				// writer appending a 500 to a body that promised its length.
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				s.failAs(w, r, 500, "INTERNAL_ERROR", "请求未完成。", "请凭操作编号检查服务日志。", jsonBody)
			}
		}()
		u, _ := url.Parse(s.cfg.Origin)
		if r.Host != u.Host || r.URL.IsAbs() {
			s.failAs(w, r, 403, "HOST_REJECTED", "请求主机不匹配。", "请使用配置的管理地址。", jsonBody)
			return
		}
		// Outbound Agents authenticate with Bearer identity, not browser Origin.
		if r.Method != "GET" && r.Method != "HEAD" && !agentAPI(r.URL.Path) {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || origins[0] != s.cfg.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				s.failAs(w, r, 403, "ORIGIN_REJECTED", "请求来源不可信。", "请从管理页面重新提交。", jsonBody)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func operation(r *http.Request) string { v, _ := r.Context().Value(operationKey).(string); return v }
func (s *Server) event(r *http.Request, code string) {
	// Allowlisted fields only: never log URLs, headers, forms, usernames or raw errors.
	s.log.Info("web_event", "operation_id", operation(r), "stage", "web", "error_code", code)
}

// jsonResponseKey marks a request whose failure body must be the management JSON
// envelope. The router sets it when it registers a JSON route (see jsonAPI), so
// the representation is declared once next to the route instead of being guessed
// from the path inside the error writer. A renamed or relocated endpoint
// therefore cannot silently change its failure body.
type jsonResponseKeyType struct{}

var jsonResponseKey jsonResponseKeyType

// jsonAPI marks every request that reaches the wrapped route as a JSON API. It
// is applied per route at registration; nothing infers the representation from a
// URL prefix.
func jsonAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(context.WithValue(r.Context(), jsonResponseKey, true)))
	}
}

// jsonNamespace reports whether an unmatched request belongs to a JSON
// namespace. It exists only for the router's NotFound and MethodNotAllowed
// fallbacks: those run when no handler matched, so no handler could declare a
// representation. Every matched route declares its own shape with jsonAPI, and
// the failure writer itself never inspects a path.
func jsonNamespace(path string) bool {
	return path == "/healthz" || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/nodes/out/")
}

// wantsJSON reports whether the route declared a JSON failure body.
func wantsJSON(r *http.Request) bool {
	marked, _ := r.Context().Value(jsonResponseKey).(bool)
	return marked
}

// fail writes one failure in the representation the route declared at
// registration (see jsonAPI). It never inspects the path, so a renamed or
// relocated endpoint cannot silently change its failure body.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	s.failAs(w, r, status, code, message, next, wantsJSON(r))
}

// failAs is the single failure writer. The caller decides the representation.
func (s *Server) failAs(w http.ResponseWriter, r *http.Request, status int, code, message, next string, jsonBody bool) {
	s.event(r, code)
	if jsonBody {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code, "operation_id": operation(r), "stage": "web", "message": message, "next_action": next})
		return
	}
	s.render(w, r, status, view.ErrorPage(code, message, next, operation(r)))
}
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	var b bytes.Buffer
	if err := c.Render(r.Context(), &b); err != nil {
		s.event(r, "RENDER_FAILED")
		http.Error(w, "RENDER_FAILED", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

func (s *Server) cookieName() string {
	if s.cfg.DevHTTP {
		return "meshmux_dev"
	}
	return "__Host-meshmux"
}
func (s *Server) cookie(w http.ResponseWriter, token string, expires int64) {
	age := int(time.Until(time.Unix(expires, 0)).Seconds())
	if token == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", Secure: !s.cfg.DevHTTP, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age, Expires: time.Unix(expires, 0)})
}
func (s *Server) current(r *http.Request) (session, error) {
	var token string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == s.cookieName() {
			token = c.Value
			count++
		}
	}
	if count != 1 {
		return session{}, sql.ErrNoRows
	}
	return s.store.Session(token, s.now())
}
func (s *Server) authenticated(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.current(r)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "暂时无法验证登录状态。", "请检查数据库和服务日志。")
			return
		}
		if err != nil || !sess.Auth {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			s.fail(w, r, 401, "AUTH_REQUIRED", "登录已失效或尚未登录。", "请重新登录。")
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) authPage(w http.ResponseWriter, r *http.Request, setup bool) {
	hash, err := s.store.AdminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取管理员状态。", "请检查数据库。")
		return
	}
	if setup && hash != "" {
		s.fail(w, r, 403, "SETUP_CLOSED", "管理员已经初始化。", "请使用登录入口。")
		return
	}
	if !setup && hash == "" {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	sess, err := s.current(r)
	if err == nil && sess.Auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取会话。", "请检查数据库。")
		return
	}
	// The unauthenticated form needs a CSRF value, never a stored session. The
	// double-submit cookie is the only state it adds, so no amount of anonymous
	// traffic can fill a row cap and take this page away from the administrator
	// who needs it to get back in.
	form, ferr := s.formSession(r, s.now())
	if ferr != nil {
		form = s.newFormSession(w, s.now())
	}
	s.render(w, r, 200, view.AuthPage(setup, form.CSRF, s.cfg.DevHTTP, "", ""))
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) { s.authPage(w, r, false) }
func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) { s.authPage(w, r, true) }

func (s *Server) mutation(next func(http.ResponseWriter, *http.Request, session), auth bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.current(r)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取会话。", "请检查数据库。")
			return
		}
		if !auth {
			// The login and setup forms are CSRF-protected by the stateless
			// double-submit token, not by a stored session (#113 3-3). They never
			// needed a row, and requiring one let anonymous traffic fill the
			// session cap and take the login page away. An authenticated session
			// still may not post to them.
			if err == nil && sess.Auth {
				s.fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
				return
			}
			if sess, err = s.formSession(r, s.now()); err != nil {
				s.fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
				return
			}
		}
		if err != nil || (auth && !sess.Auth) {
			s.fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
			return
		}
		ct, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || ct != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 {
			s.fail(w, r, 415, "FORM_REQUIRED", "请求格式不正确。", "请使用页面表单。")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err = r.ParseForm(); err != nil {
			s.fail(w, r, 400, "FORM_INVALID", "表单过大或格式不正确。", "请重新填写表单。")
			return
		}
		// Reject duplicate fields and URL parameters; never let query data override POST.
		if r.URL.RawQuery != "" {
			s.fail(w, r, 400, "FORM_INVALID", "不接受 URL 表单参数。", "请重新打开页面。")
			return
		}
		for _, values := range r.PostForm {
			if len(values) != 1 {
				s.fail(w, r, 400, "FORM_INVALID", "表单包含重复字段。", "请重新打开页面。")
				return
			}
		}
		if !store.Equal(r.PostForm.Get("csrf"), sess.CSRF) {
			s.fail(w, r, 403, "CSRF_REJECTED", "表单已失效或校验失败。", "请刷新页面后重试。")
			return
		}
		next(w, r, sess)
	}
}

// kdfGuard bounds the password KDF to one Argon2id operation (64 MiB) at a
// time. Only the three routes that prove or derive a password go through it:
// login, setup and password change.
//
// The slot is deliberately not held by any other mutation. It used to wrap
// every management POST, so a publication that gates kernels for minutes kept
// the slot and made an unrelated node creation answer 429. A password hash is
// the only unbounded memory cost that needs serializing; everything else has
// its own narrower guard.
//
// The guard runs after the mutation wrapper has checked the session, form and
// CSRF token, so unauthenticated or forged requests never occupy the slot.
func (s *Server) kdfGuard(next func(http.ResponseWriter, *http.Request, session)) func(http.ResponseWriter, *http.Request, session) {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		select {
		case s.kdfSlot <- struct{}{}:
			defer func() { <-s.kdfSlot }()
		default:
			w.Header().Set("Retry-After", "2")
			s.fail(w, r, 429, "AUTH_KDF_BUSY", "另一个密码运算正在进行中。", "请稍后重试；该限制只影响登录、初始化与改密，其他操作不受影响。")
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) budget(w http.ResponseWriter, r *http.Request) bool {
	ok, retry, err := s.store.Attempt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证登录频率。", "请检查数据库。")
		return false
	}
	if !ok {
		// Report the remaining window instead of a constant, so a locked-out
		// administrator knows when the next attempt can succeed. This reveals
		// nothing about a password: the budget is consumed by right and wrong
		// attempts alike, and a success clears it.
		seconds := int((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.fail(w, r, 429, "AUTH_RATE_LIMITED", "认证尝试过于频繁。", "鉴权预算为 10 次 / 10 分钟，约 "+retryText(seconds)+"后可再试；成功认证会立即清零。已登录会话、只读页面与退出不受此预算影响，请勿反复重试。")
		return false
	}
	return true
}

// retryText renders a wait in the unit an administrator can act on.
func retryText(seconds int) string {
	if seconds < 120 {
		return strconv.Itoa(seconds) + " 秒"
	}
	return strconv.Itoa((seconds+59)/60) + " 分钟"
}

func (s *Server) authFailure(w http.ResponseWriter, r *http.Request, sess session, setup bool) {
	// Caddy must overwrite this dedicated header. Loopback peers are part of the
	// trusted host boundary; X-Forwarded-For/Forwarded/CF headers are NEVER parsed.
	ip := ""
	candidate := false
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.cfg.DirectProxy && net.ParseIP(peer) != nil && net.ParseIP(peer).IsLoopback() {
		values := r.Header.Values("X-MeshMux-Client-IP")
		if len(values) == 1 {
			parsed := net.ParseIP(values[0])
			if parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
				ip = parsed.String()
				candidate = true
			}
		}
	}
	s.log.Warn("authentication_failed", "operation_id", operation(r), "stage", "auth", "error_code", "AUTH_FAILED", "ban_candidate", candidate, "client_ip", ip)
	s.render(w, r, 401, view.AuthPage(setup, sess.CSRF, s.cfg.DevHTTP, "凭据不正确或已失效，请重新输入。", operation(r)))
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.AdminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取管理员状态。", "请检查数据库。")
		return
	}
	if hash != "" {
		s.fail(w, r, 403, "SETUP_CLOSED", "管理员已经初始化。", "请使用登录入口。")
		return
	}
	var valid int
	err = s.store.DB.QueryRow("SELECT count(*) FROM bootstrap WHERE id=1 AND token_hash=? AND expires>?", store.TokenHash(r.PostForm.Get("bootstrap")), s.now().Unix()).Scan(&valid)
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取初始化状态。", "请检查数据库。")
		return
	}
	if valid != 1 {
		s.authFailure(w, r, sess, true)
		return
	}
	if !store.PasswordValid(r.PostForm.Get("password")) {
		s.fail(w, r, 400, "PASSWORD_POLICY", "密码须至少 12 个字符、最多 256 字节。", "建议使用密码管理器生成长密码。")
		return
	}
	hash, err = store.HashPassword(r.PostForm.Get("password"))
	if err != nil {
		s.fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请检查服务日志。")
		return
	}
	tx, err := s.store.DB.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法开始初始化。", "请检查数据库。")
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO admin VALUES(1,?)", hash); err == nil {
		_, err = tx.Exec("DELETE FROM bootstrap; DELETE FROM sessions;")
	}
	// The bootstrap secret and the new password were both proven, so the shared
	// budget is cleared with the same commit: the operator's first login must
	// not inherit the initialization attempt.
	if err == nil {
		err = store.ResetAuthBudget(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "初始化未完成。", "请重新打开登录页面确认状态。")
		return
	}
	if err = os.Remove(filepath.Join(s.store.Dir, "bootstrap.token")); err != nil && !os.IsNotExist(err) {
		s.event(r, "BOOTSTRAP_FILE_CLEANUP_FAILED")
	}
	s.cookie(w, "", 0)
	s.clearFormCookie(w)
	s.event(r, "ADMIN_INITIALIZED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.AdminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证密码。", "请检查数据库。")
		return
	}
	if hash == "" || !store.VerifyPassword(hash, r.PostForm.Get("password")) {
		s.authFailure(w, r, sess, false)
		return
	}
	// A successful login replaces every previous login. Rotation and revocation
	// commit together, preventing fixation and keeping one active admin session.
	token := store.RandomToken()
	csrf := store.RandomToken()
	expires := s.now().Add(store.SessionLifetime).Unix()
	tx, err := s.store.DB.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法建立会话。", "请重试。")
		return
	}
	defer tx.Rollback()
	// Every row is replaced, including any anonymous row left by a build that
	// still minted one for the login form. A successful login is the moment the
	// stored session stops being needed at all.
	_, err = tx.Exec("DELETE FROM sessions")
	if err == nil {
		_, err = tx.Exec("INSERT INTO sessions VALUES(?,?,1,?,?)", store.TokenHash(token), csrf, expires, s.now().Unix())
	}
	// The password was proven, so the shared budget is cleared in this same
	// transaction: ten routine logins never lock the only administrator out,
	// and a session that failed to persist cannot leave a half-applied reset.
	if err == nil {
		err = store.ResetAuthBudget(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法建立会话。", "请重试。")
		return
	}
	s.cookie(w, token, expires)
	// The unauthenticated form token is spent: the session now carries its own
	// CSRF value, so the double-submit cookie is dropped rather than left to
	// outlive the form it protected.
	s.clearFormCookie(w)
	s.event(r, "LOGIN_SUCCEEDED")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess session) {
	if _, err := s.store.DB.Exec("DELETE FROM sessions WHERE token_hash=?", sess.Hash); err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "注销未完成。", "请重试，尚未确认会话撤销。")
		return
	}
	s.cookie(w, "", 0)
	s.clearFormCookie(w)
	s.event(r, "LOGOUT_SUCCEEDED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) password(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.AdminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证密码。", "请检查数据库。")
		return
	}
	if !store.VerifyPassword(hash, r.PostForm.Get("current_password")) {
		s.event(r, "PASSWORD_CURRENT_REJECTED")
		s.fail(w, r, 401, "AUTH_FAILED", "当前密码不正确。", "请返回设置重新输入。")
		return
	}
	if !store.PasswordValid(r.PostForm.Get("password")) {
		s.fail(w, r, 400, "PASSWORD_POLICY", "新密码须至少 12 个字符、最多 256 字节。", "请返回设置重新填写。")
		return
	}
	newHash, err := store.HashPassword(r.PostForm.Get("password"))
	if err != nil {
		s.fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请重试。")
		return
	}
	tx, err := s.store.DB.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法修改密码。", "请重试。")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE admin SET password_hash=? WHERE id=1", newHash)
	if err == nil {
		_, err = tx.Exec("DELETE FROM sessions")
	}
	// The current password was proven and every session is about to be revoked,
	// so the budget is cleared here: otherwise the operator's next login could
	// hit the limit that this successful change just consumed.
	if err == nil {
		err = store.ResetAuthBudget(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "密码修改未完成。", "请检查数据库。")
		return
	}
	s.cookie(w, "", 0)
	s.clearFormCookie(w)
	s.event(r, "PASSWORD_CHANGED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Healthy reports whether the database still answers the /healthz SELECT 1
// contract. It is the watchdog predicate, deliberately the same fact /healthz
// exposes: identity, queue depth and page rendering are not liveness.
func (s *Server) Healthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var one int
	return s.store.DB.QueryRowContext(ctx, "SELECT 1").Scan(&one) == nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var one int
	if err := s.store.DB.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "数据库不可用。", "请检查服务日志。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, _ session) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"web": "running", "proxy": "unknown", "mesh": "unknown", "operation_id": operation(r)})
}
func (s *Server) statusFragment(w http.ResponseWriter, r *http.Request, _ session) {
	s.render(w, r, 200, view.Status(s.now().UTC().Format("15:04:05 UTC")))
}
