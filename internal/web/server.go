package web

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/headscale"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	cfg      Config
	store    *store
	log      *slog.Logger
	handler  http.Handler
	now      func() time.Time
	authSlot chan struct{}
	// mesh is the narrow Headscale control-plane adapter behind the mesh
	// pages. The production value is the fixed local CLI runner; HTTP tests
	// replace it with a fake so no Headscale binary or socket is required.
	mesh headscale.Client
}

type requestKey int

const operationKey requestKey = 0

func New(c Config, logger *slog.Logger) (*Server, error) {
	c = sanitizeInstallArtifact(c)
	if err := c.validate(); err != nil {
		return nil, err
	}
	return newServer(c, logger)
}

func sanitizeInstallArtifact(c Config) Config {
	if c.DevHTTP {
		c.InstallArtifact = nil
		return c
	}
	if origin, err := url.Parse(c.Origin); err != nil || origin.Scheme != "https" {
		c.InstallArtifact = nil
	}
	return c
}

// newServer is also used by HTTP tests; the executable must go through New.
func newServer(c Config, logger *slog.Logger) (*Server, error) {
	c = sanitizeInstallArtifact(c)
	s, err := openStore(c.DataDir)
	if err != nil {
		return nil, err
	}
	if err = s.prepareBootstrap(time.Now()); err != nil {
		s.Close()
		return nil, err
	}
	app := &Server{cfg: c, store: s, log: logger, now: time.Now, authSlot: make(chan struct{}, 1), mesh: headscale.NewCLIRunner()}
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
	r.Post("/login", app.mutation(app.login, false))
	r.Post("/setup", app.mutation(app.setup, false))
	r.Post("/logout", app.mutation(app.logout, true))
	r.Post("/password", app.mutation(app.password, true))
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
	r.Post("/nodes/{nodeID}/reissue", app.mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/reissue-pairing", app.mutation(app.nodesReissue, true))
	r.Post("/nodes/{nodeID}/revoke", app.mutation(app.nodesRevoke, true))
	r.Post("/nodes/{nodeID}/revoke-identity", app.mutation(app.nodesRevoke, true))
	// Out binding management. Preview is read-only but keeps the same
	// session + CSRF boundary because it is a management POST.
	// The Out binding endpoints are a JSON management API whose paths live under
	// /nodes. They are marked as JSON here, at registration, so the error writer
	// never has to recognise their path.
	r.Post("/nodes/out/bind", jsonAPI(app.mutation(app.outBind, true)))
	r.Post("/nodes/out/unbind", jsonAPI(app.mutation(app.outUnbind, true)))
	r.Post("/nodes/out/delete", jsonAPI(app.mutation(app.outDelete, true)))
	r.Post("/nodes/out/preview", jsonAPI(app.mutation(app.outPreview, true)))
	// The JSON management routes declare their failure representation here, next
	// to the route. The error writer never infers it from the URL, so moving an
	// endpoint cannot silently change its failure body.
	r.Get("/api/nodes", jsonAPI(app.authenticated(app.nodesList)))
	r.Get("/api/nodes/cli", jsonAPI(app.authenticated(app.installArtifactDownload)))
	// Agent endpoints use Bearer identity, not admin session + browser Origin.
	r.Post("/api/agent/pair", jsonAPI(app.pairAgent))
	r.Get("/api/agent/node", jsonAPI(app.agentMetadata))
	r.Get("/api/agent/config/{revision}", jsonAPI(app.agentCandidate))
	r.Get("/api/agent/tasks", jsonAPI(app.agentTasks))
	r.Post("/api/agent/heartbeat", jsonAPI(app.agentHeartbeat))
	r.Post("/api/agent/result", jsonAPI(app.agentResult))
	// The subscriber and Line routes are registered before the generic
	// navigation loop, so the real subscriber page owns its path.
	app.registerSubscriberRoutes(r)
	// The mesh device routes own "/mesh" for the same reason.
	app.registerMeshRoutes(r)
	// /policies is a read-only snapshot plus two read-only helpers: the validate
	// dry run and the explain query. Neither stores nor publishes a policy.
	r.Get("/policies", app.authenticated(app.policiesPage))
	r.Get("/policies/explain", app.authenticated(app.policiesExplain))
	r.Post("/policies/validate", jsonAPI(app.mutation(app.policiesValidate, true)))
	// Route approval is a separate, explicit action: the page's read-only
	// snapshot never moves a prefix to approved on its own.
	r.Post("/mesh/routes/approve", app.mutation(app.meshRouteApprove, true))
	r.Post("/mesh/routes/revoke", app.mutation(app.meshRouteRevoke, true))
	for _, page := range navigation {
		if page.Path == "/nodes" || page.Path == "/subscribers" || page.Path == "/mesh" || page.Path == "/policies" {
			continue
		}
		p := page
		r.Get(p.Path, app.authenticated(func(w http.ResponseWriter, r *http.Request, sess session) {
			app.render(w, r, 200, Dashboard(pageData{Title: p.Title, Path: p.Path, CSRF: sess.CSRF, Dev: app.cfg.DevHTTP, DirectProxy: app.cfg.DirectProxy}))
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

func (s *Server) Close() error          { return s.store.Close() }
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) boundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := randomToken()[:22]
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
			if recover() != nil {
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
	s.render(w, r, status, ErrorPage(code, message, next, operation(r)))
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
	return s.store.session(token, s.now())
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
	hash, err := s.store.adminHash()
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
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取会话。", "请检查数据库。")
			return
		}
		token, newSess, e := s.store.newSession(false, s.now())
		if e != nil {
			s.fail(w, r, 503, "SESSION_UNAVAILABLE", "暂时无法建立登录会话。", "请稍后重试或检查服务日志。")
			return
		}
		sess = newSess
		s.cookie(w, token, sess.Expires)
	}
	s.render(w, r, 200, AuthPage(setup, sess.CSRF, s.cfg.DevHTTP, "", ""))
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) { s.authPage(w, r, false) }
func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) { s.authPage(w, r, true) }

func (s *Server) mutation(next func(http.ResponseWriter, *http.Request, session), auth bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Serialize security mutations, bounding Argon2 to one 64 MiB operation.
		select {
		case s.authSlot <- struct{}{}:
			defer func() { <-s.authSlot }()
		default:
			w.Header().Set("Retry-After", "2")
			s.fail(w, r, 429, "AUTH_BUSY", "认证请求正在处理中。", "请稍后重试。")
			return
		}
		sess, err := s.current(r)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取会话。", "请检查数据库。")
			return
		}
		if err != nil || (auth && !sess.Auth) || (!auth && sess.Auth) {
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
		if !equal(r.PostForm.Get("csrf"), sess.CSRF) {
			s.fail(w, r, 403, "CSRF_REJECTED", "表单已失效或校验失败。", "请刷新页面后重试。")
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) budget(w http.ResponseWriter, r *http.Request) bool {
	ok, err := s.store.attempt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证登录频率。", "请检查数据库。")
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", "600")
		s.fail(w, r, 429, "AUTH_RATE_LIMITED", "认证尝试过于频繁。", "请等待十分钟后再试。")
		return false
	}
	return true
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
	s.render(w, r, 401, AuthPage(setup, sess.CSRF, s.cfg.DevHTTP, "凭据不正确或已失效，请重新输入。", operation(r)))
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.adminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取管理员状态。", "请检查数据库。")
		return
	}
	if hash != "" {
		s.fail(w, r, 403, "SETUP_CLOSED", "管理员已经初始化。", "请使用登录入口。")
		return
	}
	var valid int
	err = s.store.db.QueryRow("SELECT count(*) FROM bootstrap WHERE id=1 AND token_hash=? AND expires>?", tokenHash(r.PostForm.Get("bootstrap")), s.now().Unix()).Scan(&valid)
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取初始化状态。", "请检查数据库。")
		return
	}
	if valid != 1 {
		s.authFailure(w, r, sess, true)
		return
	}
	if !passwordValid(r.PostForm.Get("password")) {
		s.fail(w, r, 400, "PASSWORD_POLICY", "密码须至少 12 个字符、最多 256 字节。", "建议使用密码管理器生成长密码。")
		return
	}
	hash, err = hashPassword(r.PostForm.Get("password"))
	if err != nil {
		s.fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请检查服务日志。")
		return
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法开始初始化。", "请检查数据库。")
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO admin VALUES(1,?)", hash); err == nil {
		_, err = tx.Exec("DELETE FROM bootstrap; DELETE FROM sessions;")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "初始化未完成。", "请重新打开登录页面确认状态。")
		return
	}
	if err = os.Remove(filepath.Join(s.store.dir, "bootstrap.token")); err != nil && !os.IsNotExist(err) {
		s.event(r, "BOOTSTRAP_FILE_CLEANUP_FAILED")
	}
	s.cookie(w, "", 0)
	s.event(r, "ADMIN_INITIALIZED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.adminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证密码。", "请检查数据库。")
		return
	}
	if hash == "" || !verifyPassword(hash, r.PostForm.Get("password")) {
		s.authFailure(w, r, sess, false)
		return
	}
	// A successful login replaces every previous login. Rotation and revocation
	// commit together, preventing fixation and keeping one active admin session.
	token := randomToken()
	csrf := randomToken()
	expires := s.now().Add(sessionLifetime).Unix()
	tx, err := s.store.db.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法建立会话。", "请重试。")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("DELETE FROM sessions WHERE authenticated=1 OR token_hash=?", sess.Hash)
	if err == nil {
		_, err = tx.Exec("INSERT INTO sessions VALUES(?,?,1,?,?)", tokenHash(token), csrf, expires, s.now().Unix())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法建立会话。", "请重试。")
		return
	}
	s.cookie(w, token, expires)
	s.event(r, "LOGIN_SUCCEEDED")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess session) {
	if _, err := s.store.db.Exec("DELETE FROM sessions WHERE token_hash=?", sess.Hash); err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "注销未完成。", "请重试，尚未确认会话撤销。")
		return
	}
	s.cookie(w, "", 0)
	s.event(r, "LOGOUT_SUCCEEDED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) password(w http.ResponseWriter, r *http.Request, sess session) {
	if !s.budget(w, r) {
		return
	}
	hash, err := s.store.adminHash()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法验证密码。", "请检查数据库。")
		return
	}
	if !verifyPassword(hash, r.PostForm.Get("current_password")) {
		s.event(r, "PASSWORD_CURRENT_REJECTED")
		s.fail(w, r, 401, "AUTH_FAILED", "当前密码不正确。", "请返回设置重新输入。")
		return
	}
	if !passwordValid(r.PostForm.Get("password")) {
		s.fail(w, r, 400, "PASSWORD_POLICY", "新密码须至少 12 个字符、最多 256 字节。", "请返回设置重新填写。")
		return
	}
	newHash, err := hashPassword(r.PostForm.Get("password"))
	if err != nil {
		s.fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请重试。")
		return
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法修改密码。", "请重试。")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE admin SET password_hash=? WHERE id=1", newHash)
	if err == nil {
		_, err = tx.Exec("DELETE FROM sessions")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "密码修改未完成。", "请检查数据库。")
		return
	}
	s.cookie(w, "", 0)
	s.event(r, "PASSWORD_CHANGED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var one int
	if err := s.store.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "数据库不可用。", "请检查服务日志。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, _ session) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"web": "running", "proxy": "not_implemented", "mesh": "not_implemented", "operation_id": operation(r)})
}
func (s *Server) statusFragment(w http.ResponseWriter, r *http.Request, _ session) {
	s.render(w, r, 200, Status(s.now().UTC().Format("15:04:05 UTC")))
}
