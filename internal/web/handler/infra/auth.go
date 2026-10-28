package infra

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// Event writes one audit event at Warn. The level is a visibility floor, not a
// severity judgement: the process floor is Warn (internal/logging), so an Info
// audit line would never reach the journal at all. An audit event is a business
// fact an operator must be able to find afterwards, and its cadence is one line
// per operator action. A path that repeats on every poll must use EventAt with
// Debug instead (see agentHeartbeat).
func (rt *Runtime) Event(r *http.Request, code string) {
	rt.EventAt(r, slog.LevelWarn, code)
}

// EventAt writes one audit event at an explicit severity. Three tiers exist:
//
//   - Warn (Event): a business fact or a refusal, one line per operator action.
//     This is the only tier visible at the default floor.
//   - Info: per-step detail of one operation, such as the agent_task_result line
//     a recorded task result emits. Restored by MESHMUX_LOG_LEVEL=info.
//   - Debug: a path a node repeats on every poll. A 1s heartbeat cannot write a
//     line per tick, so its success path lands here.
func (rt *Runtime) EventAt(r *http.Request, level slog.Level, code string) {
	// Allowlisted fields only: never log URLs, headers, forms, usernames or raw errors.
	rt.Log.Log(r.Context(), level, "web_event", "operation_id", Operation(r), "stage", "web", "error_code", code)
}

// jsonAPI marks every request that reaches the wrapped route as a JSON API. It
// is applied per route at registration; nothing infers the representation from a
// URL prefix.
func JSONAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(context.WithValue(r.Context(), jsonResponseKey, true)))
	}
}

// jsonNamespace reports whether an unmatched request belongs to a JSON
// namespace. It exists only for the router's NotFound and MethodNotAllowed
// fallbacks: those run when no handler matched, so no handler could declare a
// representation. Every matched route declares its own shape with jsonAPI, and
// the failure writer itself never inspects a path.
func JSONNamespace(path string) bool {
	return path == "/healthz" || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/nodes/out/")
}

// wantsJSON reports whether the route declared a JSON failure body.
func WantsJSON(r *http.Request) bool {
	marked, _ := r.Context().Value(jsonResponseKey).(bool)
	return marked
}

// fail writes one failure in the representation the route declared at
// registration (see jsonAPI). It never inspects the path, so a renamed or
// relocated endpoint cannot silently change its failure body.
func (rt *Runtime) Fail(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	rt.FailAs(w, r, status, code, message, next, WantsJSON(r))
}

// failAs is the single failure writer. The caller decides the representation.
func (rt *Runtime) FailAs(w http.ResponseWriter, r *http.Request, status int, code, message, next string, jsonBody bool) {
	rt.Event(r, code)
	if jsonBody {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code, "operation_id": Operation(r), "stage": "web", "message": message, "next_action": next})
		return
	}
	rt.Render(w, r, status, view.ErrorPage(code, message, next, Operation(r)))
}

func (rt *Runtime) Render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	var b bytes.Buffer
	if err := c.Render(r.Context(), &b); err != nil {
		rt.Event(r, "RENDER_FAILED")
		http.Error(w, "RENDER_FAILED", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

func (rt *Runtime) CookieName() string {
	if rt.Cfg.DevHTTP {
		return "meshmux_dev"
	}
	return "__Host-meshmux"
}

func (rt *Runtime) Cookie(w http.ResponseWriter, token string, expires int64) {
	age := int(time.Until(time.Unix(expires, 0)).Seconds())
	if token == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: rt.CookieName(), Value: token, Path: "/", Secure: !rt.Cfg.DevHTTP, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age, Expires: time.Unix(expires, 0)})
}

func (rt *Runtime) Current(r *http.Request) (Session, error) {
	var token string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == rt.CookieName() {
			token = c.Value
			count++
		}
	}
	if count != 1 {
		return Session{}, sql.ErrNoRows
	}
	return rt.Store.Session(token, rt.Now())
}

func (rt *Runtime) Authenticated(next func(http.ResponseWriter, *http.Request, Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := rt.Current(r)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "暂时无法验证登录状态。", "请检查数据库和服务日志。")
			return
		}
		if err != nil || !sess.Auth {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			rt.Fail(w, r, 401, "AUTH_REQUIRED", "登录已失效或尚未登录。", "请重新登录。")
			return
		}
		next(w, r, sess)
	}
}

func (rt *Runtime) authPage(w http.ResponseWriter, r *http.Request, setup bool) {
	hash, err := rt.Store.AdminHash()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取管理员状态。", "请检查数据库。")
		return
	}
	if setup && hash != "" {
		rt.Fail(w, r, 403, "SETUP_CLOSED", "管理员已经初始化。", "请使用登录入口。")
		return
	}
	if !setup && hash == "" {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	sess, err := rt.Current(r)
	if err == nil && sess.Auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取会话。", "请检查数据库。")
		return
	}
	// The unauthenticated form needs a CSRF value, never a stored Session. The
	// double-submit cookie is the only state it adds, so no amount of anonymous
	// traffic can fill a row cap and take this page away from the administrator
	// who needs it to get back in.
	form, ferr := rt.FormSession(r, rt.Now())
	if ferr != nil {
		form = rt.NewFormSession(w, rt.Now())
	}
	rt.Render(w, r, 200, view.AuthPage(setup, form.CSRF, rt.Cfg.DevHTTP, "", ""))
}

func (rt *Runtime) LoginPage(w http.ResponseWriter, r *http.Request) { rt.authPage(w, r, false) }

func (rt *Runtime) SetupPage(w http.ResponseWriter, r *http.Request) { rt.authPage(w, r, true) }

func (rt *Runtime) Mutation(next func(http.ResponseWriter, *http.Request, Session), auth bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := rt.Current(r)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取会话。", "请检查数据库。")
			return
		}
		if !auth {
			// The login and setup forms are CSRF-protected by the stateless
			// double-submit token, not by a stored Session (#113 3-3). They never
			// needed a row, and requiring one let anonymous traffic fill the
			// Session cap and take the login page away. An authenticated Session
			// still may not post to them.
			if err == nil && sess.Auth {
				rt.Fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
				return
			}
			if sess, err = rt.FormSession(r, rt.Now()); err != nil {
				rt.Fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
				return
			}
		}
		if err != nil || (auth && !sess.Auth) {
			rt.Fail(w, r, 401, "SESSION_INVALID", "会话无效或已过期。", "请重新打开登录页面。")
			return
		}
		ct, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || ct != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 {
			rt.Fail(w, r, 415, "FORM_REQUIRED", "请求格式不正确。", "请使用页面表单。")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MutationFormMaxBytes)
		if err = r.ParseForm(); err != nil {
			rt.Fail(w, r, 400, "FORM_INVALID", "表单过大或格式不正确。", "请重新填写表单。")
			return
		}
		// Reject duplicate fields and URL parameters; never let query data override POST.
		if r.URL.RawQuery != "" {
			rt.Fail(w, r, 400, "FORM_INVALID", "不接受 URL 表单参数。", "请重新打开页面。")
			return
		}
		for _, values := range r.PostForm {
			if len(values) != 1 {
				rt.Fail(w, r, 400, "FORM_INVALID", "表单包含重复字段。", "请重新打开页面。")
				return
			}
		}
		if !store.Equal(r.PostForm.Get("csrf"), sess.CSRF) {
			rt.Fail(w, r, 403, "CSRF_REJECTED", "表单已失效或校验失败。", "请刷新页面后重试。")
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
// The guard runs after the mutation wrapper has checked the Session, form and
// CSRF token, so unauthenticated or forged requests never occupy the slot.
func (rt *Runtime) KDFGuard(next func(http.ResponseWriter, *http.Request, Session)) func(http.ResponseWriter, *http.Request, Session) {
	return func(w http.ResponseWriter, r *http.Request, sess Session) {
		select {
		case rt.kdfSlot <- struct{}{}:
			defer func() { <-rt.kdfSlot }()
		default:
			w.Header().Set("Retry-After", "2")
			rt.Fail(w, r, 429, "AUTH_KDF_BUSY", "另一个密码运算正在进行中。", "请稍后重试；该限制只影响登录、初始化与改密，其他操作不受影响。")
			return
		}
		next(w, r, sess)
	}
}

func (rt *Runtime) Budget(w http.ResponseWriter, r *http.Request) bool {
	ok, retry, err := rt.Store.Attempt(rt.Now())
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法验证登录频率。", "请检查数据库。")
		return false
	}
	if !ok {
		// Report the remaining window instead of a constant, so a locked-out
		// administrator knows when the next attempt can succeed. This reveals
		// nothing about a password: the budget is consumed by right and wrong
		// attempts alike, and a success clears it.
		seconds := int((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		rt.Fail(w, r, 429, "AUTH_RATE_LIMITED", "认证尝试过于频繁。", "鉴权预算为 10 次 / 10 分钟，约 "+RetryText(seconds)+"后可再试；成功认证会立即清零。已登录会话、只读页面与退出不受此预算影响，请勿反复重试。")
		return false
	}
	return true
}

// retryText renders a wait in the unit an administrator can act on.
func RetryText(seconds int) string {
	if seconds < 120 {
		return strconv.Itoa(seconds) + " 秒"
	}
	return strconv.Itoa((seconds+59)/60) + " 分钟"
}

func (rt *Runtime) AuthFailure(w http.ResponseWriter, r *http.Request, sess Session, setup bool) {
	// Caddy must overwrite this dedicated header. Loopback peers are part of the
	// trusted host boundary; X-Forwarded-For/Forwarded/CF headers are NEVER parsed.
	ip := ""
	candidate := false
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if rt.Cfg.DirectProxy && net.ParseIP(peer) != nil && net.ParseIP(peer).IsLoopback() {
		values := r.Header.Values("X-MeshMux-Client-IP")
		if len(values) == 1 {
			parsed := net.ParseIP(values[0])
			if parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
				ip = parsed.String()
				candidate = true
			}
		}
	}
	rt.Log.Warn("authentication_failed", "operation_id", Operation(r), "stage", "auth", "error_code", "AUTH_FAILED", "ban_candidate", candidate, "client_ip", ip)
	rt.Render(w, r, 401, view.AuthPage(setup, sess.CSRF, rt.Cfg.DevHTTP, "凭据不正确或已失效，请重新输入。", Operation(r)))
}

func (rt *Runtime) Setup(w http.ResponseWriter, r *http.Request, sess Session) {
	if !rt.Budget(w, r) {
		return
	}
	hash, err := rt.Store.AdminHash()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取管理员状态。", "请检查数据库。")
		return
	}
	if hash != "" {
		rt.Fail(w, r, 403, "SETUP_CLOSED", "管理员已经初始化。", "请使用登录入口。")
		return
	}
	var valid int
	err = rt.Store.DB.QueryRow("SELECT count(*) FROM bootstrap WHERE id=1 AND token_hash=? AND expires>?", store.TokenHash(r.PostForm.Get("bootstrap")), rt.Now().Unix()).Scan(&valid)
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取初始化状态。", "请检查数据库。")
		return
	}
	if valid != 1 {
		rt.AuthFailure(w, r, sess, true)
		return
	}
	if !store.PasswordValid(r.PostForm.Get("password")) {
		rt.Fail(w, r, 400, "PASSWORD_POLICY", "密码须至少 12 个字符、最多 256 字节。", "建议使用密码管理器生成长密码。")
		return
	}
	hash, err = store.HashPassword(r.PostForm.Get("password"))
	if err != nil {
		rt.Fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请检查服务日志。")
		return
	}
	tx, err := rt.Store.DB.Begin()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法开始初始化。", "请检查数据库。")
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
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "初始化未完成。", "请重新打开登录页面确认状态。")
		return
	}
	if err = os.Remove(filepath.Join(rt.Store.Dir, "bootstrap.token")); err != nil && !os.IsNotExist(err) {
		rt.Event(r, "BOOTSTRAP_FILE_CLEANUP_FAILED")
	}
	rt.Cookie(w, "", 0)
	rt.ClearFormCookie(w)
	rt.Event(r, "ADMIN_INITIALIZED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (rt *Runtime) Login(w http.ResponseWriter, r *http.Request, sess Session) {
	if !rt.Budget(w, r) {
		return
	}
	hash, err := rt.Store.AdminHash()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法验证密码。", "请检查数据库。")
		return
	}
	if hash == "" || !store.VerifyPassword(hash, r.PostForm.Get("password")) {
		rt.AuthFailure(w, r, sess, false)
		return
	}
	// A successful login adds one session instead of replacing the others:
	// every device keeps its own token hash, CSRF value and expiry, so signing
	// in on a phone never signs the administrator out on a desktop. The new
	// token is always fresh, so a known or planted cookie cannot be fixed into
	// an authenticated session. Legacy anonymous rows and rows that can no
	// longer authenticate are pruned in the same transaction.
	now := rt.Now()
	op := Operation(r)
	if op == "" {
		op = NewOperation()
	}
	token := store.RandomToken()
	csrf := store.RandomToken()
	expires := now.Add(store.SessionLifetime).Unix()
	tx, err := rt.Store.DB.Begin()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法建立会话。", "请重试。")
		return
	}
	defer tx.Rollback()
	if err = store.PruneSessions(tx, now); err == nil {
		_, err = tx.Exec("INSERT INTO sessions VALUES(?,?,1,?,?)", store.TokenHash(token), csrf, expires, now.Unix())
	}
	// The login record is written in the same transaction as the session: it
	// carries the operation id and time only, never the password, the token or
	// the CSRF value, and no URL, IP or user agent.
	if err == nil {
		err = store.RecordLogin(tx, op, now)
	}
	// The password was proven, so the shared budget is cleared in this same
	// transaction: ten routine logins never lock the only administrator out,
	// and a Session that failed to persist cannot leave a half-applied reset.
	if err == nil {
		err = store.ResetAuthBudget(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法建立会话。", "请重试。")
		return
	}
	rt.Cookie(w, token, expires)
	// The unauthenticated form token is spent: the Session now carries its own
	// CSRF value, so the double-submit cookie is dropped rather than left to
	// outlive the form it protected.
	rt.ClearFormCookie(w)
	rt.Event(r, "LOGIN_SUCCEEDED")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (rt *Runtime) Logout(w http.ResponseWriter, r *http.Request, sess Session) {
	// Logout revokes only the session that made the request. Every other
	// signed-in device keeps its own token, CSRF value and expiry.
	if _, err := rt.Store.DB.Exec("DELETE FROM sessions WHERE token_hash=?", sess.Hash); err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "注销未完成。", "请重试，尚未确认会话撤销。")
		return
	}
	rt.Cookie(w, "", 0)
	rt.ClearFormCookie(w)
	rt.Event(r, "LOGOUT_SUCCEEDED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (rt *Runtime) Password(w http.ResponseWriter, r *http.Request, sess Session) {
	if !rt.Budget(w, r) {
		return
	}
	hash, err := rt.Store.AdminHash()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法验证密码。", "请检查数据库。")
		return
	}
	if !store.VerifyPassword(hash, r.PostForm.Get("current_password")) {
		rt.Event(r, "PASSWORD_CURRENT_REJECTED")
		rt.Fail(w, r, 401, "AUTH_FAILED", "当前密码不正确。", "请返回设置重新输入。")
		return
	}
	if !store.PasswordValid(r.PostForm.Get("password")) {
		rt.Fail(w, r, 400, "PASSWORD_POLICY", "新密码须至少 12 个字符、最多 256 字节。", "请返回设置重新填写。")
		return
	}
	newHash, err := store.HashPassword(r.PostForm.Get("password"))
	if err != nil {
		rt.Fail(w, r, 500, "PASSWORD_HASH_FAILED", "无法保存密码。", "请重试。")
		return
	}
	tx, err := rt.Store.DB.Begin()
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "无法修改密码。", "请重试。")
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("UPDATE admin SET password_hash=? WHERE id=1", newHash)
	if err == nil {
		_, err = tx.Exec("DELETE FROM sessions")
	}
	// The current password was proven and every Session on every device is
	// about to be revoked, so the budget is cleared here: otherwise the
	// operator's next login could hit the limit that this successful change
	// just consumed.
	if err == nil {
		err = store.ResetAuthBudget(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "密码修改未完成。", "请检查数据库。")
		return
	}
	rt.Cookie(w, "", 0)
	rt.ClearFormCookie(w)
	rt.Event(r, "PASSWORD_CHANGED")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Healthy reports whether the database still answers the /healthz SELECT 1
// contract. It is the watchdog predicate, deliberately the same fact /healthz
// exposes: identity, queue depth and page rendering are not liveness.
func (rt *Runtime) Healthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var one int
	return rt.Store.DB.QueryRowContext(ctx, "SELECT 1").Scan(&one) == nil
}

func (rt *Runtime) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var one int
	if err := rt.Store.DB.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		rt.Fail(w, r, 503, store.CodeDatabaseUnavailable, "数据库不可用。", "请检查服务日志。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
}

func (rt *Runtime) Status(w http.ResponseWriter, r *http.Request, _ Session) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"web": "running", "proxy": "unknown", "mesh": "unknown", "operation_id": Operation(r)})
}

func (rt *Runtime) StatusFragment(w http.ResponseWriter, r *http.Request, _ Session) {
	rt.Render(w, r, 200, view.Status(rt.Now().UTC().Format("15:04:05 UTC")))
}
