package infra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

func (rt *Runtime) Boundary(next http.Handler) http.Handler {
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
		jsonBody := JSONNamespace(r.URL.Path)
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
				rt.FailAs(w, r, 500, "INTERNAL_ERROR", "请求未完成。", "请稍后重试。", jsonBody)
			}
		}()
		u, _ := url.Parse(rt.Cfg.Origin)
		if r.Host != u.Host || r.URL.IsAbs() {
			rt.FailAs(w, r, 403, "HOST_REJECTED", "请求主机不匹配。", "请使用配置的管理地址。", jsonBody)
			return
		}
		// Outbound Agents authenticate with Bearer identity, not browser Origin.
		if r.Method != "GET" && r.Method != "HEAD" && !AgentAPI(r.URL.Path) {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || origins[0] != rt.Cfg.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				rt.FailAs(w, r, 403, "ORIGIN_REJECTED", "请求来源不可信。", "请从管理页面重新提交。", jsonBody)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// WriteJSON writes one success body in the management JSON shape. The failure
// writer is separate (Fail/FailAs): a success receipt and a refusal never share
// a helper, so a caller cannot accidentally encode a refusal as a 200.
func (rt *Runtime) WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
