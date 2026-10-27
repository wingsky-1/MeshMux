package handler

import (
	"errors"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

const (
	// subscriptionPrefix is the only public download namespace. It is matched
	// against the raw request path before the router can normalize, redirect
	// or expose any other endpoint.
	subscriptionPrefix = "/subscription/"
	// subscriptionSingBoxFormat and subscriptionMihomoFormat are the two fixed
	// document names. They are never negotiated and never redirected.
	subscriptionSingBoxFormat = "sing-box.json"
	subscriptionMihomoFormat  = "mihomo.yaml"
)

// subscriptionHost returns the only Host value that may serve downloads.
// An empty SubscriptionOrigin means the management origin also serves them,
// which is the single-host development default.
func (s *Server) subscriptionHost() string {
	return originHost(s.subscriptionOrigin())
}

// managementHost returns the Host value that serves the operator console.
func (s *Server) managementHost() string {
	return originHost(s.Cfg.Origin)
}

// subscriptionOrigin returns the configured download origin. An empty
// SubscriptionOrigin falls back to the management origin.
func (s *Server) subscriptionOrigin() string {
	if s.Cfg.SubscriptionOrigin != "" {
		return s.Cfg.SubscriptionOrigin
	}
	return s.Cfg.Origin
}

// originHost returns the host of one exact origin.
func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Host
}

// distinctSubscriptionHost reports whether downloads live on their own host.
// On such a host nothing except the two download routes is exposed.
func (s *Server) distinctSubscriptionHost() bool {
	host, management := s.subscriptionHost(), s.managementHost()
	return host != "" && management != "" && host != management
}

// route intercepts the subscription namespace before the management router
// sees the request. The router normalizes paths and issues redirects for
// trailing slashes; a bearer download must never be redirected, rewritten or
// answered by any other endpoint.
//
// The interception happens outside the management boundary, so a download
// never carries an admin session, never starts one, never asks for a captcha
// and never touches the login rate limit.
func (s *Server) route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.subscriptionOperation(r)
		distinct := s.distinctSubscriptionHost()
		if subscriptionNamespace(r) {
			// The download namespace is always answered by the subscription
			// handler, which checks the Host itself. On a dedicated download
			// host the management host never serves a download.
			if distinct && r.Host != s.subscriptionHost() {
				s.subscriptionHeader(w, r)
				s.subscriptionNotFound(w, r)
				return
			}
			s.subscription(w, r)
			return
		}
		// A dedicated download host exposes nothing except the two fixed
		// download routes: no health, no login, no API and no assets.
		if distinct && r.Host == s.subscriptionHost() {
			s.subscriptionHeader(w, r)
			s.subscriptionNotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// subscriptionOperation assigns the operation identifier of one request. The
// identifier is the only per-request value that may appear in a log line and
// in a response header; it never carries the path or the bearer.
func (s *Server) subscriptionOperation(r *http.Request) *http.Request {
	return infra.AssignOperation(r)
}

// subscriptionNamespace reports whether the raw request path belongs to the
// subscription namespace. The first segment must be exactly "subscription",
// so an encoded or differently cased spelling never reaches the download
// handler and never falls back to the management console.
func subscriptionNamespace(r *http.Request) bool {
	raw := rawRequestPath(r)
	if !strings.HasPrefix(raw, "/") {
		return false
	}
	rest := raw[1:]
	segment := rest
	if before, _, ok := strings.Cut(rest, "/"); ok {
		segment = before
	}
	return segment == "subscription"
}

// rawRequestPath returns the request path exactly as it was written on the
// request line, keeping percent escapes visible.
func rawRequestPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	return r.URL.EscapedPath()
}

// subscriptionHeader sets the fixed download response headers. A bearer
// document must never be cached, indexed, referenced or sniffed.
func (s *Server) subscriptionHeader(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("X-Operation-ID", infra.Operation(r))
	header.Set("Cache-Control", "private, no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Robots-Tag", "noindex")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")
}

// subscriptionNotFound answers every rejected download with one identical
// body. Invalid, unknown, revoked, suspended and not-yet-converged bearers
// must not be distinguishable.
func (s *Server) subscriptionNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(subscriptionNotFoundBody)))
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = w.Write(subscriptionNotFoundBody)
	}
}

var subscriptionNotFoundBody = []byte("Not Found\n")

// subscription serves the two fixed download routes. It never starts a
// session, never asks for a captcha, never applies a per-client rate limit and
// never mutates stored state.
func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	written := false
	// A panic must never reach the net/http default handler, which would log
	// the panic value and therefore the request URL. The abort handler is the
	// one exception: it is the documented way to abort a response, so it is
	// re-panicked instead of being swallowed.
	defer func() {
		if recovered := recover(); recovered != nil {
			if recovered == http.ErrAbortHandler {
				panic(recovered)
			}
			s.Event(r, "SUBSCRIPTION_DOWNLOAD_FAILED")
			if !written {
				s.subscriptionHeader(w, r)
				s.subscriptionNotFound(w, r)
			}
		}
	}()
	s.subscriptionHeader(w, r)
	if r.Host != s.subscriptionHost() || r.URL == nil || r.URL.IsAbs() {
		s.subscriptionNotFound(w, r)
		written = true
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		written = true
		return
	}
	token, format, ok := parseSubscriptionPath(r)
	if !ok {
		s.subscriptionNotFound(w, r)
		written = true
		return
	}
	// One resolve runs the convergence gate first: an unconverged Line refuses
	// the download even when an artifact was approved. The approved artifact is
	// then the download's single source of truth for a subscription that went
	// through the wizard: the bytes are re-derived from the saved selection and
	// must match the digest that passed the kernel gate. A subscription without
	// a snapshot keeps the historical export.
	approved, artifactErr := s.Store.SubscriptionArtifactDownload(token, s.Now())
	if artifactErr != nil {
		if errors.Is(artifactErr, store.ErrSubscriptionStoreUnavailable) {
			s.Event(r, store.CodeDatabaseUnavailable)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			written = true
			return
		}
		s.Event(r, "SUBSCRIPTION_DOWNLOAD_REJECTED")
		s.subscriptionNotFound(w, r)
		written = true
		return
	}
	var (
		body        []byte
		contentType string
		renderErr   error
	)
	switch format {
	case subscriptionSingBoxFormat:
		body = approved.SingBox
		contentType = "application/json; charset=utf-8"
	case subscriptionMihomoFormat:
		body = approved.Mihomo
		contentType = "text/yaml; charset=utf-8"
	default:
		renderErr = errors.New("SUBSCRIPTION_FORMAT_INVALID")
	}
	if len(body) == 0 {
		// A zero-length document is never a valid artifact; falling back to the
		// legacy export here would hide the failure.
		renderErr = errors.New("SUBSCRIPTION_ARTIFACT_EMPTY")
	}
	if renderErr != nil {
		s.Event(r, "SUBSCRIPTION_EXPORT_INVALID")
		s.subscriptionNotFound(w, r)
		written = true
		return
	}
	header := w.Header()
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	written = true
	s.Event(r, "SUBSCRIPTION_DOWNLOAD_SUCCEEDED")
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// parseSubscriptionPath accepts only the two exact canonical paths. Any query
// string, escape, dot segment, extra segment or different case is rejected
// before the bearer is even looked up.
func parseSubscriptionPath(r *http.Request) (string, string, bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", "", false
	}
	raw := rawRequestPath(r)
	// A canonical path never needs escaping. Percent-encoded separators,
	// dots, letters or trailing bytes are rejected here.
	if raw != r.URL.Path {
		return "", "", false
	}
	if !strings.HasPrefix(raw, subscriptionPrefix) {
		return "", "", false
	}
	parts := strings.Split(raw[len(subscriptionPrefix):], "/")
	if len(parts) != 2 {
		return "", "", false
	}
	token, format := parts[0], parts[1]
	if err := subscription.ValidateToken(token); err != nil {
		return "", "", false
	}
	switch format {
	case subscriptionSingBoxFormat, subscriptionMihomoFormat:
	default:
		return "", "", false
	}
	return token, format, true
}
