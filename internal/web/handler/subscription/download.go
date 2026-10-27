// Package subscription owns the public bearer download boundary: two fixed
// paths on one Host, no session, no captcha and no rate limit.
//
// The interception runs before the management router, so the router never
// normalizes, redirects or exposes a download; on a dedicated download host
// nothing else is served at all. Every refusal answers one identical body, so
// an invalid, unknown, revoked, suspended or not-yet-converged bearer is not
// distinguishable.
package subscription

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	coresubscription "github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
)

const (
	// prefix is the only public download namespace. It is matched against the
	// raw request path before the router can normalize, redirect or expose any
	// other endpoint.
	prefix = "/subscription/"
	// SingBoxFormat and MihomoFormat are the two fixed document names. They are
	// never negotiated and never redirected.
	SingBoxFormat = "sing-box.json"
	MihomoFormat  = "mihomo.yaml"
)

// Server is the download boundary. It holds only the runtime: a download reads
// the store directly and never touches another domain's state.
type Server struct {
	rt *infra.Runtime
}

// New builds the download boundary over one runtime.
func New(rt *infra.Runtime) *Server { return &Server{rt: rt} }

// Host returns the only Host value that may serve downloads. An empty
// SubscriptionOrigin means the management origin also serves them, which is the
// single-host development default.
func (s *Server) Host() string { return infra.OriginHost(s.Origin()) }

// ManagementHost returns the Host value that serves the operator console.
func (s *Server) ManagementHost() string { return infra.OriginHost(s.rt.Cfg.Origin) }

// Origin returns the configured download origin. An empty SubscriptionOrigin
// falls back to the management origin, which is also the URL the pages show the
// operator.
func (s *Server) Origin() string {
	if s.rt.Cfg.SubscriptionOrigin != "" {
		return s.rt.Cfg.SubscriptionOrigin
	}
	return s.rt.Cfg.Origin
}

// distinctHost reports whether downloads live on their own host. On such a host
// nothing except the two download routes is exposed.
func (s *Server) distinctHost() bool {
	host, management := s.Host(), s.ManagementHost()
	return host != "" && management != "" && host != management
}

// Route intercepts the subscription namespace before the management router sees
// the request. The router normalizes paths and issues redirects for trailing
// slashes; a bearer download must never be redirected, rewritten or answered by
// any other endpoint.
//
// The interception happens outside the management boundary, so a download never
// carries an admin session, never starts one, never asks for a captcha and
// never touches the login rate limit.
func (s *Server) Route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = infra.AssignOperation(r)
		distinct := s.distinctHost()
		if namespace(r) {
			// The download namespace is always answered by the download handler,
			// which checks the Host itself. On a dedicated download host the
			// management host never serves a download.
			if distinct && r.Host != s.Host() {
				s.notFound(w, r)
				return
			}
			s.serve(w, r)
			return
		}
		// A dedicated download host exposes nothing except the two fixed download
		// routes: no health, no login, no API and no assets.
		if distinct && r.Host == s.Host() {
			s.notFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// namespace reports whether the raw request path belongs to the subscription
// namespace. The first segment must be exactly "subscription", so an encoded or
// differently cased spelling never reaches the download handler and never falls
// back to the management console.
func namespace(r *http.Request) bool {
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

// header sets the fixed download response headers. A bearer document must never
// be cached, indexed, referenced or sniffed.
func (s *Server) header(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("X-Operation-ID", infra.Operation(r))
	header.Set("Cache-Control", "private, no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Robots-Tag", "noindex")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")
}

// notFound answers every rejected download with one identical body.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.header(w, r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(notFoundBody)))
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = w.Write(notFoundBody)
	}
}

var notFoundBody = []byte("Not Found\n")

// serve answers the two fixed download routes. It never starts a session, never
// asks for a captcha, never applies a per-client rate limit and never mutates
// stored state.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	written := false
	// A panic must never reach the net/http default handler, which would log the
	// panic value and therefore the request URL. The abort handler is the one
	// exception: it is the documented way to abort a response, so it is
	// re-panicked instead of being swallowed.
	defer func() {
		if recovered := recover(); recovered != nil {
			if recovered == http.ErrAbortHandler {
				panic(recovered)
			}
			s.rt.Event(r, "SUBSCRIPTION_DOWNLOAD_FAILED")
			if !written {
				s.notFound(w, r)
			}
		}
	}()
	s.header(w, r)
	if r.Host != s.Host() || r.URL == nil || r.URL.IsAbs() {
		s.notFound(w, r)
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
	token, format, ok := parsePath(r)
	if !ok {
		s.notFound(w, r)
		written = true
		return
	}
	// One resolve runs the convergence gate first: an unconverged Line refuses
	// the download even when an artifact was approved. The approved artifact is
	// then the download's single source of truth for a subscription that went
	// through the wizard: the bytes are re-derived from the saved selection and
	// must match the digest that passed the kernel gate. A subscription without
	// a snapshot keeps the historical export.
	approved, artifactErr := s.rt.Store.SubscriptionArtifactDownload(token, s.rt.Now())
	if artifactErr != nil {
		if errors.Is(artifactErr, store.ErrSubscriptionStoreUnavailable) {
			s.rt.Event(r, store.CodeDatabaseUnavailable)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			written = true
			return
		}
		s.rt.Event(r, "SUBSCRIPTION_DOWNLOAD_REJECTED")
		s.notFound(w, r)
		written = true
		return
	}
	var (
		body        []byte
		contentType string
		renderErr   error
	)
	switch format {
	case SingBoxFormat:
		body = approved.SingBox
		contentType = "application/json; charset=utf-8"
	case MihomoFormat:
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
		s.rt.Event(r, "SUBSCRIPTION_EXPORT_INVALID")
		s.notFound(w, r)
		written = true
		return
	}
	header := w.Header()
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	written = true
	s.rt.Event(r, "SUBSCRIPTION_DOWNLOAD_SUCCEEDED")
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// parsePath accepts only the two exact canonical paths. Any query string,
// escape, dot segment, extra segment or different case is rejected before the
// bearer is even looked up.
func parsePath(r *http.Request) (string, string, bool) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", "", false
	}
	raw := rawRequestPath(r)
	// A canonical path never needs escaping. Percent-encoded separators, dots,
	// letters or trailing bytes are rejected here.
	if raw != r.URL.Path {
		return "", "", false
	}
	if !strings.HasPrefix(raw, prefix) {
		return "", "", false
	}
	parts := strings.Split(raw[len(prefix):], "/")
	if len(parts) != 2 {
		return "", "", false
	}
	token, format := parts[0], parts[1]
	if err := coresubscription.ValidateToken(token); err != nil {
		return "", "", false
	}
	switch format {
	case SingBoxFormat, MihomoFormat:
	default:
		return "", "", false
	}
	return token, format, true
}
