package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The unauthenticated login and setup forms carry their CSRF token in a
// dedicated signed double-submit cookie instead of an anonymous session row
// (#113 3-3).
//
// Those two pages used to create a row in `sessions` only to hold their CSRF
// value, capped at 256 rows. A flood that discarded cookies filled the cap, and
// the administrator's own login page then answered 503 SESSION_UNAVAILABLE: the
// page that exists to restore access could be taken away by requests that never
// authenticate. A stored row was never what proved the form came from this
// server; a value the browser must echo back does, and it needs no durable
// state, so anonymous requests cannot consume a bounded resource. The page
// therefore renders while anonymous rows, the login budget or the session table
// are under pressure, as long as the administrator row is readable.
//
// The cookie is `__Host-` prefixed (host-only, Secure, Path=/), HttpOnly and
// Strict, so another origin or a sibling subdomain can neither read nor
// overwrite it. The value is an expiry plus a random nonce plus an HMAC-SHA256
// over both with a process-local key, so a planted cookie cannot be paired with
// a forged form field and the expiry is enforced server-side rather than
// trusted from the cookie's Max-Age. The POST still requires the exact Origin
// and one form field carrying the same value. A restart invalidates outstanding
// forms - a page reload, never an authenticated session.
const formTokenLifetime = 15 * time.Minute

func (s *Server) formCookieName() string {
	if s.cfg.DevHTTP {
		return "meshmux_dev_form"
	}
	return "__Host-meshmux-form"
}

func (s *Server) formCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: s.formCookieName(), Value: token, Path: "/", Secure: !s.cfg.DevHTTP, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// clearFormCookie drops the token once the form is spent, so a successful login
// or setup leaves no stale CSRF value behind.
func (s *Server) clearFormCookie(w http.ResponseWriter) { s.formCookie(w, "", -1) }

// newFormSession issues the CSRF token of a fresh unauthenticated form. It is
// shaped like a session so the existing form/CSRF boundary applies unchanged,
// but it is never stored and authorizes nothing on its own.
func (s *Server) newFormSession(w http.ResponseWriter, now time.Time) session {
	token := s.formToken(now)
	s.formCookie(w, token, int(formTokenLifetime.Seconds()))
	return session{CSRF: token}
}

// formSession reads and verifies the double-submit token. It fails closed
// unless exactly one cookie is present, its signature matches and it has not
// expired.
func (s *Server) formSession(r *http.Request, now time.Time) (session, error) {
	var token string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == s.formCookieName() {
			token = c.Value
			count++
		}
	}
	if count != 1 || !s.formTokenValid(token, now) {
		return session{}, errNoFormToken
	}
	return session{CSRF: token}, nil
}

var errNoFormToken = errors.New("FORM_TOKEN_INVALID")

func (s *Server) formToken(now time.Time) string {
	payload := strconv.FormatInt(now.Add(formTokenLifetime).Unix(), 10) + "." + store.RandomToken()
	return payload + "." + s.formSign(payload)
}

func (s *Server) formTokenValid(token string, now time.Time) bool {
	// The fixed shape is checked before splitting, so an oversized cookie never
	// reaches the MAC comparison.
	if len(token) > 160 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || now.Unix() >= expires {
		return false
	}
	return hmac.Equal([]byte(s.formSign(parts[0]+"."+parts[1])), []byte(parts[2]))
}

func (s *Server) formSign(payload string) string {
	mac := hmac.New(sha256.New, s.formKey)
	mac.Write([]byte("meshmux-form-v1\x00"))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
