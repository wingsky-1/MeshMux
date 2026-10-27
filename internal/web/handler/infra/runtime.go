package infra

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

// Runtime is the shared HTTP runtime every domain package receives. It owns the
// store handle, the injected clock, the password-KDF slot, the pairing budget,
// the stateless form key, the request boundary and the failure writer.
//
// The exported fields are the ones a domain handler reads on every request and
// a test replaces once: they are set before the router serves and never
// reassigned afterwards. Everything mutable per request stays unexported.
type Runtime struct {
	Cfg   Config
	Store *store.Store
	Log   *slog.Logger
	// Now is the clock. Production sets time.Now; a test pins it so a budget
	// window, a drain or an expiry can be advanced without sleeping.
	Now func() time.Time
	// handler is the assembled router. The root package publishes it once after
	// registering every domain's routes.
	handler http.Handler

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
}

// NewRuntime opens the store and prepares bootstrap. It starts no background
// pass: the root package owns the lifecycle.
func NewRuntime(c Config, logger *slog.Logger) (*Runtime, error) {
	c = SanitizeInstallArtifact(c)
	s, err := store.OpenStore(c.DataDir)
	if err != nil {
		return nil, err
	}
	if err = s.PrepareBootstrap(time.Now()); err != nil {
		s.Close()
		return nil, err
	}
	return &Runtime{
		Cfg:     c,
		Store:   s,
		Log:     logger,
		Now:     time.Now,
		kdfSlot: make(chan struct{}, 1),
		formKey: []byte(store.RandomToken()),
	}, nil
}

// requestKey is this package's context key namespace, so a domain package
// cannot collide with it.
type requestKey int

const (
	operationKey requestKey = iota
	jsonResponseKey
)

// KDFSlotForTest exposes the KDF slot to a test that must occupy or inspect it.
// Production has no caller: the guard is the only holder.
func (rt *Runtime) KDFSlotForTest() chan struct{} { return rt.kdfSlot }

// SetHandler publishes the assembled router.
func (rt *Runtime) SetHandler(h http.Handler) { rt.handler = h }

// Handler serves the assembled router.
func (rt *Runtime) Handler() http.Handler { return rt.handler }

// Close releases the store. The root package stops the background passes first,
// so a watchdog probing during shutdown sees a closed store, never a write on a
// handle that a goroutine still owns.
func (rt *Runtime) Close() error { return rt.Store.Close() }
