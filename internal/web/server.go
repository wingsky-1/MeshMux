package web

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/wingsky-1/MeshMux/internal/web/handler"
)

// Server is the thin assembly over the handler runtime. All HTTP behavior,
// session authentication and routing live in internal/web/handler; all
// persistence lives in internal/web/store; all rendering lives in
// internal/web/view. This type only converts the operator configuration,
// delegates construction, and exposes the handler for serving and closing.
type Server struct {
	cfg   Config
	inner *handler.Server
	log   *slog.Logger
}

// New validates the operator configuration and builds the handler runtime.
// Validation (including the root refusal) stays here so the development-only
// and installed entry points share one gate; the handler constructor itself
// never validates.
func New(c Config, logger *slog.Logger) (*Server, error) {
	c = sanitizeInstallArtifact(c)
	if err := c.validate(); err != nil {
		return nil, err
	}
	inner, err := handler.New(handler.Config{
		Listen:             c.Listen,
		Origin:             c.Origin,
		DataDir:            c.DataDir,
		DevHTTP:            c.DevHTTP,
		SubscriptionOrigin: c.SubscriptionOrigin,
		HeadscaleOrigin:    c.HeadscaleOrigin,
		InstallArtifact:    c.InstallArtifact,
		DirectProxy:        c.DirectProxy,
		SingBoxPath:        c.SingBoxPath,
		MihomoPath:         c.MihomoPath,
	}, logger)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: c, inner: inner, log: logger}, nil
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

// Close releases the store held by the handler runtime.
func (s *Server) Close() error { return s.inner.Close() }

// Handler serves the full management, agent and download boundary.
func (s *Server) Handler() http.Handler { return s.inner.Handler() }

// Healthy reports whether the database still answers SELECT 1. It is the
// systemd watchdog predicate; see handler.Server.Healthy.
func (s *Server) Healthy() bool { return s.inner.Healthy() }
