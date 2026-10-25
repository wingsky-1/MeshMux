package handler

import (
	"net/url"

	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// Config is the handler's deployment configuration. It mirrors web.Config
// field for field so the assembly layer converts without interpretation;
// validation stays in web (see Config.Validate), the handler only sanitizes
// the install artifact the same way the single-package server did.
type Config struct {
	Listen             string
	Origin             string
	DataDir            string
	DevHTTP            bool
	SubscriptionOrigin string
	HeadscaleOrigin    string
	InstallArtifact    *InstallArtifact
	DirectProxy        bool
	SingBoxPath        string
	MihomoPath         string
}

// session is the handler-local alias of the store session. Handlers thread it
// through authentication wrappers without naming store internals.
type session = store.Session

// InstallArtifact is the current same-origin CLI binary served by the
// development and installed runtimes. The type lives in view because the
// Nodes page renders it; the alias keeps handler signatures short.
type InstallArtifact = view.InstallArtifact

// InstallArtifactMaxBytes bounds both the configured CLI artifact and the
// download response. It lives here because the artifact stream enforces it;
// web.Config.Validate reuses the same bound through this package.
const InstallArtifactMaxBytes = 128 << 20

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
