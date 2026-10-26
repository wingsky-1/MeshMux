// Package web implements the unprivileged, local-only Hub control plane: the
// HTTP surface, administrator authentication, the SQLite store and the
// orchestration that turns operator actions into protocol tasks.
//
// The layers are: server.go plus the server_*.go handlers (routing, CSRF and
// origin checks in boundary, rendering), password.go and the session/rate-limit
// half of store.go (argon2id password hashing, hashed session tokens, login
// throttling), and the store_*.go files that persist state. Handlers never
// touch SQL directly; they call store methods.
//
// The store speaks to nodes only through internal/protocol: it builds
// protocol.Task values and persists their results. The four publication kinds
// are shared through protocol.PublicationKinds, used by
// store_node_candidates.go and aliased as subscriberChainKinds in
// store_subscriber_sync.go, so producers and consumers cannot drift.
//
// The package imports internal/node for the node domain contract and does not
// import internal/install; installation stays behind the CLI boundary.
package web

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// The install artifact digest must match the frozen SHA-256 grammar shared by
// every producer and consumer (internal/backup/grammar.go); the check lives in
// Validate below via backup.ValidDigest.

// InstallArtifact is view.InstallArtifact: the type lives in the view package
// so templates, handlers and assembly share one definition.
type InstallArtifact = view.InstallArtifact

// Config is local operator configuration, never accepted from an HTTP request.
type Config struct {
	Listen  string
	Origin  string
	DataDir string
	DevHTTP bool
	// SubscriptionOrigin is the optional dedicated origin that serves the two
	// fixed public subscription download routes. It must be one exact HTTPS
	// origin without a path. Empty means the management Origin also serves
	// those routes, which is the single-host development default. A distinct
	// value moves downloads to their own host; that host then exposes nothing
	// except the two download routes.
	SubscriptionOrigin string
	// HeadscaleOrigin is the exact HTTPS origin of the local Headscale control
	// plane that a generated Mesh client config uses as control_url. Empty is
	// allowed so an existing Hub keeps running, but a Mesh configuration is
	// then refused: the exporter never falls back to the public Tailscale SaaS
	// control plane. The installer passes the configured Headscale domain.
	HeadscaleOrigin string
	// InstallArtifact is populated by the installed CLI runtime. The
	// development-only meshmux-web binary deliberately leaves it nil.
	InstallArtifact *InstallArtifact
	// DirectProxy enables ban candidates only for a directly exposed local Caddy.
	// Leave false behind ANY additional proxy (including Cloudflare).
	DirectProxy bool
	// SingBoxPath is the kernel the publish gate uses to validate an assembled
	// Line candidate. Empty selects the installer-owned kernel path of a
	// co-located Line; a host without that binary refuses publication instead
	// of skipping the check.
	SingBoxPath string
	// MihomoPath is the pinned Mihomo binary the publish gate uses to validate
	// an assembled client document. Empty means "not installed", which is an
	// explicit refusal for a client-layer publication, never a silent skip.
	MihomoPath string
}

func (c Config) Validate(uid int) error {
	if uid == 0 {
		return errors.New("ROOT_FORBIDDEN: run as a dedicated non-root user")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() {
		return errors.New("LISTEN_INVALID: use a literal loopback IP and port")
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return errors.New("ORIGIN_INVALID: provide one exact origin without a path")
	}
	if c.DevHTTP {
		if u.Scheme != "http" || u.Host != c.Listen || c.DirectProxy {
			return errors.New("ORIGIN_INVALID: development HTTP must match the loopback listener; no proxy mode")
		}
	} else if u.Scheme != "https" {
		return errors.New("HTTPS_REQUIRED: configure Caddy HTTPS, or explicitly select local development HTTP")
	}
	if c.DataDir == "" {
		return errors.New("DATA_DIR_REQUIRED")
	}
	if err := c.validateSubscriptionOrigin(u); err != nil {
		return err
	}
	if err := c.validateHeadscaleOrigin(); err != nil {
		return err
	}
	if err := validateGatePath(c.SingBoxPath); err != nil {
		return err
	}
	if err := validateGatePath(c.MihomoPath); err != nil {
		return err
	}
	if c.InstallArtifact != nil {
		if c.DevHTTP || u.Scheme != "https" {
			return errors.New("INSTALL_ARTIFACT_INVALID: CLI download and install commands require an HTTPS Hub")
		}
		a := c.InstallArtifact
		if a.Path == "" || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path {
			return errors.New("INSTALL_ARTIFACT_INVALID: use one absolute executable path")
		}
		if a.Version != node.CurrentAgentVersion() || !backup.ValidDigest(a.SHA256) {
			return errors.New("INSTALL_ARTIFACT_INVALID: version or digest is not pinned")
		}
		if _, ok := node.KernelReleaseFor(a.Architecture); !ok {
			return errors.New("INSTALL_ARTIFACT_INVALID: unsupported architecture")
		}
		info, err := os.Lstat(a.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > handler.InstallArtifactMaxBytes {
			return errors.New("INSTALL_ARTIFACT_INVALID: require a regular executable of at most 128 MiB")
		}
	}
	return nil
}

func (c Config) validate() error { return c.Validate(os.Geteuid()) }

// validateGatePath accepts one absolute, cleaned executable path or the empty
// value. The value comes from deployment configuration only, never from a
// request, and a relative or unclean path would let the gate run an unintended
// binary.
func validateGatePath(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("PUBLISH_GATE_PATH_INVALID: configure one absolute executable path")
	}
	return nil
}

// validateHeadscaleOrigin checks the optional Mesh control URL. Empty is valid
// at startup and makes a Mesh config generation fail with its own stable code;
// a non-empty value must be one exact HTTPS origin without a path, query,
// fragment or credentials. The public Tailscale SaaS control plane is never a
// default and never inferred from this field.
func (c Config) validateHeadscaleOrigin() error {
	if c.HeadscaleOrigin == "" {
		return nil
	}
	u, err := url.Parse(c.HeadscaleOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return errors.New("HEADSCALE_ORIGIN_INVALID: provide one exact HTTPS origin without a path")
	}
	return nil
}

// validateSubscriptionOrigin checks the optional dedicated download origin.
//
// The value must be one exact origin without a path, query, fragment or
// credentials. It must use HTTPS, except for the local development mode
// where it has to match the loopback listener exactly.
//
// An empty value is valid and keeps the management origin in charge of the
// two fixed download routes.
func (c Config) validateSubscriptionOrigin(management *url.URL) error {
	if c.SubscriptionOrigin == "" {
		return nil
	}
	u, err := url.Parse(c.SubscriptionOrigin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return errors.New("SUBSCRIPTION_ORIGIN_INVALID: provide one exact origin without a path")
	}
	if c.DevHTTP {
		if u.Scheme != "http" || u.Host != c.Listen {
			return errors.New("SUBSCRIPTION_ORIGIN_INVALID: development HTTP must match the loopback listener")
		}
		return nil
	}
	if u.Scheme != "https" {
		return errors.New("SUBSCRIPTION_ORIGIN_INVALID: the subscription origin must use HTTPS")
	}
	if management != nil && u.Host == management.Host {
		// A distinct download host is the point of the separate origin. The
		// same host is still accepted, but it must be spelled the same way in
		// both fields, so the served Host is never ambiguous.
		if c.SubscriptionOrigin != management.Scheme+"://"+management.Host {
			return errors.New("SUBSCRIPTION_ORIGIN_INVALID: the subscription origin must be spelled exactly like the management origin")
		}
	}
	return nil
}
