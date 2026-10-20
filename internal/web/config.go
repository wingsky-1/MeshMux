// Package web implements the unprivileged, local-only Hub security foundation.
package web

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/node"
)

var artifactSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// InstallArtifact is the current same-origin CLI binary made available by the
// private Web runtime. Path never enters HTTP responses or logs.
type InstallArtifact struct {
	Path         string
	Version      string
	Architecture string
	SHA256       string
}

// Config is local operator configuration, never accepted from an HTTP request.
type Config struct {
	Listen  string
	Origin  string
	DataDir string
	DevHTTP bool
	// InstallArtifact is populated by the installed CLI runtime. The
	// development-only meshmux-web binary deliberately leaves it nil.
	InstallArtifact *InstallArtifact
	// DirectProxy enables ban candidates only for a directly exposed local Caddy.
	// Leave false behind ANY additional proxy (including Cloudflare).
	DirectProxy bool
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
	if c.InstallArtifact != nil {
		if c.DevHTTP || u.Scheme != "https" {
			return errors.New("INSTALL_ARTIFACT_INVALID: CLI download and install commands require an HTTPS Hub")
		}
		a := c.InstallArtifact
		if a.Path == "" || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path {
			return errors.New("INSTALL_ARTIFACT_INVALID: use one absolute executable path")
		}
		if a.Version != node.CurrentAgentVersion || !artifactSHA256.MatchString(a.SHA256) {
			return errors.New("INSTALL_ARTIFACT_INVALID: version or digest is not pinned")
		}
		if _, ok := node.KernelReleaseFor(a.Architecture); !ok {
			return errors.New("INSTALL_ARTIFACT_INVALID: unsupported architecture")
		}
		info, err := os.Lstat(a.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 128<<20 {
			return errors.New("INSTALL_ARTIFACT_INVALID: require a regular executable of at most 128 MiB")
		}
	}
	return nil
}

func (c Config) validate() error { return c.Validate(os.Geteuid()) }
