// Package web implements the unprivileged, local-only Hub security foundation.
package web

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
)

// Config is local operator configuration, never accepted from an HTTP request.
type Config struct {
	Listen  string
	Origin  string
	DataDir string
	DevHTTP bool
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
	return nil
}

func (c Config) validate() error { return c.Validate(os.Geteuid()) }
