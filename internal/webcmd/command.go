// Package webcmd hosts the internal Web entrypoint used by both the development
// binary and the installed MeshMux runtime. The installer copies the already
// running CLI binary and starts its private __internal-web subcommand.
package webcmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/web"
)

// Run starts the unprivileged loopback Web service.
func Run(args []string) int {
	c, err := parseConfig(args, os.Stderr)
	if err != nil {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Time(slog.TimeKey, a.Value.Time().UTC())
		}
		return a
	}}))
	if err := subscriptionOrigin(c); err != nil {
		logger.Error("startup_failed", "error_code", "SUBSCRIPTION_ORIGIN_INVALID")
		return 1
	}
	if !c.DevHTTP {
		if origin, err := url.Parse(c.Origin); err == nil && origin.Scheme == "https" {
			c.InstallArtifact = discoverInstallArtifact()
		}
	}
	app, err := web.New(c, logger)
	if err != nil {
		logger.Error("startup_failed", "error_code", "STARTUP_FAILED")
		return 1
	}
	defer app.Close()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		logger.Error("listen_failed", "error_code", "LISTEN_FAILED")
		return 1
	}
	server := &http.Server{
		Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
		close(stopped)
	}()
	logger.Info("web_started", "stage", "startup", "error_code", "WEB_STARTED", "development_http", c.DevHTTP)
	err = server.Serve(listener)
	stop()
	<-stopped
	if !errors.Is(err, http.ErrServerClosed) {
		logger.Error("http_failed", "error_code", "HTTP_SERVE_FAILED")
		return 1
	}
	logger.Info("web_stopped", "stage", "shutdown", "error_code", "WEB_STOPPED")
	return 0
}

// parseConfig turns the internal command line into the operator configuration.
// The subscription origin is optional: an empty value keeps the management
// origin serving the fixed download routes, which preserves every existing
// call that never passes the flag.
func parseConfig(args []string, output io.Writer) (web.Config, error) {
	var c web.Config
	flags := flag.NewFlagSet("meshmux-web", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&c.Listen, "listen", "127.0.0.1:9080", "literal loopback address")
	flags.StringVar(&c.Origin, "origin", "", "exact public HTTPS origin")
	flags.StringVar(&c.SubscriptionOrigin, "subscription-origin", "", "exact public HTTPS origin serving only the two fixed subscription download routes; empty keeps the management origin")
	flags.StringVar(&c.DataDir, "data-dir", "", "private directory owned by service user")
	flags.BoolVar(&c.DevHTTP, "dev-http", false, "isolated loopback HTTP only; never publish this mode")
	flags.BoolVar(&c.DirectProxy, "direct-caddy", false, "trust the dedicated client IP header from a directly exposed local Caddy")
	if err := flags.Parse(args); err != nil {
		return web.Config{}, err
	}
	if flags.NArg() != 0 {
		return web.Config{}, errors.New("unexpected positional argument")
	}
	return c, nil
}

// subscriptionOrigin rejects a subscription origin that is not one exact
// origin without a path. The empty value is valid and keeps the management
// origin in charge of the download routes.
func subscriptionOrigin(c web.Config) error {
	if c.SubscriptionOrigin == "" {
		return nil
	}
	u, err := url.Parse(c.SubscriptionOrigin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return errors.New("SUBSCRIPTION_ORIGIN_INVALID: provide one exact origin without a path")
	}
	if !c.DevHTTP && u.Scheme != "https" {
		return errors.New("SUBSCRIPTION_ORIGIN_INVALID: the subscription origin must use HTTPS")
	}
	return nil
}

// discoverInstallArtifact exposes only the currently running installed CLI.
// The standalone web development command has no matching install runtime.
func discoverInstallArtifact() *web.InstallArtifact {
	info, ok := debug.ReadBuildInfo()
	const cliPackage = "github.com/wingsky-1/MeshMux/cmd/meshmux"
	if !ok || info.Path != cliPackage || strings.Contains(info.Main.Version, "meshmux-web") {
		return nil
	}
	path, err := os.Executable()
	if err != nil || !isTrustedLocalExecutable(path) {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, 128<<20+1))
	if err != nil || n > 128<<20 || n < 1 {
		return nil
	}
	if _, ok := node.KernelReleaseFor(runtime.GOARCH); !ok {
		return nil
	}
	return &web.InstallArtifact{
		Path:         path,
		Version:      node.CurrentAgentVersion,
		Architecture: runtime.GOARCH,
		SHA256:       hex.EncodeToString(sum.Sum(nil)),
	}
}

func isTrustedLocalExecutable(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
