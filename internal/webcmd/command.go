// Package webcmd hosts the internal Web entrypoint used by both the development
// binary and the installed MeshMux runtime. The installer copies the already
// running CLI binary and starts its private __internal-web subcommand.
package webcmd

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/web"
)

// Run starts the unprivileged loopback Web service.
func Run(args []string) int {
	var c web.Config
	flags := flag.NewFlagSet("meshmux-web", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&c.Listen, "listen", "127.0.0.1:9080", "literal loopback address")
	flags.StringVar(&c.Origin, "origin", "", "exact public HTTPS origin")
	flags.StringVar(&c.DataDir, "data-dir", "", "private directory owned by service user")
	flags.BoolVar(&c.DevHTTP, "dev-http", false, "isolated loopback HTTP only; never publish this mode")
	flags.BoolVar(&c.DirectProxy, "direct-caddy", false, "trust the dedicated client IP header from a directly exposed local Caddy")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Time(slog.TimeKey, a.Value.Time().UTC())
		}
		return a
	}}))
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
