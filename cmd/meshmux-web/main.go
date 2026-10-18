// meshmux-web is an internal service entry point, not a user management CLI.
package main

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

func main() { os.Exit(run()) }
func run() int {
	var c web.Config
	flag.StringVar(&c.Listen, "listen", "127.0.0.1:9080", "literal loopback address")
	flag.StringVar(&c.Origin, "origin", "", "exact public HTTPS origin")
	flag.StringVar(&c.DataDir, "data-dir", "", "private directory owned by service user")
	flag.BoolVar(&c.DevHTTP, "dev-http", false, "isolated loopback HTTP only; never publish this mode")
	flag.BoolVar(&c.DirectProxy, "direct-caddy", false, "trust dedicated IP header from a direct local Caddy; forbidden behind additional proxies")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Time(slog.TimeKey, a.Value.Time().UTC())
		}
		return a
	}}))
	if flag.NArg() != 0 {
		logger.Error("unexpected_arguments", "error_code", "CONFIG_INVALID")
		return 2
	}
	app, err := web.New(c, logger)
	if err != nil {
		logger.Error("startup_failed", "error_code", "STARTUP_FAILED", "reason", err.Error())
		return 1
	}
	defer app.Close()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		logger.Error("listen_failed", "error_code", "LISTEN_FAILED")
		return 1
	}
	server := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
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
