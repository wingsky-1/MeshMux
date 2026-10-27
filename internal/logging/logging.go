// Package logging resolves the one process log level of both long-running
// MeshMux entrypoints: the Hub Web launcher (__internal-web) and the node Agent
// (__internal-agent).
//
// The default is Warn. Both processes write to journald, and their healthy
// steady state is now chatty by design: the Agent heartbeats once per second and
// the Web records an event per Agent poll. At the standard Info floor those
// lines would bury the ones an operator has to act on, so the floor is Warn and
// an operator who needs the detail raises it explicitly with
// MESHMUX_LOG_LEVEL=info (or debug).
//
// The package deliberately owns nothing else: the handlers stay stdlib
// log/slog JSON with UTC timestamps and the callers' own ReplaceAttr redaction
// rules, so this is one policy decision and no new log library.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

const (
	// EnvLevel is the only runtime switch over the log floor.
	EnvLevel = "MESHMUX_LOG_LEVEL"
	// Default is the floor when EnvLevel is unset. Warn keeps a healthy
	// 1s-heartbeat fleet out of the journal while every failure path stays
	// visible.
	Default = slog.LevelWarn
)

// FromEnv resolves the level from EnvLevel in the current process environment.
func FromEnv() (slog.Level, bool) { return Parse(os.Getenv(EnvLevel)) }

// Parse maps one configured value to a level. An empty value means "unset" and
// yields Default. A recognized value yields its level. An unrecognized value
// also yields Default but reports false, so the entrypoint can say once that the
// setting was ignored instead of leaving an operator to wonder why a typo had
// no effect.
func Parse(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return Default, true
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return Default, false
}
