package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  slog.Level
		ok    bool
	}{
		{"unset", "", slog.LevelWarn, true},
		{"debug", "debug", slog.LevelDebug, true},
		{"info", "info", slog.LevelInfo, true},
		{"warn", "warn", slog.LevelWarn, true},
		{"warning alias", "warning", slog.LevelWarn, true},
		{"error", "error", slog.LevelError, true},
		{"mixed case and spaces", "  DEBUG ", slog.LevelDebug, true},
		{"unknown keeps the floor", "verbose", slog.LevelWarn, false},
		{"numeric level is not a name", "0", slog.LevelWarn, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			level, ok := Parse(tc.value)
			if level != tc.want || ok != tc.ok {
				t.Fatalf("Parse(%q) = %s, %t; want %s, %t", tc.value, level, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestDefaultIsWarn pins the floor itself. It is the one value the whole
// quiet-by-default policy rests on: a healthy fleet writes a heartbeat per
// second plus an event per poll, so a lower default would flood journald.
func TestDefaultIsWarn(t *testing.T) {
	if Default != slog.LevelWarn {
		t.Fatalf("default level = %s, want Warn", Default)
	}
	if got := Default; got < slog.LevelWarn {
		t.Fatalf("default level %s is below Warn", got)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv(EnvLevel, "debug")
	if level, ok := FromEnv(); !ok || level != slog.LevelDebug {
		t.Fatalf("FromEnv() = %s, %t; want Debug, true", level, ok)
	}
	t.Setenv(EnvLevel, "")
	if level, ok := FromEnv(); !ok || level != Default {
		t.Fatalf("FromEnv() with an empty value = %s, %t; want %s, true", level, ok, Default)
	}
}
