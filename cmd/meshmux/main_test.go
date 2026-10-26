package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestCLIRejectsUnsupportedRolesAndCommands(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"install", "hub"}, 2},
		{[]string{"install", "edge"}, 2},
		{[]string{"install", "out"}, 2},
		{[]string{"install", "nas"}, 2},
		{[]string{"update"}, 2},
		{[]string{"install"}, 2},
		{nil, 2},
	} {
		var b bytes.Buffer
		if got := runWithIO(tc.args, strings.NewReader(""), io.Discard, &b); got != tc.want {
			t.Fatalf("runWithIO(%v)=%d, want %d", tc.args, got, tc.want)
		}
		if strings.Contains(b.String(), "NOT READY TO INSTALL") {
			t.Fatalf("obsolete installation notice for %v", tc.args)
		}
	}
}

func TestInternalHubDispatchRefusesOpenShape(t *testing.T) {
	for _, tc := range [][]string{
		nil,
		{"--request-dir", "/tmp/not-the-fixed-dir"},
		{"--target", "2.0.0"},
		{"--request-dir", "/run/meshmux-hub/requests", "extra"},
	} {
		var b bytes.Buffer
		args := append([]string{"__internal-hub-dispatch"}, tc...)
		if got := runWithIO(args, strings.NewReader(""), io.Discard, &b); got != 2 {
			t.Fatalf("run(%v)=%d, want 2", tc, got)
		}
		if !strings.HasPrefix(strings.TrimSpace(b.String()), "USAGE: meshmux __internal-hub-dispatch") {
			t.Fatalf("run(%v) stderr = %q", tc, b.String())
		}
	}
}
