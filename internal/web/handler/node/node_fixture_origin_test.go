package node_test

import (
	"testing"
)

// TestFixtureOriginHostKeepsLoopbackDefault pins the exact allowlist for the
// disposable-VM Hub fixture Origin. Only the runner loopback (local review)
// and the QEMU slirp gateway (guest pairing path) are accepted.
func TestFixtureOriginHostKeepsLoopbackDefault(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want string
		fail bool
	}{
		{name: "empty keeps loopback default", env: "", want: "127.0.0.1"},
		{name: "explicit loopback", env: "127.0.0.1", want: "127.0.0.1"},
		{name: "slirp gateway for guest pairing", env: "10.0.2.2", want: "10.0.2.2"},
		{name: "whitespace is trimmed", env: "  10.0.2.2\n", want: "10.0.2.2"},
		{name: "arbitrary host rejected", env: "example.invalid", fail: true},
		{name: "external IP rejected", env: "203.0.113.7", fail: true},
		{name: "empty port host rejected", env: "10.0.2.2:19443", fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST", tc.env)
			got, err := fixtureOriginHost()
			if tc.fail {
				if err == nil {
					t.Fatalf("env %q must be rejected", tc.env)
				}
				return
			}
			if err != nil {
				t.Fatalf("env %q: %v", tc.env, err)
			}
			if got != tc.want {
				t.Fatalf("env %q = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

// TestNodeFixtureOriginMatchesListenPort keeps the fixture Origin on the
// same port as the loopback listener; only the host varies.
func TestNodeFixtureOriginMatchesListenPort(t *testing.T) {
	t.Setenv("MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST", "10.0.2.2")
	if got := nodeFixtureOrigin(t); got != "https://10.0.2.2:19443" {
		t.Fatalf("origin = %q, want https://10.0.2.2:19443", got)
	}
	t.Setenv("MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST", "")
	if got := nodeFixtureOrigin(t); got != "https://127.0.0.1:19443" {
		t.Fatalf("origin = %q, want https://127.0.0.1:19443", got)
	}
}
