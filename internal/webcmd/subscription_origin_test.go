package webcmd

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/web"
)

// TestSubscriptionOriginFlagIsOptional keeps the internal command backwards
// compatible: an installation that does not pass the flag keeps the previous
// behaviour, where the management origin also serves the download routes.
func TestSubscriptionOriginFlagIsOptional(t *testing.T) {
	c, err := parseConfig([]string{"--origin", "https://console.example.org", "--data-dir", "/var/lib/meshmux"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SubscriptionOrigin != "" {
		t.Fatalf("subscription origin must default to empty, got %q", c.SubscriptionOrigin)
	}
	if c.Origin != "https://console.example.org" || c.Listen != "127.0.0.1:9080" {
		t.Fatalf("existing flags changed behaviour: %+v", c)
	}
}

// TestSubscriptionOriginFlagPassesConfiguredValue checks the flag reaches the
// validated Web configuration unchanged.
func TestSubscriptionOriginFlagPassesConfiguredValue(t *testing.T) {
	c, err := parseConfig([]string{
		"--origin", "https://console.example.org",
		"--subscription-origin", "https://sub.example.org",
		"--data-dir", "/var/lib/meshmux",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SubscriptionOrigin != "https://sub.example.org" {
		t.Fatalf("subscription origin = %q", c.SubscriptionOrigin)
	}
	if c.Origin != "https://console.example.org" {
		t.Fatalf("management origin changed: %q", c.Origin)
	}
}

// TestSubscriptionOriginRejectsUnusableValues keeps a malformed or
// non-HTTPS subscription origin from reaching the running service. The
// internal command must refuse it before it can serve a download route on an
// unexpected host.
func TestSubscriptionOriginRejectsUnusableValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		dev    bool
	}{
		{"path", "https://sub.example.org/download", false},
		{"query", "https://sub.example.org?a=b", false},
		{"fragment", "https://sub.example.org#x", false},
		{"credentials", "https://user@sub.example.org", false},
		{"no host", "https://", false},
		{"not a url", "sub.example.org", false},
		{"plain HTTP", "http://sub.example.org", false},
		{"scheme only", "https://", false},
		{"development HTTP without dev mode", "http://127.0.0.1:9080", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := web.Config{Listen: "127.0.0.1:9080", Origin: "https://console.example.org", SubscriptionOrigin: tc.origin, DevHTTP: tc.dev}
			if err := subscriptionOrigin(c); err == nil {
				t.Fatalf("subscription origin %q was accepted", tc.origin)
			}
		})
	}
}

// TestSubscriptionOriginAcceptsExactOrigins keeps the valid values working,
// including the empty value that keeps the management origin in charge.
func TestSubscriptionOriginAcceptsExactOrigins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		dev    bool
	}{
		{"empty keeps the management origin", "", false},
		{"distinct HTTPS origin", "https://sub.example.org", false},
		{"development HTTP origin", "http://127.0.0.1:9080", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := web.Config{Listen: "127.0.0.1:9080", Origin: "https://console.example.org", SubscriptionOrigin: tc.origin, DevHTTP: tc.dev}
			if err := subscriptionOrigin(c); err != nil {
				t.Fatalf("subscription origin %q was rejected: %v", tc.origin, err)
			}
		})
	}
}

// TestRunRejectsBadSubscriptionOrigin makes the internal command exit
// non-zero on a bad subscription origin instead of starting a service that
// would answer downloads on an unexpected host.
func TestRunRejectsBadSubscriptionOrigin(t *testing.T) {
	code, stdout, _ := runWebCommand(t,
		"--origin", "https://console.example.invalid",
		"--subscription-origin", "https://sub.example.invalid/download",
		"--data-dir", tempDataDir(t),
	)
	if code != 1 {
		t.Fatalf("Run()=%d, want startup failure exit 1; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, `"error_code":"SUBSCRIPTION_ORIGIN_INVALID"`) {
		t.Fatalf("bad subscription origin was not reported: %s", stdout)
	}
}
