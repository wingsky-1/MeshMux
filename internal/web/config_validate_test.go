package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestValidateRejectsDevHTTPArtifact pins the single validation rule that the
// handler move could not take along: a development-HTTP Hub never serves a
// CLI install artifact. The handler package has no Validate method by design,
// so this assembly-level rule is covered here, next to the Config it guards.
func TestValidateRejectsDevHTTPArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meshmux")
	body := []byte("fixed-test-cli")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	c := Config{
		Listen:  "127.0.0.1:9080",
		Origin:  "http://127.0.0.1:9080",
		DataDir: t.TempDir(),
		DevHTTP: true,
		InstallArtifact: &InstallArtifact{
			Path: path, Version: node.CurrentAgentVersion(), Architecture: "amd64", SHA256: hex.EncodeToString(sum[:]),
		},
	}
	if err := c.Validate(1000); err == nil || !strings.Contains(err.Error(), "INSTALL_ARTIFACT_INVALID") {
		t.Fatalf("DevHTTP accepted an executable install artifact: %v", err)
	}
}

func TestSubscriptionOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		origin    string
		subscribe string
		dev       bool
		valid     bool
	}{
		{"empty keeps the management origin", "https://admin.example.invalid", "", false, true},
		{"distinct HTTPS origin", "https://admin.example.invalid", "https://download.example.invalid", false, true},
		{"same origin spelled exactly", "https://admin.example.invalid", "https://admin.example.invalid", false, true},
		{"path", "https://admin.example.invalid", "https://download.example.invalid/sub", false, false},
		{"query", "https://admin.example.invalid", "https://download.example.invalid?a=b", false, false},
		{"fragment", "https://admin.example.invalid", "https://download.example.invalid#x", false, false},
		{"credentials", "https://admin.example.invalid", "https://user@download.example.invalid", false, false},
		{"no host", "https://admin.example.invalid", "https://", false, false},
		{"plain HTTP", "https://admin.example.invalid", "http://download.example.invalid", false, false},
		{"not a url", "https://admin.example.invalid", "download.example.invalid", false, false},
		{"development HTTP", "http://127.0.0.1:9080", "http://127.0.0.1:9080", true, true},
		{"development HTTP on another port", "http://127.0.0.1:9080", "http://127.0.0.1:9081", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{
				Listen:             "127.0.0.1:9080",
				Origin:             tc.origin,
				SubscriptionOrigin: tc.subscribe,
				DevHTTP:            tc.dev,
				DataDir:            filepath.Join(t.TempDir(), "state"),
			}
			err := c.Validate(1000)
			if tc.valid && err != nil {
				t.Fatalf("origin %q was rejected: %v", tc.subscribe, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("origin %q was accepted", tc.subscribe)
			}
		})
	}
}

func TestConfigurationBoundary(t *testing.T) {
	base := Config{Listen: "127.0.0.1:9080", Origin: "https://admin.example.invalid", DataDir: "state"}
	if err := base.Validate(1000); err != nil {
		t.Fatal(err)
	}
	if err := base.Validate(0); err == nil {
		t.Fatal("root allowed")
	}
	for _, listen := range []string{"0.0.0.0:9080", "[::]:9080", "localhost:9080", "192.0.2.1:9080", "127.0.0.1:0", "127.0.0.1:99999"} {
		c := base
		c.Listen = listen
		if c.Validate(1000) == nil {
			t.Fatalf("unsafe listen %s", listen)
		}
	}
	for _, origin := range []string{"http://admin.example.invalid", "https://admin.example.invalid/", "https://x@admin.example.invalid", "https://admin.example.invalid?x=y", "https://admin.example.invalid#x", "https://admin.example.invalid?"} {
		c := base
		c.Origin = origin
		if c.Validate(1000) == nil {
			t.Fatalf("unsafe origin %s", origin)
		}
	}
	c := base
	c.DevHTTP = true
	c.Origin = "http://127.0.0.1:9080"
	if err := c.Validate(1000); err != nil {
		t.Fatal(err)
	}
	c.DirectProxy = true
	if c.Validate(1000) == nil {
		t.Fatal("dev proxy trusted")
	}
	c = base
	c.Listen = "[::1]:9080"
	if err := c.Validate(1000); err != nil {
		t.Fatal(err)
	}
}
