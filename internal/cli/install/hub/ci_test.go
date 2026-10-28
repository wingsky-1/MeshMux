package hub

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

func TestPortProbeIPv4Only(t *testing.T) {
	var calls []string
	err := probePorts(func(network, address string) error {
		calls = append(calls, network+" "+address)
		if network == "tcp6" {
			return syscall.EAFNOSUPPORT
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != len(core.Ports())+1 {
		t.Fatalf("IPv4-only host: unexpected probes: %v", calls)
	}
}

func TestPortProbeBlocksConflict(t *testing.T) {
	err := probePorts(func(network, address string) error {
		if network == "tcp" && address == "0.0.0.0:443" {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("port conflict was not returned: %v", err)
	}
}

func TestPortProbeIPv6Conflict(t *testing.T) {
	err := probePorts(func(network, address string) error {
		if network == "tcp6" && address == "[::]:443" {
			return syscall.EADDRINUSE
		}
		return nil
	})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("IPv6 port conflict was not returned: %v", err)
	}
}

// TestWriteComponentFixtures supplies real candidate configurations to a
// disposable Debian 13 container for upstream binary validation. It is off
// for ordinary Go tests, and never writes to the running host's /etc.
func TestWriteComponentFixtures(t *testing.T) {
	dir := os.Getenv("MESHMUX_HUB_FIXTURE_DIR")
	if dir == "" {
		t.Skip("MESHMUX_HUB_FIXTURE_DIR is not set: only used by the Debian 13 component integration CI")
	}
	files, err := candidateFiles(core.Config{
		ManagementDomain:   "admin.example.org",
		SubscriptionDomain: "sub.example.org",
		HeadscaleDomain:    "mesh.example.org",
	}, []int{2222}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for path, body := range files {
		if filepath.Base(path) == "headscale.yaml" {
			// Headscale configtest can initialize state. Every path must point
			// at a disposable directory, never a production database/key.
			body = strings.ReplaceAll(body, "/var/lib/meshmux-headscale/", "/tmp/meshmux-headscale-ci/")
			body = strings.ReplaceAll(body, "/run/meshmux-headscale/", "/tmp/meshmux-headscale-ci/")
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(path)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSLocalAddressDebian13(t *testing.T) {
	lines := "udp UNCONN 0 0 0.0.0.0:3478 0.0.0.0:* users:((\"headscale\",pid=42,fd=4))\n" +
		"tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"headscale\",pid=42,fd=3))"
	if !core.HasListenerPort(lines, 3478) || !core.HasListenerPort(lines, 8080) || core.HasListenerPort(lines, 443) {
		t.Fatalf("Debian 13 ss parser failed: %s", lines)
	}
	ssh := "tcp LISTEN 0 128 0.0.0.0:60794 0.0.0.0:* users:((\"sshd\",pid=789,fd=6))"
	ports := core.ParseSSHListeners(ssh)
	if len(ports) != 1 || ports[0] != 60794 {
		t.Fatalf("SSH parser misread protocol-aware ss: %v", ports)
	}
}
