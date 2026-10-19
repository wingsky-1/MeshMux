package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
	if len(calls) != len(Ports())+1 {
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
		t.Skip("only used by Debian 13 component integration CI")
	}
	files, err := CandidateFiles(Config{
		ManagementDomain: "admin.example.org",
		SubscriptionDomain: "sub.example.org",
		HeadscaleDomain: "mesh.example.org",
	}, []int{2222})
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
