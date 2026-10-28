package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

// TestHubSystemVM runs only in an ephemeral Debian 13 VM with real systemd.
// It never runs on a production node. TLS is internal to the VM and only the
// test probe trusts that internal issuer; the public installer always uses ACME.
func TestHubSystemVM(t *testing.T) {
	if os.Getenv("MESHMUX_HUB_SYSTEM_VM") != "1" {
		t.Skip("MESHMUX_HUB_SYSTEM_VM is not set to 1: requires an explicit disposable Debian 13 QEMU VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated VM integration test requires root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("VM did not boot with systemd")
	}
	c := core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	tlsProbe := func(ctx context.Context, domain string) error {
		deadline := time.Now().Add(70 * time.Second)
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // disposable VM only
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
			},
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{
			Transport: transport,
			Timeout:   4 * time.Second,
			// Mirror waitForHTTPS: read the raw response and never follow the
			// first-install 303 from /login to /setup. The certificate
			// assertions below inspect resp.TLS, which must come from the
			// original, non-redirected response.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		for time.Now().Before(deadline) {
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/login", nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				// Same readiness semantics as waitForHTTPS: 2xx/3xx means TLS
				// terminated and the origin answered (a fresh install has no
				// administrator yet, so /login answers 303 to /setup).
				if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 &&
					resp.TLS.PeerCertificates[0].VerifyHostname(domain) == nil {
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		return errors.New("VM_TLS_PROBE_FAILED")
	}
	opts := core.ApplyOptions{
		InternalTLSForTest: true,
		Executable:         "/tmp/meshmux",
		TLSProbe:           tlsProbe,
		Preflight: func(ctx context.Context, c core.Config, installed bool) ([]core.Check, []int) {
			ports, err := core.SSHPorts(ctx)
			if err != nil {
				return []core.Check{{Name: "ssh", Status: "fail", Code: "SSH_LISTENER_MISMATCH"}}, nil
			}
			return []core.Check{{Name: "debian13", Status: "pass"}, {Name: "public_ingress", Status: "pending"}}, ports
		},
	}
	phase := os.Getenv("MESHMUX_HUB_SYSTEM_PHASE")
	switch phase {
	case "install":
		state, exists, err := core.ReadState("/")
		if err != nil || exists {
			t.Fatalf("VM image is not clean: exists=%v state=%+v err=%v", exists, state, err)
		}
		out, err := InstallHub(ctx, c, strings.Repeat("a", 32), false, opts)
		if err != nil || out.Status != "installed" {
			t.Fatalf("VM first install result=%+v err=%v", out, err)
		}
		initial, exists, err := core.ReadState("/")
		if err != nil || !exists || initial.Status != "installed" {
			t.Fatalf("VM install readback=%+v err=%v", initial, err)
		}
		key := "/var/lib/meshmux-headscale/noise_private.key"
		if _, err := os.Stat(key); err != nil {
			t.Fatalf("Headscale did not create a persistent Noise key: %v", err)
		}
		sentinel := "/var/lib/meshmux/ci-sentinel"
		if err := os.WriteFile(sentinel, []byte("web data must survive"), 0600); err != nil {
			t.Fatal(err)
		}
		second, err := InstallHub(ctx, c, strings.Repeat("b", 32), false, opts)
		if err != nil || second.Status != "already_installed" {
			t.Fatalf("re-run=%+v err=%v", second, err)
		}
		after, _, _ := core.ReadState("/")
		if !reflect.DeepEqual(initial.ManagedFiles, after.ManagedFiles) || initial.OperationID != after.OperationID {
			t.Fatal("idempotent operation mutated recorded files or operation identity")
		}

		injected := &VMOneFailureRunner{target: "restart meshmux-caddy.service"}
		broken := opts
		broken.Runner = injected
		rolledBack, err := InstallHub(ctx, c, strings.Repeat("c", 32), true, broken)
		if err == nil || rolledBack.Status != "rolled_back" || rolledBack.ErrorCode != "CADDY_START_FAILED" {
			t.Fatalf("injected restart failure did not restore previous state: %+v err=%v", rolledBack, err)
		}
		state, _, _ = core.ReadState("/")
		if state.Status != "installed" || !reflect.DeepEqual(initial.ManagedFiles, state.ManagedFiles) {
			t.Fatal("rollback did not preserve the previous installed state and managed hashes")
		}
		if err := core.VerifyServices(ctx, c, core.ExecRunner{}, tlsProbe); err != nil {
			t.Fatalf("rollback failed to restore services: %v", err)
		}
		afterRepair, err := InstallHub(ctx, c, strings.Repeat("d", 32), true, opts)
		if err != nil || afterRepair.Status != "installed" {
			t.Fatalf("recovery repair=%+v err=%v", afterRepair, err)
		}
		if string(MustReadVM(t, sentinel)) != "web data must survive" {
			t.Fatal("repair deleted Web state")
		}
	case "post-reboot":
		state, exists, err := core.ReadState("/")
		if err != nil || !exists || state.Status != "installed" {
			t.Fatalf("state lost after reboot: %+v err=%v", state, err)
		}
		if err := core.VerifyServices(ctx, c, core.ExecRunner{}, tlsProbe); err != nil {
			t.Fatalf("services not healthy after reboot: %v", err)
		}
		// This tests the real Fail2ban -> nftables action in the disposable VM,
		// without making failed SSH login attempts or affecting a real firewall.
		runner := core.ExecRunner{}
		banIP := "198.51.100.123"
		if _, err := runner.Run(ctx, "fail2ban-client", "set", "meshmux-sshd", "banip", banIP); err != nil {
			t.Fatalf("test IP ban failed: %v", err)
		}
		defer runner.Run(context.Background(), "fail2ban-client", "set", "meshmux-sshd", "unbanip", banIP)
		rules, err := runner.Run(ctx, "nft", "-a", "list", "ruleset")
		if err != nil || !strings.Contains(string(rules), banIP) {
			t.Fatalf("Fail2ban ban not reflected in nftables rules (err=%v)", err)
		}
		if _, err := runner.Run(ctx, "fail2ban-client", "set", "meshmux-sshd", "unbanip", banIP); err != nil {
			t.Fatalf("test IP unban failed: %v", err)
		}
		if string(MustReadVM(t, "/var/lib/meshmux/ci-sentinel")) != "web data must survive" {
			t.Fatal("Web data lost after reboot")
		}
		if _, err := os.Stat(filepath.Join("/var/lib/meshmux-headscale", "noise_private.key")); err != nil {
			t.Fatalf("Headscale private key lost after reboot: %v", err)
		}
	default:
		t.Fatalf("invalid VM-only phase %q", phase)
	}
}

type VMOneFailureRunner struct {
	core.ExecRunner
	target string
	used   bool
}

func (r *VMOneFailureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !r.used && name == "systemctl" && strings.Join(args, " ") == r.target {
		r.used = true
		return nil, errors.New("isolated VM injected failure")
	}
	return r.ExecRunner.Run(ctx, name, args...)
}

func MustReadVM(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
