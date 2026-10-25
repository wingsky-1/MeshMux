package install

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeInstallerRunner struct {
	users    map[string]bool
	calls    []string
	failUnit string
	// failCall fails the first command whose rendered call contains this
	// substring, then stops firing so rollback itself can still proceed.
	failCall string
	failUsed bool
	// packages records dpkg's "install ok installed" answers.
	packages map[string]bool
}

func (f *fakeInstallerRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failCall != "" && !f.failUsed && strings.Contains(call, f.failCall) {
		f.failUsed = true
		return nil, errors.New("fault injected")
	}
	switch name {
	case "getent":
		if len(args) == 2 && f.users[args[1]] {
			return []byte("existing-user"), nil
		}
		return nil, errors.New("user not found")
	case "useradd":
		if f.users == nil {
			f.users = map[string]bool{}
		}
		f.users[args[len(args)-1]] = true
	case "systemctl":
		if f.failUnit != "" && (strings.Contains(call, "enable --now "+f.failUnit) || strings.Contains(call, "restart "+f.failUnit)) {
			return nil, errors.New("fault injected")
		}
	case "chown":
		// Unit tests use a private filesystem root without changing system users.
	case "dpkg-query":
		// args are ["-W", "-f=${Status}", pkg].
		if len(args) == 3 && f.packages[args[2]] {
			return []byte("install ok installed"), nil
		}
		return nil, errors.New("package not installed")
	default:
		if len(args) == 1 && args[0] == "version" {
			if strings.Contains(name, "caddy") {
				return []byte("v2.11.7"), nil
			}
			return []byte("v0.29.5"), nil
		}
	}
	return nil, nil
}

type installerFixture struct {
	root   string
	runner *fakeInstallerRunner
	opts   ApplyOptions
	c      Config
}

// TestRollbackDisablesHubDispatchPath pins the T4 review item: a failed fresh
// install must not leave the root path unit armed while its unit files are
// restored or removed.
func TestRollbackDisablesHubDispatchPath(t *testing.T) {
	root := t.TempDir()
	pathTarget := filepath.Join(root, strings.TrimPrefix(hubDispatchPathPath, "/"))
	serviceTarget := filepath.Join(root, strings.TrimPrefix(hubDispatchServicePath, "/"))
	for _, target := range []string{pathTarget, serviceTarget} {
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("[Unit]\nDescription=fixture\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeInstallerRunner{}
	snapshots := []fileSnapshot{
		{Target: pathTarget, Exists: false},
		{Target: serviceTarget, Exists: false},
	}
	if ok := rollbackManaged(context.Background(), ApplyOptions{Root: root, Runner: runner}, snapshots, false); !ok {
		t.Fatalf("rollback reported failure: %v", runner.calls)
	}
	found := false
	for _, call := range runner.calls {
		if call == "systemctl disable --now meshmux-hub-dispatch.path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback did not disable the hub dispatch path: %v", runner.calls)
	}
	for _, target := range []string{pathTarget, serviceTarget} {
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s was not removed by the rollback: %v", target, err)
		}
	}
}

func makeInstallerFixture(t *testing.T) installerFixture {
	t.Helper()
	root := t.TempDir()
	binaryDir := t.TempDir()
	source := filepath.Join(binaryDir, "meshmuxd")
	if err := os.WriteFile(source, []byte("isolated MeshMux test executable"), 0755); err != nil {
		t.Fatal(err)
	}
	assets := []Artifact{}
	for _, item := range []struct {
		component, version string
	}{
		{"caddy", "2.11.7"}, {"headscale", "0.29.5"},
	} {
		sourcePath := filepath.Join(binaryDir, item.component)
		data := []byte("verified test artifact " + item.component)
		if err := os.WriteFile(sourcePath, data, 0755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		assets = append(assets, Artifact{
			Component: item.component, Version: item.version,
			Source: "fixture://" + item.component, SHA256: hex.EncodeToString(sum[:]), Format: "elf",
		})
	}
	runner := &fakeInstallerRunner{users: map[string]bool{}}
	download := func(_ context.Context, a Artifact, _ string) (string, error) {
		return filepath.Join(binaryDir, a.Component), nil
	}
	return installerFixture{
		root: root, runner: runner,
		c: Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"},
		opts: ApplyOptions{
			Root: root, Runner: runner, Executable: source, Artifacts: assets,
			DownloadArtifact: download,
			Preflight: func(context.Context, Config, bool) ([]Check, []int) {
				return []Check{{Name: "system", Status: "pass"}, {Name: "public_https", Status: "pending"}}, []int{60794}
			},
			Verify: func(context.Context, Config, CommandRunner, func(context.Context, string) error) error { return nil },
		},
	}
}

func invokeInstaller(t *testing.T, fixture installerFixture, op string, repair bool) (InstallResult, error) {
	t.Helper()
	return InstallHub(context.Background(), fixture.c, op, repair, fixture.opts)
}

func TestHubInstallFirstRunIdempotentAndStatePreservation(t *testing.T) {
	f := makeInstallerFixture(t)
	result, err := invokeInstaller(t, f, strings.Repeat("a", 32), false)
	if err != nil || result.Status != "installed" {
		t.Fatalf("first install = %+v, %v", result, err)
	}
	state, ok, err := ReadState(f.root)
	if err != nil || !ok || state.Status != "installed" || len(state.ManagedFiles) < 10 {
		t.Fatalf("missing managed state: %+v, %v", state, err)
	}
	web := rooted(f.root, "/var/lib/meshmux")
	noise := rooted(f.root, "/var/lib/meshmux-headscale")
	if err := os.WriteFile(filepath.Join(web, "sentinel.db"), []byte("admin must survive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(noise, "noise_private.key"), []byte("keep key"), 0600); err != nil {
		t.Fatal(err)
	}
	before := len(f.runner.calls)
	result, err = invokeInstaller(t, f, strings.Repeat("b", 32), false)
	if err != nil || result.Status != "already_installed" {
		t.Fatalf("idempotent readback = %+v, %v", result, err)
	}
	if len(f.runner.calls) != before {
		t.Fatalf("idempotent call wrote to host: %v", f.runner.calls[before:])
	}
	result, err = invokeInstaller(t, f, strings.Repeat("c", 32), true)
	if err != nil || result.Status != "installed" {
		t.Fatalf("repair = %+v, %v", result, err)
	}
	for path, expected := range map[string]string{
		filepath.Join(web, "sentinel.db"):         "admin must survive",
		filepath.Join(noise, "noise_private.key"): "keep key",
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != expected {
			t.Fatalf("repair damaged user data %s: %q, %v", path, got, err)
		}
	}
	jail, err := os.ReadFile(rooted(f.root, "/etc/fail2ban/jail.d/meshmux-ssh.local"))
	if err != nil || !strings.Contains(string(jail), "port = 60794") {
		t.Fatalf("actual SSH port missing: %s, %v", jail, err)
	}
}

func TestHubInstallRejectsThirdPartyFilesAndSymlinks(t *testing.T) {
	for _, tc := range []string{"third-party", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			f := makeInstallerFixture(t)
			target := rooted(f.root, "/etc/meshmux/Caddyfile")
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if tc == "symlink" {
				if err := os.Symlink(filepath.Join(t.TempDir(), "other"), target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("must not overwrite"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := invokeInstaller(t, f, strings.Repeat("d", 32), false)
			if err == nil || result.Status != "failed" {
				t.Fatalf("third-party conflict silently adopted: %+v %v", result, err)
			}
			if _, found, err := ReadState(f.root); err != nil || found {
				t.Fatalf("conflict created installer state: found=%v err=%v", found, err)
			}
			if tc == "third-party" {
				data, _ := os.ReadFile(target)
				if string(data) != "must not overwrite" {
					t.Fatalf("third-party file overwritten: %q", data)
				}
			}
		})
	}
}

func TestHubInstallBadChecksumAndInterruptedServiceRecovery(t *testing.T) {
	f := makeInstallerFixture(t)
	f.opts.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	result, err := invokeInstaller(t, f, strings.Repeat("e", 32), false)
	if err == nil || result.ErrorCode != "ARTIFACT_CHECKSUM_MISMATCH" {
		t.Fatalf("checksum fail-open: %+v %v", result, err)
	}
	if _, err := os.Stat(rooted(f.root, "/usr/local/libexec/meshmux-caddy")); !os.IsNotExist(err) {
		t.Fatalf("failed checksum installed a binary: %v", err)
	}
	original := makeInstallerFixture(t)
	f.opts.Artifacts = original.opts.Artifacts
	f.opts.DownloadArtifact = original.opts.DownloadArtifact
	f.runner.failUnit = "meshmux-headscale.service"
	result, err = invokeInstaller(t, f, strings.Repeat("f", 32), true)
	if err == nil || result.ErrorCode != "HEADSCALE_START_FAILED" || result.Status != "partial" {
		t.Fatalf("service fault not recoverable: %+v %v", result, err)
	}
	if _, err := os.Stat(rooted(f.root, "/etc/meshmux/headscale.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed first activation did not roll back candidate: %v", err)
	}
	f.runner.failUnit = ""
	result, err = invokeInstaller(t, f, strings.Repeat("1", 32), true)
	if err != nil || result.Status != "installed" {
		t.Fatalf("repair after startup fault: %+v %v", result, err)
	}
}

func TestHubInstallRefusesModifiedManagedFile(t *testing.T) {
	f := makeInstallerFixture(t)
	if result, err := invokeInstaller(t, f, strings.Repeat("2", 32), false); err != nil || result.Status != "installed" {
		t.Fatalf("initial install: %+v %v", result, err)
	}
	target := rooted(f.root, "/etc/meshmux/Caddyfile")
	const manual = "operator-edited Caddyfile"
	if err := os.WriteFile(target, []byte(manual), 0640); err != nil {
		t.Fatal(err)
	}
	result, err := invokeInstaller(t, f, strings.Repeat("3", 32), true)
	if err == nil || result.ErrorCode != "MANAGED_FILE_DRIFT" {
		t.Fatalf("out-of-band edit silently overwritten: %+v %v", result, err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != manual {
		t.Fatalf("manual edit destroyed: %q", data)
	}
}

// TestHubRepairRollbackKeepsManagedLedgerConsistent reproduces a repair that
// fails and rolls back while a previous operation never reached "installed".
// The rollback must leave the ledger describing the restored files; emptying
// it would make the next repair reject MeshMux's own files.
func TestHubRepairRollbackKeepsManagedLedgerConsistent(t *testing.T) {
	f := makeInstallerFixture(t)
	if result, err := invokeInstaller(t, f, strings.Repeat("4", 32), false); err != nil || result.Status != "installed" {
		t.Fatalf("initial install: %+v %v", result, err)
	}
	// Simulate an apply that died mid-flight after writing and hashing every
	// file: the files exist on disk with matching hashes, but the run never
	// recorded "installed".
	state, ok, err := ReadState(f.root)
	if err != nil || !ok {
		t.Fatalf("read state: %+v %v", state, err)
	}
	state.Status, state.Stage = "installing", "apply"
	if err := writeState(f.root, state); err != nil {
		t.Fatal(err)
	}
	before := state.ManagedFiles
	if len(before) == 0 {
		t.Fatal("fixture ledger is empty; the regression cannot be exercised")
	}

	// Fault after snapshots exist, so the repair performs a real rollback.
	f.runner.failCall = "systemd-analyze verify"
	result, err := invokeInstaller(t, f, strings.Repeat("5", 32), true)
	if err == nil || result.ErrorCode != "SYSTEMD_UNIT_INVALID" || result.Status != "partial" {
		t.Fatalf("injected fault did not roll back to partial: %+v %v", result, err)
	}
	rolled, ok, err := ReadState(f.root)
	if err != nil || !ok {
		t.Fatalf("read rolled-back state: %+v %v", rolled, err)
	}
	if len(rolled.ManagedFiles) == 0 {
		t.Fatal("rollback cleared the managed-file ledger; --repair can no longer adopt the restored files")
	}
	if len(rolled.ManagedFiles) != len(before) {
		t.Fatalf("rollback changed the ledger size: before=%d after=%d", len(before), len(rolled.ManagedFiles))
	}
	for target, digest := range rolled.ManagedFiles {
		if digest != before[target] {
			t.Fatalf("ledger digest drifted for %s: %s != %s", target, digest, before[target])
		}
		actual, hashErr := sha256File(rooted(f.root, target))
		if hashErr != nil {
			t.Fatalf("ledger entry %s is not on disk: %v", target, hashErr)
		}
		if actual != digest {
			t.Fatalf("ledger hash for %s does not match the disk: %s != %s", target, digest, actual)
		}
	}

	// The decisive regression: repair must not reject its own restored files.
	f.runner.failCall = ""
	result, err = invokeInstaller(t, f, strings.Repeat("6", 32), true)
	if err != nil || result.Status != "installed" {
		t.Fatalf("second repair after rollback: %+v %v", result, err)
	}
}

// TestHubInstallQueriesPackagesBeforeApt covers the "query first, install
// second" rule: a host that already has every package must never run apt, and
// a host missing one package must install only that package.
func TestHubInstallQueriesPackagesBeforeApt(t *testing.T) {
	aptCalls := func(calls []string) []string {
		var out []string
		for _, call := range calls {
			if strings.HasPrefix(call, "apt-get ") {
				out = append(out, call)
			}
		}
		return out
	}

	t.Run("all-present", func(t *testing.T) {
		f := makeInstallerFixture(t)
		f.runner.packages = map[string]bool{"ca-certificates": true, "fail2ban": true, "nftables": true}
		if result, err := invokeInstaller(t, f, strings.Repeat("7", 32), false); err != nil || result.Status != "installed" {
			t.Fatalf("install with packages present: %+v %v", result, err)
		}
		if got := aptCalls(f.runner.calls); len(got) != 0 {
			t.Fatalf("apt ran although every package was installed: %v", got)
		}
	})

	t.Run("one-missing", func(t *testing.T) {
		f := makeInstallerFixture(t)
		f.runner.packages = map[string]bool{"fail2ban": true, "nftables": true}
		if result, err := invokeInstaller(t, f, strings.Repeat("8", 32), false); err != nil || result.Status != "installed" {
			t.Fatalf("install with one missing package: %+v %v", result, err)
		}
		got := aptCalls(f.runner.calls)
		if len(got) != 2 || got[0] != "apt-get update" {
			t.Fatalf("expected one update plus one install, got %v", got)
		}
		if got[1] != "apt-get install -y --no-install-recommends ca-certificates" {
			t.Fatalf("apt installed more than the missing package: %q", got[1])
		}
	})
}

// TestWaitForHTTPSReadinessSemantics locks in the readiness contract of the
// public HTTPS probe. A fresh install has no administrator yet, so /login
// legitimately answers 303 to /setup; treating that as a failure rolled back
// every first install with TLS_ISSUANCE_FAILED. The probe must observe the raw
// response instead of following redirects, and accept any 2xx/3xx while still
// rejecting 4xx/5xx.
func TestWaitForHTTPSReadinessSemantics(t *testing.T) {
	const domain = "console.example.org"
	originalAddress := httpsProbeAddress
	originalRoots := httpsProbeRoots
	t.Cleanup(func() {
		httpsProbeAddress = originalAddress
		httpsProbeRoots = originalRoots
	})

	// The probe verifies the chain and SNI, so the test certificate must be
	// trusted through the same seam instead of the system root store. Without
	// this, a handshake failure would make every "not ready" assertion pass
	// for the wrong reason.
	cert := proberCert(t, domain)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	httpsProbeRoots = pool

	newServer := func(handler http.HandlerFunc) *httptest.Server {
		srv := httptest.NewUnstartedServer(handler)
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	// waitForHTTPS dials a fixed local address, so point it at the test server.
	point := func(t *testing.T, url string) {
		t.Helper()
		_, port, err := net.SplitHostPort(strings.TrimPrefix(url, "https://"))
		if err != nil {
			t.Fatalf("test server URL: %v", err)
		}
		httpsProbeAddress = net.JoinHostPort("127.0.0.1", port)
	}

	t.Run("first-install redirect counts as ready", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
		})
		point(t, srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := waitForHTTPS(ctx, domain); err != nil {
			t.Fatalf("303 /login -> /setup must be ready: %v", err)
		}
	})

	t.Run("200 counts as ready", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		point(t, srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := waitForHTTPS(ctx, domain); err != nil {
			t.Fatalf("200 must be ready: %v", err)
		}
	})

	// 4xx/5xx must still fail. waitForHTTPS polls for 180s, so a short context
	// deadline keeps the test fast. Asserting DeadlineExceeded (rather than any
	// error) proves the handshake succeeded and the status was actually
	// rejected, instead of a certificate failure masking the outcome.
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprintf("%d is not ready", status), func(t *testing.T) {
			srv := newServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})
			point(t, srv.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := waitForHTTPS(ctx, domain)
			if err == nil {
				t.Fatalf("status %d must not be treated as healthy TLS termination", status)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("status %d failed for the wrong reason: %v", status, err)
			}
		})
	}
}

// proberCert mints a short-lived self-signed certificate for one domain. The
// returned Leaf lets a test trust it explicitly, so a plain httptest
// certificate cannot make a "not ready" assertion pass because of a failed
// handshake instead of the status code under test.
func proberCert(t *testing.T, domain string) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{domain},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
