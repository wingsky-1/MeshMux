package hub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// The fixture is shared with the node package's co-location tests; both read
// the same non-test helper from install/core because a _test.go declaration
// cannot cross package boundaries.
type fakeInstallerRunner = core.HubTestRunner

type installerFixture = core.HubInstallerFixture

// TestRollbackDisablesHubDispatchPath pins the T4 review item: a failed fresh
// install must not leave the root path unit armed while its unit files are
// restored or removed.
func TestRollbackDisablesHubDispatchPath(t *testing.T) {
	root := t.TempDir()
	pathTarget := filepath.Join(root, strings.TrimPrefix(core.HubDispatchPathPath, "/"))
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
	snapshots := []core.FileSnapshot{
		{Target: pathTarget, Exists: false},
		{Target: serviceTarget, Exists: false},
	}
	if ok := core.RollbackManaged(context.Background(), core.ApplyOptions{Root: root, Runner: runner}, snapshots, false); !ok {
		t.Fatalf("rollback reported failure: %v", runner.Calls)
	}
	found := false
	for _, call := range runner.Calls {
		if call == "systemctl disable --now meshmux-hub-dispatch.path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback did not disable the hub dispatch path: %v", runner.Calls)
	}
	for _, target := range []string{pathTarget, serviceTarget} {
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s was not removed by the rollback: %v", target, err)
		}
	}
}

func callIndex(calls []string, want string) int {
	for i, call := range calls {
		if call == want {
			return i
		}
	}
	return -1
}

// TestActivateUnitRepairClearsStartLimitBeforeRestart pins the repair recovery
// path: failed starts consume the unit's StartLimitBurst budget, so the fourth
// repair restart would be refused with "Start request repeated too quickly"
// unless reset-failed runs first.
func TestActivateUnitRepairClearsStartLimitBeforeRestart(t *testing.T) {
	runner := &fakeInstallerRunner{}
	if err := core.ActivateUnit(context.Background(), runner, "meshmux-web.service", true); err != nil {
		t.Fatalf("repair activation failed: %v", err)
	}
	reset := callIndex(runner.Calls, "systemctl reset-failed meshmux-web.service")
	restart := callIndex(runner.Calls, "systemctl restart meshmux-web.service")
	if reset < 0 || restart < 0 || reset > restart {
		t.Fatalf("reset-failed must precede restart: %v", runner.Calls)
	}
}

// TestActivateUnitRepairToleratesResetFailedError keeps the reset best-effort:
// a unit with no recorded failure makes reset-failed exit non-zero, which must
// not turn a valid repair into a failed one.
func TestActivateUnitRepairToleratesResetFailedError(t *testing.T) {
	runner := &fakeInstallerRunner{FailCall: "systemctl reset-failed meshmux-caddy.service"}
	if err := core.ActivateUnit(context.Background(), runner, "meshmux-caddy.service", true); err != nil {
		t.Fatalf("reset-failed error aborted the repair restart: %v", err)
	}
	if callIndex(runner.Calls, "systemctl restart meshmux-caddy.service") < 0 {
		t.Fatalf("repair did not restart the unit after reset-failed failed: %v", runner.Calls)
	}
}

// TestActivateUnitFreshInstallSkipsResetFailed keeps the fresh-install path
// unchanged: enable --now is the only activation command.
func TestActivateUnitFreshInstallSkipsResetFailed(t *testing.T) {
	runner := &fakeInstallerRunner{}
	if err := core.ActivateUnit(context.Background(), runner, "meshmux-web.service", false); err != nil {
		t.Fatalf("fresh activation failed: %v", err)
	}
	want := []string{"systemctl enable --now meshmux-web.service"}
	if len(runner.Calls) != 1 || runner.Calls[0] != want[0] {
		t.Fatalf("fresh activation calls = %v, want %v", runner.Calls, want)
	}
}

// TestRollbackClearsStartLimitBeforeStart covers the rollback restore loop: the
// failed apply already spent the units' start budget, so the rollback must
// clear it before starting the previously verified units, or a recoverable
// failure escalates to ROLLBACK_FAILED.
func TestRollbackClearsStartLimitBeforeStart(t *testing.T) {
	runner := &fakeInstallerRunner{}
	opts := core.ApplyOptions{Root: t.TempDir(), Runner: runner}
	if ok := core.RollbackManaged(context.Background(), opts, nil, true); !ok {
		t.Fatalf("rollback reported failure: %v", runner.Calls)
	}
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service"} {
		reset := callIndex(runner.Calls, "systemctl reset-failed "+unit)
		start := callIndex(runner.Calls, "systemctl start "+unit)
		if reset < 0 || start < 0 || reset > start {
			t.Fatalf("rollback must reset-failed before starting %s: %v", unit, runner.Calls)
		}
	}
}

// TestRollbackToleratesResetFailedError keeps the rollback restore best-effort
// in the same way as the repair path: a reset failure must not fail the
// rollback nor skip the start.
func TestRollbackToleratesResetFailedError(t *testing.T) {
	runner := &fakeInstallerRunner{FailCall: "systemctl reset-failed meshmux-web.service"}
	opts := core.ApplyOptions{Root: t.TempDir(), Runner: runner}
	if ok := core.RollbackManaged(context.Background(), opts, nil, true); !ok {
		t.Fatalf("reset-failed error turned the rollback into a failure: %v", runner.Calls)
	}
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service"} {
		if callIndex(runner.Calls, "systemctl start "+unit) < 0 {
			t.Fatalf("rollback skipped starting %s after reset-failed failed: %v", unit, runner.Calls)
		}
	}
}

func MakeInstallerFixture(t *testing.T) installerFixture {
	t.Helper()
	return core.NewHubInstallerFixture(t.TempDir(), t.TempDir())
}

func InvokeInstaller(t *testing.T, fixture installerFixture, op string, repair bool) (core.InstallResult, error) {
	t.Helper()
	return InstallHub(context.Background(), fixture.Config, op, repair, fixture.Options)
}

func TestHubInstallFirstRunIdempotentAndStatePreservation(t *testing.T) {
	f := MakeInstallerFixture(t)
	result, err := InvokeInstaller(t, f, strings.Repeat("a", 32), false)
	if err != nil || result.Status != "installed" {
		t.Fatalf("first install = %+v, %v", result, err)
	}
	state, ok, err := core.ReadState(f.Root)
	if err != nil || !ok || state.Status != "installed" || len(state.ManagedFiles) < 10 {
		t.Fatalf("missing managed state: %+v, %v", state, err)
	}
	web := core.Rooted(f.Root, "/var/lib/meshmux")
	noise := core.Rooted(f.Root, "/var/lib/meshmux-headscale")
	if err := os.WriteFile(filepath.Join(web, "sentinel.db"), []byte("admin must survive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(noise, "noise_private.key"), []byte("keep key"), 0600); err != nil {
		t.Fatal(err)
	}
	before := len(f.Runner.Calls)
	result, err = InvokeInstaller(t, f, strings.Repeat("b", 32), false)
	if err != nil || result.Status != "already_installed" {
		t.Fatalf("idempotent readback = %+v, %v", result, err)
	}
	if len(f.Runner.Calls) != before {
		t.Fatalf("idempotent call wrote to host: %v", f.Runner.Calls[before:])
	}
	result, err = InvokeInstaller(t, f, strings.Repeat("c", 32), true)
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
	jail, err := os.ReadFile(core.Rooted(f.Root, "/etc/fail2ban/jail.d/meshmux-ssh.local"))
	if err != nil || !strings.Contains(string(jail), "port = 60794") {
		t.Fatalf("actual SSH port missing: %s, %v", jail, err)
	}
}

func TestHubInstallRejectsThirdPartyFilesAndSymlinks(t *testing.T) {
	for _, tc := range []string{"third-party", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			f := MakeInstallerFixture(t)
			target := core.Rooted(f.Root, "/etc/meshmux/Caddyfile")
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
			result, err := InvokeInstaller(t, f, strings.Repeat("d", 32), false)
			if err == nil || result.Status != "failed" {
				t.Fatalf("third-party conflict silently adopted: %+v %v", result, err)
			}
			if _, found, err := core.ReadState(f.Root); err != nil || found {
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
	f := MakeInstallerFixture(t)
	f.Options.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	result, err := InvokeInstaller(t, f, strings.Repeat("e", 32), false)
	if err == nil || result.ErrorCode != "ARTIFACT_CHECKSUM_MISMATCH" {
		t.Fatalf("checksum fail-open: %+v %v", result, err)
	}
	if _, err := os.Stat(core.Rooted(f.Root, "/usr/local/libexec/meshmux-caddy")); !os.IsNotExist(err) {
		t.Fatalf("failed checksum installed a binary: %v", err)
	}
	original := MakeInstallerFixture(t)
	f.Options.Artifacts = original.Options.Artifacts
	f.Options.DownloadArtifact = original.Options.DownloadArtifact
	f.Runner.FailUnit = "meshmux-headscale.service"
	result, err = InvokeInstaller(t, f, strings.Repeat("f", 32), true)
	if err == nil || result.ErrorCode != "HEADSCALE_START_FAILED" || result.Status != "partial" {
		t.Fatalf("service fault not recoverable: %+v %v", result, err)
	}
	if _, err := os.Stat(core.Rooted(f.Root, "/etc/meshmux/headscale.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed first activation did not roll back candidate: %v", err)
	}
	f.Runner.FailUnit = ""
	result, err = InvokeInstaller(t, f, strings.Repeat("1", 32), true)
	if err != nil || result.Status != "installed" {
		t.Fatalf("repair after startup fault: %+v %v", result, err)
	}
}

func TestHubInstallRefusesModifiedManagedFile(t *testing.T) {
	f := MakeInstallerFixture(t)
	if result, err := InvokeInstaller(t, f, strings.Repeat("2", 32), false); err != nil || result.Status != "installed" {
		t.Fatalf("initial install: %+v %v", result, err)
	}
	target := core.Rooted(f.Root, "/etc/meshmux/Caddyfile")
	const manual = "operator-edited Caddyfile"
	if err := os.WriteFile(target, []byte(manual), 0640); err != nil {
		t.Fatal(err)
	}
	result, err := InvokeInstaller(t, f, strings.Repeat("3", 32), true)
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
	f := MakeInstallerFixture(t)
	if result, err := InvokeInstaller(t, f, strings.Repeat("4", 32), false); err != nil || result.Status != "installed" {
		t.Fatalf("initial install: %+v %v", result, err)
	}
	// Simulate an apply that died mid-flight after writing and hashing every
	// file: the files exist on disk with matching hashes, but the run never
	// recorded "installed".
	state, ok, err := core.ReadState(f.Root)
	if err != nil || !ok {
		t.Fatalf("read state: %+v %v", state, err)
	}
	state.Status, state.Stage = "installing", "apply"
	if err := core.WriteState(f.Root, state); err != nil {
		t.Fatal(err)
	}
	before := state.ManagedFiles
	if len(before) == 0 {
		t.Fatal("fixture ledger is empty; the regression cannot be exercised")
	}

	// Fault after snapshots exist, so the repair performs a real rollback.
	f.Runner.FailCall = "systemd-analyze verify"
	result, err := InvokeInstaller(t, f, strings.Repeat("5", 32), true)
	if err == nil || result.ErrorCode != "SYSTEMD_UNIT_INVALID" || result.Status != "partial" {
		t.Fatalf("injected fault did not roll back to partial: %+v %v", result, err)
	}
	rolled, ok, err := core.ReadState(f.Root)
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
		actual, hashErr := core.SHA256File(core.Rooted(f.Root, target))
		if hashErr != nil {
			t.Fatalf("ledger entry %s is not on disk: %v", target, hashErr)
		}
		if actual != digest {
			t.Fatalf("ledger hash for %s does not match the disk: %s != %s", target, digest, actual)
		}
	}

	// The decisive regression: repair must not reject its own restored files.
	f.Runner.FailCall = ""
	result, err = InvokeInstaller(t, f, strings.Repeat("6", 32), true)
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
		f := MakeInstallerFixture(t)
		f.Runner.Packages = map[string]bool{"ca-certificates": true, "fail2ban": true, "nftables": true, "python3-systemd": true}
		if result, err := InvokeInstaller(t, f, strings.Repeat("7", 32), false); err != nil || result.Status != "installed" {
			t.Fatalf("install with packages present: %+v %v", result, err)
		}
		if got := aptCalls(f.Runner.Calls); len(got) != 0 {
			t.Fatalf("apt ran although every package was installed: %v", got)
		}
	})

	t.Run("one-missing", func(t *testing.T) {
		f := MakeInstallerFixture(t)
		f.Runner.Packages = map[string]bool{"fail2ban": true, "nftables": true, "python3-systemd": true}
		if result, err := InvokeInstaller(t, f, strings.Repeat("8", 32), false); err != nil || result.Status != "installed" {
			t.Fatalf("install with one missing package: %+v %v", result, err)
		}
		got := aptCalls(f.Runner.Calls)
		if len(got) != 2 || got[0] != "apt-get update" {
			t.Fatalf("expected one update plus one install, got %v", got)
		}
		if got[1] != "apt-get install -y --no-install-recommends ca-certificates" {
			t.Fatalf("apt installed more than the missing package: %q", got[1])
		}
	})

	// A minimal Debian image has Fail2ban installed but not the systemd
	// backend binding: every MeshMux jail uses backend = systemd, so the
	// installer must supply python3-systemd instead of relying on a
	// recommendation that --no-install-recommends suppresses.
	t.Run("systemd-backend-missing", func(t *testing.T) {
		f := MakeInstallerFixture(t)
		f.Runner.Packages = map[string]bool{"ca-certificates": true, "fail2ban": true, "nftables": true}
		if result, err := InvokeInstaller(t, f, strings.Repeat("9", 32), false); err != nil || result.Status != "installed" {
			t.Fatalf("install with python3-systemd missing: %+v %v", result, err)
		}
		got := aptCalls(f.Runner.Calls)
		if len(got) != 2 || got[1] != "apt-get install -y --no-install-recommends python3-systemd" {
			t.Fatalf("apt must install exactly python3-systemd: %v", got)
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
	originalAddress := core.HTTPSProbeAddress
	originalRoots := core.HTTPSProbeRoots
	t.Cleanup(func() {
		core.HTTPSProbeAddress = originalAddress
		core.HTTPSProbeRoots = originalRoots
	})

	// The probe verifies the chain and SNI, so the test certificate must be
	// trusted through the same seam instead of the system root store. Without
	// this, a handshake failure would make every "not ready" assertion pass
	// for the wrong reason.
	cert := proberCert(t, domain)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	core.HTTPSProbeRoots = pool

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
		core.HTTPSProbeAddress = net.JoinHostPort("127.0.0.1", port)
	}

	t.Run("first-install redirect counts as ready", func(t *testing.T) {
		srv := newServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
		})
		point(t, srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := core.WaitForHTTPS(ctx, domain); err != nil {
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
		if err := core.WaitForHTTPS(ctx, domain); err != nil {
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
			err := core.WaitForHTTPS(ctx, domain)
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

// plantHubDatabaseBackup writes the pre-migration snapshot chain the new Web
// binary leaves in the Hub data directory: a committed per-operation record, its
// verified database copy and the flat pointer the downgraded binary names.
func plantHubDatabaseBackup(t *testing.T, root string) (recordPath, payloadPath string) {
	t.Helper()
	backupRoot := filepath.Join(core.Rooted(root, versions.HubDataDir), versions.HubDatabaseBackupDir)
	operationID := strings.Repeat("9", 32)
	dir, err := backup.Dir(backupRoot, operationID)
	if err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(dir, backup.PayloadPart)
	if err := os.Mkdir(part, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, backup.SingleDBName), []byte("pre-migration copy"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Write(backupRoot, backup.Spec{
		OperationID: operationID, FromVersion: "1.0.0", TargetVersion: buildinfo.Version,
		DBSchema: 16, PolicySchema: 8,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
	}, backup.Payload{Kind: backup.PayloadSingleDB, Check: func(string) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	body, err := backup.ReadRecordBytes(dir, operationID, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	recordPath = filepath.Join(backupRoot, backup.RecordName)
	if err := os.WriteFile(recordPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	return recordPath, filepath.Join(dir, backup.PayloadDir, backup.SingleDBName)
}

// TestHubRollbackNamesThePreMigrationDatabaseBackup is the rollback half of the
// installer upgrade P0: a failed repair that rolls back the package must say
// where the database copy of the new binary's migration is, because the restored
// old binary will refuse the migrated file with SCHEMA_TOO_NEW.
func TestHubRollbackNamesThePreMigrationDatabaseBackup(t *testing.T) {
	f := MakeInstallerFixture(t)
	if result, err := InvokeInstaller(t, f, strings.Repeat("5", 32), false); err != nil || result.Status != "installed" {
		t.Fatalf("first install = %+v, %v", result, err)
	}
	recordPath, payloadPath := plantHubDatabaseBackup(t, f.Root)
	f.Options.Verify = func(context.Context, core.Config, core.CommandRunner, func(context.Context, string) error) error {
		return &core.InstallError{Stage: "verify", Code: "WEB_HEALTH_FAILED", Recovery: "Check meshmux-web.service, the loopback Web port, and the private SQLite directory."}
	}
	result, err := InvokeInstaller(t, f, strings.Repeat("6", 32), true)
	if err == nil || result.Status != "rolled_back" {
		t.Fatalf("failed repair = %+v, %v", result, err)
	}
	for _, want := range []string{recordPath, payloadPath, "from_version 1.0.0", "db_schema 16"} {
		if !strings.Contains(result.Recovery, want) {
			t.Fatalf("rollback recovery does not name %q: %s", want, result.Recovery)
		}
	}
	var ie *core.InstallError
	if !errors.As(err, &ie) || !strings.Contains(ie.Recovery, recordPath) {
		t.Fatalf("the error the CLI prints lost the backup path: %v", err)
	}
	journal, readErr := os.ReadFile(filepath.Join(f.Root, "var/lib/meshmux-installer/operations", strings.Repeat("6", 32), "events.jsonl"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(journal), "hub_database_backup") || !strings.Contains(string(journal), recordPath) {
		t.Fatalf("operation journal does not record the backup: %s", journal)
	}
}
