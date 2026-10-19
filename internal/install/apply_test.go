package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeInstallerRunner struct {
	users map[string]bool
	calls []string
	failUnit string
}

func (f *fakeInstallerRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
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
		if strings.Contains(call, "enable --now "+f.failUnit) && f.failUnit != "" {
			return nil, errors.New("fault injected")
		}
	case "chown":
		// Unit tests use a private filesystem root without changing system users.
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
	root string
	runner *fakeInstallerRunner
	opts ApplyOptions
	c Config
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
		filepath.Join(web, "sentinel.db"): "admin must survive",
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
