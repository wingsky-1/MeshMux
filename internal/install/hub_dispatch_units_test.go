package install

// R-SURFACE tests of the static dispatch units and the installer-owned state
// layout (#11d Task 4, spec §5.1/§5.9). These files are the only new privileged
// surface: one root oneshot, one path unit and one meshmux-writable request
// directory.

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func hubFixtureConfig() Config {
	return Config{
		ManagementDomain:   "admin.example.org",
		SubscriptionDomain: "sub.example.org",
		HeadscaleDomain:    "mesh.example.org",
	}
}

func TestHubDispatchUnitsPinned(t *testing.T) {
	files, err := CandidateFiles(hubFixtureConfig(), []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	service, ok := files[hubDispatchServicePath]
	if !ok {
		t.Fatal("dispatcher service is not a managed candidate")
	}
	for _, line := range []string{
		"Type=oneshot",
		"ExecStart=/usr/local/libexec/meshmuxd __internal-hub-dispatch --request-dir /run/meshmux-hub/requests",
		"User=root",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ReadWritePaths=/run/meshmux-hub /usr/local/libexec /var/lib/meshmux /var/lib/meshmux-installer /etc/meshmux /etc/systemd/system",
		"CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE",
	} {
		if !strings.Contains(service, line+"\n") {
			t.Fatalf("dispatcher service is missing %q:\n%s", line, service)
		}
	}
	if strings.Contains(service, "[Install]") {
		t.Fatal("the dispatcher service must not be enabled directly")
	}

	pathUnit, ok := files[hubDispatchPathPath]
	if !ok {
		t.Fatal("dispatcher path unit is not a managed candidate")
	}
	for _, line := range []string{
		"After=systemd-tmpfiles-setup.service",
		"DirectoryNotEmpty=/run/meshmux-hub/requests",
		"Unit=meshmux-hub-dispatch.service",
		"WantedBy=paths.target",
	} {
		if !strings.Contains(pathUnit, line+"\n") {
			t.Fatalf("dispatcher path unit is missing %q:\n%s", line, pathUnit)
		}
	}

	tmpfiles, ok := files[hubTmpfilesPath]
	if !ok {
		t.Fatal("tmpfiles drop-in is not a managed candidate")
	}
	for _, line := range []string{
		"d /run/meshmux-hub 0730 root meshmux",
		"d /run/meshmux-hub/requests 0730 root meshmux",
		"d /run/meshmux-hub/requests.done 0700 root root",
		"d /var/lib/meshmux-installer 0711 root root",
		"d /var/lib/meshmux-installer/hub-upgrade 0755 root root",
		"d /var/lib/meshmux-installer/hub-upgrade/results 0750 root meshmux",
		"d /var/lib/meshmux-installer/upgrade 0755 root root",
	} {
		if !strings.Contains(tmpfiles, line+"\n") {
			t.Fatalf("tmpfiles drop-in is missing %q:\n%s", line, tmpfiles)
		}
	}

	for _, path := range []string{hubDispatchServicePath, hubDispatchPathPath, hubTmpfilesPath} {
		mode, owner := filePolicy(path)
		if mode != 0644 || owner != "root:root" {
			t.Fatalf("%s policy = %o %s, want 0644 root:root", path, mode, owner)
		}
	}

	web := files["/etc/systemd/system/meshmux-web.service"]
	if !strings.Contains(web, "ReadWritePaths=/run/meshmux-hub/requests\n") {
		t.Fatalf("web unit cannot write the request directory:\n%s", web)
	}
}

func TestResultDirRejectsWebWrites(t *testing.T) {
	root := t.TempDir()
	if err := ensureHubUpgradeLayout(root); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		path string
		mode os.FileMode
	}{
		{"/var/lib/meshmux-installer", 0711},
		{"/var/lib/meshmux-installer/hub-upgrade", 0755},
		{"/var/lib/meshmux-installer/hub-upgrade/results", 0750},
		{"/var/lib/meshmux-installer/upgrade", 0755},
	}
	for _, check := range checks {
		info, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(check.path, "/")))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode = %o, want %o", check.path, info.Mode().Perm(), check.mode)
		}
		if check.path == "/var/lib/meshmux-installer/hub-upgrade/results" {
			// meshmux reads results but never writes or replaces them.
			if info.Mode().Perm()&0022 != 0 {
				t.Fatalf("results directory is writable by group/other: %o", info.Mode().Perm())
			}
		}
		// The installer state tree is traversable for the Web but not listable.
		if check.path == "/var/lib/meshmux-installer" && info.Mode().Perm()&0111 == 0 {
			t.Fatal("installer state directory is not traversable")
		}
	}
	// A literal EACCES needs the Web identity; a non-root fixture cannot switch
	// uid, so the mode assertions above are the B-level proof there. When the
	// test itself runs as root on a host with the meshmux account, prove it.
	if os.Geteuid() == 0 {
		account, err := user.Lookup("meshmux")
		if err == nil {
			uid, uidErr := strconv.Atoi(account.Uid)
			gid, gidErr := strconv.Atoi(account.Gid)
			if uidErr == nil && gidErr == nil && uid != 0 {
				if err := os.Chmod(root, 0711); err != nil {
					t.Fatal(err)
				}
				probe := filepath.Join(root, "var/lib/meshmux-installer/hub-upgrade/results/probe")
				cmd := exec.Command("touch", probe)
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
				if err := cmd.Run(); err == nil {
					t.Fatalf("the Web account wrote %s; results must be read-only for it", probe)
				}
			}
		}
	}
}

func TestInstallerStateDirTraversable(t *testing.T) {
	root := t.TempDir()
	if err := ensureHubUpgradeLayout(root); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "var/lib/meshmux-installer")
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0711 {
		t.Fatalf("installer state dir mode = %o, want 0711", info.Mode().Perm())
	}
	if err := writeState(root, InstallState{Schema: 1, OperationID: "abc", Status: "installed"}); err != nil {
		t.Fatal(err)
	}
	ledger, err := os.Lstat(filepath.Join(stateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ledger.Mode().Perm() != 0600 {
		t.Fatalf("ledger mode = %o, want 0600", ledger.Mode().Perm())
	}
	if ledger.Mode().Perm()&0077 != 0 {
		t.Fatal("ledger is readable by another account")
	}
}

func TestHubTargetManifestDirMode(t *testing.T) {
	root := t.TempDir()
	if err := ensureHubUpgradeLayout(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, "var/lib/meshmux-installer/upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("root manifest dir mode = %o, want 0755", info.Mode().Perm())
	}
}
