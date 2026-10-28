package hub

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

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

func hubFixtureConfig() core.Config {
	return core.Config{
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

	pathUnit, ok := files[core.HubDispatchPathPath]
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
		"d /run/meshmux-hub/staging 0730 root meshmux",
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

	for _, path := range []string{hubDispatchServicePath, core.HubDispatchPathPath, hubTmpfilesPath} {
		mode, owner := core.FilePolicy(path)
		if mode != 0644 || owner != "root:root" {
			t.Fatalf("%s policy = %o %s, want 0644 root:root", path, mode, owner)
		}
	}

	web := files["/etc/systemd/system/meshmux-web.service"]
	// Both runtime directories must be writable: the Web completes a request in
	// staging/ and renames it into requests/, and ProtectSystem=strict makes an
	// undeclared path EROFS while a declared-but-absent one fails the unit with
	// 226/NAMESPACE.
	if !strings.Contains(web, "ReadWritePaths=/run/meshmux-hub/requests /run/meshmux-hub/staging\n") {
		t.Fatalf("web unit does not declare the request and staging directories writable:\n%s", web)
	}
}

// TestHubRuntimeDirsDeclaredWritable is the blocker-1 fix regression of the T4r
// review round. The Web publishes a request through an unwatched staging sibling
// and only renames the finished document into requests/, so *both* directories
// must be writable for the Web identity in every three places that can grant it:
//
//  1. the shipped web unit (ProtectSystem=strict means an undeclared path is
//     EROFS, and a declared-but-absent path makes the unit fail 226/NAMESPACE);
//  2. the tmpfiles drop-in that creates the tree on boot;
//  3. the installer preflight layout that creates it before any unit can start.
func TestHubRuntimeDirsDeclaredWritable(t *testing.T) {
	files, err := CandidateFiles(hubFixtureConfig(), []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	web := files["/etc/systemd/system/meshmux-web.service"]
	var readWritePaths []string
	for _, line := range strings.Split(web, "\n") {
		if !strings.HasPrefix(line, "ReadWritePaths=") {
			continue
		}
		readWritePaths = append(readWritePaths, strings.Fields(strings.TrimPrefix(line, "ReadWritePaths="))...)
	}
	if len(readWritePaths) == 0 {
		t.Fatalf("the web unit declares no ReadWritePaths:\n%s", web)
	}
	for _, want := range []string{"/run/meshmux-hub/requests", "/run/meshmux-hub/staging", "/run/meshmux-hub/boot"} {
		found := false
		for _, path := range readWritePaths {
			if path == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("the web unit does not declare %s writable (writes there are EROFS): %v", want, readWritePaths)
		}
	}

	tmpfiles := files[hubTmpfilesPath]
	for _, line := range []string{
		"d /run/meshmux-hub/staging 0730 root meshmux",
		"d /run/meshmux-hub/boot 0730 root meshmux",
	} {
		if !strings.Contains(tmpfiles, line+"\n") {
			t.Fatalf("the tmpfiles drop-in does not create %q:\n%s", line, tmpfiles)
		}
	}

	root := t.TempDir()
	if err := ensureHubUpgradeLayout(root); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/run/meshmux-hub", "/run/meshmux-hub/requests", "/run/meshmux-hub/staging", "/run/meshmux-hub/boot"} {
		info, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(dir, "/")))
		if err != nil {
			t.Fatalf("the installer layout does not pre-create %s (the web unit then fails 226/NAMESPACE): %v", dir, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0730 {
			t.Fatalf("%s mode = %v %o, want a 0730 directory", dir, info.IsDir(), info.Mode().Perm())
		}
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
	if err := core.WriteState(root, core.InstallState{Schema: 1, OperationID: "abc", Status: "installed"}); err != nil {
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
