package install

// The static root-dispatch units of #11d Task 4 (spec §5.1).
//
// This is the only new privileged surface of the Hub self-upgrade: one root
// oneshot, one path unit and one meshmux-writable request directory. The Web
// never calls root; it writes a request file, and PID 1 starts the fixed
// dispatcher. The dispatcher's ExecStart is constant and the staged package is
// authenticated separately, so no Web-side argv or unit attribute exists.
//
// The installer owns these files like every other managed unit: rendered as
// 0644 root:root candidates, validated with systemd-analyze, applied atomically
// and recorded in the ledger.

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

const (
	hubDispatchServicePath = "/etc/systemd/system/meshmux-hub-dispatch.service"
	hubDispatchPathPath    = "/etc/systemd/system/meshmux-hub-dispatch.path"
	hubTmpfilesPath        = "/etc/tmpfiles.d/meshmux.conf"

	hubDispatchPathUnit = "meshmux-hub-dispatch.path"
)

// hubDispatchService is a fixed oneshot. It has no [Install] section on purpose:
// the installer enables only the .path unit, and the service runs when the path
// unit fires.
//
// The ReadWritePaths list is intentionally broad: it is the enumerated write set
// of the Hub self-upgrade (staged/exec packages, data dir, installer state,
// config and systemd units). What keeps it safe is not a narrow path list but
// that ExecStart is a constant dispatcher which can only exec a root-manifest-
// pinned digest from a root-only copy; no unit attribute or argv comes from the
// Web.
const hubDispatchService = `[Unit]
Description=MeshMux Hub upgrade dispatcher
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/meshmuxd __internal-hub-dispatch --request-dir /run/meshmux-hub/requests
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/meshmux-hub /usr/local/libexec /var/lib/meshmux /var/lib/meshmux-installer /etc/meshmux /etc/systemd/system
PrivateTmp=yes
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE
StandardOutput=journal
StandardError=journal
`

// hubDispatchPath must run after systemd-tmpfiles-setup has created the watched
// directory; otherwise the path unit is never armed on boot.
const hubDispatchPath = `[Unit]
Description=Watch MeshMux Hub upgrade requests
After=systemd-tmpfiles-setup.service

[Path]
DirectoryNotEmpty=/run/meshmux-hub/requests
Unit=meshmux-hub-dispatch.service

[Install]
WantedBy=paths.target
`

// hubTmpfiles creates the runtime request tree and the installer-side result
// tree. /var/lib/meshmux-installer is 0711 so the Web can traverse to the root
// manifest and result files without being able to list the directory; the two
// ledgers below it stay 0600 root files outside this drop-in.
const hubTmpfiles = `# MeshMux Hub upgrade runtime and dispatcher state (#11d).
# The installer tree is traversable (0711) but not listable; ledgers stay 0600 root.
d /run/meshmux-hub 0730 root meshmux
d /run/meshmux-hub/requests 0730 root meshmux
d /run/meshmux-hub/requests.done 0700 root root
d /var/lib/meshmux-installer 0711 root root
d /var/lib/meshmux-installer/hub-upgrade 0755 root root
d /var/lib/meshmux-installer/hub-upgrade/results 0750 root meshmux
d /var/lib/meshmux-installer/upgrade 0755 root root
`

// hubDispatchFiles are the three new managed files of the dispatch substrate.
func hubDispatchFiles() map[string]string {
	return map[string]string{
		hubDispatchServicePath: hubDispatchService,
		hubDispatchPathPath:    hubDispatchPath,
		hubTmpfilesPath:        hubTmpfiles,
	}
}

// ensureHubUpgradeLayout prepares the installer-owned trees the dispatcher and
// the Web need before any request can exist:
//
//	/var/lib/meshmux-installer            0711 root:root  (traverse, not list)
//	/var/lib/meshmux-installer/upgrade    0755 root:root  (root manifests)
//	/var/lib/meshmux-installer/hub-upgrade 0755 root:root
//	.../hub-upgrade/results               0750 root:meshmux (Web reads only)
//
// InstallHub creates this shape at preflight so a fresh install is correct even
// before systemd-tmpfiles runs; the tmpfiles drop-in keeps the same shape on
// boot, and ensureHubUpgradeOwnership fixes ownership once the meshmux account
// exists.
func ensureHubUpgradeLayout(root string) error {
	installerDir := rooted(root, "/var/lib/meshmux-installer")
	if err := ensureDirectory(installerDir, 0711); err != nil {
		return err
	}
	hubDir := filepath.Join(installerDir, "hub-upgrade")
	if err := ensureDirectory(hubDir, 0755); err != nil {
		return err
	}
	resultsDir := filepath.Join(hubDir, "results")
	if err := ensureDirectory(resultsDir, 0750); err != nil {
		return err
	}
	manifestDir := filepath.Join(installerDir, "upgrade")
	if err := ensureDirectory(manifestDir, 0755); err != nil {
		return err
	}
	return nil
}

// ensureHubUpgradeOwnership fixes the root owner and the meshmux-readable result
// group after the service accounts exist. The preflight layout call runs before
// the fresh-install account creation, so the group lookup lives here instead.
func ensureHubUpgradeOwnership(root string) error {
	if root != "" && root != "/" {
		return nil
	}
	installerDir := rooted(root, "/var/lib/meshmux-installer")
	hubDir := filepath.Join(installerDir, "hub-upgrade")
	resultsDir := filepath.Join(hubDir, "results")
	manifestDir := filepath.Join(installerDir, "upgrade")
	if err := os.Chown(hubDir, 0, 0); err != nil {
		return errors.New("HUB_UPGRADE_STATE_LAYOUT_FAILED")
	}
	if err := os.Chown(manifestDir, 0, 0); err != nil {
		return errors.New("HUB_UPGRADE_STATE_LAYOUT_FAILED")
	}
	group, err := user.LookupGroup("meshmux")
	if err != nil {
		return errors.New("HUB_UPGRADE_STATE_LAYOUT_FAILED")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return errors.New("HUB_UPGRADE_STATE_LAYOUT_FAILED")
	}
	if err := os.Chown(resultsDir, 0, gid); err != nil {
		return errors.New("HUB_UPGRADE_STATE_LAYOUT_FAILED")
	}
	return nil
}

// hubDispatchManagedTargets is the fixed validation list of the new units. The
// tmpfiles drop-in is not a unit and is validated by content in CI.
func hubDispatchManagedTargets() []string {
	return []string{hubDispatchServicePath, hubDispatchPathPath}
}
