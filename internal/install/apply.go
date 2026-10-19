package install

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	installerStatePath  = "/var/lib/meshmux-installer/state.json"
	runtimeBinaryPath   = "/usr/local/libexec/meshmuxd"
	caddyBinaryPath     = "/usr/local/libexec/meshmux-caddy"
	headscaleBinaryPath = "/usr/local/libexec/meshmux-headscale"
	maxInstallerFile    = 128 << 20
)

type InstallState struct {
	Schema        int               "json:\"schema\""
	OperationID   string            "json:\"operation_id\""
	Status        string            "json:\"status\""
	Stage         string            "json:\"stage\""
	Config        Config            "json:\"config\""
	Architecture  string            "json:\"architecture\""
	CreatedAt     time.Time         "json:\"created_at\""
	UpdatedAt     time.Time         "json:\"updated_at\""
	ManagedFiles  map[string]string "json:\"managed_files\""
	Artifacts     map[string]string "json:\"artifacts\""
	SSHPorts      []int             "json:\"ssh_ports\""
	ErrorCode     string            "json:\"error_code,omitempty\""
	Recovery      string            "json:\"recovery,omitempty\""
	LastOperation string            "json:\"last_operation_id,omitempty\""
}

type InstallResult struct {
	OperationID string      "json:\"operation_id\""
	Stage       string      "json:\"stage\""
	Status      string      "json:\"status\""
	ErrorCode   string      "json:\"error_code,omitempty\""
	Recovery    string      "json:\"next_action,omitempty\""
	Checks      []Check     "json:\"checks,omitempty\""
	Artifacts   []Component "json:\"components,omitempty\""
}

type InstallError struct {
	Stage    string
	Code     string
	Recovery string
}

func (e *InstallError) Error() string { return e.Code }

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type ApplyOptions struct {
	// Root is "/" in production. A temporary root is accepted only by tests.
	Root             string
	Runner           CommandRunner
	HTTPClient       *http.Client
	Executable       string
	Preflight        func(context.Context, Config, bool) ([]Check, []int)
	DownloadArtifact func(context.Context, Artifact, string) (string, error)
	TLSProbe         func(context.Context, string) error
	// Test-only seam used by the isolated systemd integration test. It is not
	// exposed by the CLI and cannot be enabled through user configuration.
	InternalTLSForTest bool
	Artifacts          []Artifact
	Verify             func(context.Context, Config, CommandRunner, func(context.Context, string) error) error
}

type operationEvent struct {
	OperationID string    "json:\"operation_id\""
	Stage       string    "json:\"stage\""
	Status      string    "json:\"status\""
	ErrorCode   string    "json:\"error_code,omitempty\""
	Time        time.Time "json:\"time\""
}

type fileSnapshot struct {
	Target string
	Backup string
	Exists bool
	Mode   os.FileMode
	UID    int
	GID    int
}

var operationIDPattern = regexp.MustCompile("^[a-f0-9]{32}$")

func ReadState(root string) (InstallState, bool, error) {
	var state InstallState
	path := rooted(root, installerStatePath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, errors.New("INSTALL_STATE_UNAVAILABLE")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return state, false, errors.New("INSTALL_STATE_UNSAFE")
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &state) != nil || state.Schema != 1 || state.OperationID == "" || state.Status == "" {
		return state, false, errors.New("INSTALL_STATE_INVALID")
	}
	return state, true, nil
}

func InstallHub(ctx context.Context, c Config, operationID string, repair bool, opts ApplyOptions) (InstallResult, error) {
	result := InstallResult{OperationID: operationID, Stage: "preflight", Status: "failed"}
	fail := func(stage, code, recovery string) (InstallResult, error) {
		result.Stage, result.Status, result.ErrorCode, result.Recovery = stage, "failed", code, recovery
		return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
	}
	if !operationIDPattern.MatchString(operationID) {
		return fail("preflight", "OPERATION_ID_INVALID", "Generate a new operation ID and retry.")
	}
	if err := c.Validate(); err != nil {
		return fail("preflight", "DOMAIN_INVALID", "Supply three distinct lowercase public DNS names.")
	}
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.Root == "/" && os.Geteuid() != 0 {
		return fail("preflight", "ROOT_REQUIRED", "Run the installer as root; the Web service itself runs unprivileged.")
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.Preflight == nil {
		opts.Preflight = PreflightWithMode
	}
	if opts.DownloadArtifact == nil {
		opts.DownloadArtifact = func(ctx context.Context, a Artifact, dir string) (string, error) {
			return DownloadVerified(ctx, opts.HTTPClient, a, dir)
		}
	}
	if opts.TLSProbe == nil {
		opts.TLSProbe = waitForHTTPS
	}
	if opts.Verify == nil {
		opts.Verify = verifyServices
	}

	lockPath := rooted(opts.Root, "/run/lock/meshmux-install.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock permissions and retry.")
	}
	if err := ensureNoSymlinkAncestors(filepath.Dir(lockPath)); err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock path ownership and symlinks.")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fail("preflight", "INSTALL_LOCK_UNAVAILABLE", "Check /run/lock permissions and retry.")
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail("preflight", "INSTALL_BUSY", "Another MeshMux installation is running; wait for it to finish.")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	state, hasState, err := ReadState(opts.Root)
	if err != nil {
		return fail("preflight", "INSTALL_STATE_INVALID", "Inspect the recorded installer state; do not delete application data or Headscale keys.")
	}
	if repair && !hasState {
		return fail("preflight", "REPAIR_STATE_MISSING", "Repair requires a state record created by MeshMux.")
	}
	if hasState && !SameConfig(state.Config, c) {
		return fail("preflight", "CONFIG_CONFLICT", "Repair only supports the recorded domains and proxy trust mode; domain migration is not part of this operation.")
	}
	if hasState && state.Status == "installed" && !repair {
		if err := opts.Verify(ctx, c, opts.Runner, opts.TLSProbe); err != nil {
			return fail("verify", "INSTALL_NEEDS_REPAIR", "The recorded installation is unhealthy. Review service logs, then run install hub --repair with the same configuration.")
		}
		result.Stage, result.Status = "verify", "already_installed"
		result.Recovery = "No files or data were changed. Use --repair only when an explicit repair is required."
		result.Artifacts = componentsFor(opts.Artifacts)
		return result, nil
	}
	if hasState && state.Status != "installed" && !repair {
		return fail("preflight", "INSTALL_PARTIAL_REPAIR_REQUIRED", "A previous operation is incomplete. Review its journal and run --repair with the same domains.")
	}
	if hasState && state.Status != "installed" && state.Status != "partial" && state.Status != "installing" {
		return fail("preflight", "INSTALL_STATE_INVALID", "Inspect installer state before retrying.")
	}

	checks, sshPorts := opts.Preflight(ctx, c, hasState)
	result.Checks = checks
	for _, check := range checks {
		if check.Status == "fail" {
			recovery := check.Recovery
			if recovery == "" {
				recovery = "Resolve the failed preflight check and retry."
			}
			result.Stage, result.Status, result.ErrorCode, result.Recovery = "preflight", "preflight_blocked", check.Code, recovery
			return result, &InstallError{Stage: "preflight", Code: check.Code, Recovery: recovery}
		}
	}
	if len(sshPorts) == 0 {
		return fail("preflight", "SSH_LISTENER_UNKNOWN", "Determine the effective SSH listening port before installing Fail2ban.")
	}

	architecture := architectureForRuntime()
	if architecture == "" {
		return fail("preflight", "ARCH_UNSUPPORTED", "Use Debian 13 on amd64 or arm64.")
	}
	artifacts := opts.Artifacts
	if len(artifacts) == 0 {
		artifacts = PinnedArtifacts(architecture)
	}
	if len(artifacts) != 2 || findArtifact(artifacts, "caddy").Component == "" || findArtifact(artifacts, "headscale").Component == "" {
		return fail("stage", "ARTIFACT_MANIFEST_INVALID", "Use the pinned Caddy and Headscale manifest for a supported architecture.")
	}
	targetFiles, err := candidateFiles(c, sshPorts, opts.InternalTLSForTest)
	if err != nil {
		return fail("stage", "CONFIG_INVALID", "Review the domains and detected SSH listener ports.")
	}
	targets := managedTargets(targetFiles)
	if err := checkTargetOwnership(opts.Root, targets, state, hasState); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "MANAGED_PATH_CONFLICT", "A target path already exists without an ownership record; inspect it manually.")
	}
	if err := checkDataOwnership(opts.Root, hasState); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "DATA_STATE_CONFLICT", "Inspect existing MeshMux or Headscale data; do not adopt or delete it automatically.")
	}
	if err := checkSystemUsers(ctx, opts.Runner, hasState); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail("preflight", ie.Code, ie.Recovery)
		}
		return fail("preflight", "ACCOUNT_CONFLICT", "A MeshMux service account already exists without a matching installer state record.")
	}

	now := time.Now().UTC()
	if err := ensureDirectory(rooted(opts.Root, filepath.Dir(installerStatePath)), 0700); err != nil {
		return fail("stage", "INSTALL_STATE_UNAVAILABLE", "Create a root-owned private installer state directory and retry.")
	}
	operationDir := rooted(opts.Root, "/var/lib/meshmux-installer/operations/"+operationID)
	if err := ensureDirectory(operationDir, 0700); err != nil {
		return fail("stage", "OPERATION_LOG_FAILED", "Check private installer state directory permissions.")
	}
	journalPath := filepath.Join(operationDir, "events.jsonl")
	record := func(stage, status, code string) error {
		return appendOperationEvent(journalPath, operationEvent{OperationID: operationID, Stage: stage, Status: status, ErrorCode: code, Time: time.Now().UTC()})
	}
	if err := record("preflight", "pass", ""); err != nil {
		return fail("preflight", "OPERATION_LOG_FAILED", "Check installer state directory permissions.")
	}

	previous := state
	if !hasState {
		state = InstallState{Schema: 1, CreatedAt: now, ManagedFiles: map[string]string{}, Artifacts: map[string]string{}}
	}
	if state.ManagedFiles == nil {
		state.ManagedFiles = map[string]string{}
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]string{}
	}
	state.OperationID, state.LastOperation = operationID, operationID
	state.Status, state.Stage = "installing", "stage"
	state.Config, state.Architecture, state.UpdatedAt = c, architecture, now
	state.SSHPorts, state.ErrorCode, state.Recovery = sshPorts, "", ""
	if err := writeState(opts.Root, state); err != nil {
		return fail("stage", "INSTALL_STATE_WRITE_FAILED", "Check disk space and permissions under /var/lib/meshmux-installer.")
	}
	if err := record("stage", "started", ""); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions.")
	}

	stageDir := rooted(opts.Root, "/var/cache/meshmux-installer/"+operationID)
	if err := ensureDirectory(stageDir, 0700); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "STAGE_UNAVAILABLE", "Check /var/cache space and permissions.")
	}
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := ensureDirectory(artifactsDir, 0700); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "STAGE_UNAVAILABLE", "Check /var/cache space and permissions.")
	}

	stagedArtifacts := map[string]string{}
	for _, a := range artifacts {
		path, downloadErr := opts.DownloadArtifact(ctx, a, artifactsDir)
		if downloadErr != nil {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", artifactErrorCode(downloadErr), "Check outbound HTTPS to the pinned official GitHub release and retry; unverified files are never applied.")
		}
		if err := VerifyFile(path, a.SHA256); err != nil {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "ARTIFACT_CHECKSUM_MISMATCH", "Delete the staged download and retry; do not bypass SHA-256 verification.")
		}
		if a.Component == "headscale" {
			if err := os.Chmod(path, 0755); err != nil {
				return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "ARTIFACT_STAGE_FAILED", "Check permission on the verified Headscale binary.")
			}
		}
		stagedArtifacts[a.Component] = path
		state.Artifacts[a.Component] = a.SHA256
	}
	caddyArchive, okCaddy := stagedArtifacts["caddy"]
	headscalePath, okHeadscale := stagedArtifacts["headscale"]
	if !okCaddy || !okHeadscale {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "ARTIFACT_MANIFEST_INVALID", "The manifest must contain the pinned Caddy and Headscale binaries.")
	}
	caddyArtifact := findArtifact(artifacts, "caddy")
	headscaleArtifact := findArtifact(artifacts, "headscale")
	caddyPath := filepath.Join(stageDir, "meshmux-caddy")
	if caddyArtifact.Format == "tar.gz" {
		if err := extractCaddyBinary(caddyArchive, caddyPath); err != nil {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "ARTIFACT_FORMAT_INVALID", "Re-download the official Caddy archive; do not extract unverified archives.")
		}
	} else {
		caddyPath = caddyArchive
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, caddyPath, caddyArtifact.Version); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "CADDY_VERSION_INVALID", "Use the exact pinned Caddy release for this architecture.")
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, headscalePath, headscaleArtifact.Version); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "HEADSCALE_VERSION_INVALID", "Use the exact pinned Headscale release for this architecture.")
	}
	runtimeStage := filepath.Join(stageDir, "meshmuxd")
	executable := opts.Executable
	if executable == "" {
		executable = "/proc/self/exe"
	}
	runtimeHash, err := copyExecutable(executable, runtimeStage)
	if err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "MESHMUX_BINARY_INVALID", "Run the installer from a regular, readable MeshMux executable and retry.")
	}

	configDir := filepath.Join(stageDir, "config")
	if err := ensureDirectory(configDir, 0700); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
	}
	stagedConfigs := map[string]string{}
	keys := make([]string, 0, len(targetFiles))
	for path := range targetFiles {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	for _, target := range keys {
		path := filepath.Join(configDir, filepath.Base(target))
		if err := os.WriteFile(path, []byte(targetFiles[target]), 0600); err != nil {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "STAGE_UNAVAILABLE", "Check temporary disk space and permissions.")
		}
		stagedConfigs[target] = path
	}
	if _, err := opts.Runner.Run(ctx, caddyPath, "validate", "--config", stagedConfigs["/etc/meshmux/Caddyfile"], "--adapter", "caddyfile"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "CADDY_CONFIG_INVALID", "Review the generated Caddy configuration and domain values.")
	}
	if _, err := opts.Runner.Run(ctx, headscalePath, "--config", stagedConfigs["/etc/meshmux/headscale.yaml"], "configtest"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "HEADSCALE_CONFIG_INVALID", "Review the generated Headscale configuration for version 0.29.5.")
	}
	if err := record("stage", "validated", ""); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "stage", "OPERATION_LOG_FAILED", "Check installer state directory permissions.")
	}

	if _, err := opts.Runner.Run(ctx, "apt-get", "update"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "PACKAGE_INDEX_FAILED", "Check Debian repository connectivity; no third-party repository was added.")
	}
	if _, err := opts.Runner.Run(ctx, "apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "fail2ban", "nftables"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "PACKAGE_INSTALL_FAILED", "Review Debian apt status and retry; do not remove existing packages or rules.")
	}
	if err := ensureSystemUsers(ctx, opts.Runner, opts.Root, hasState); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", ie.Code, ie.Recovery)
		}
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "ACCOUNT_CREATE_FAILED", "Inspect the three dedicated service accounts before retrying.")
	}
	if err := ensureDataDirectories(ctx, opts); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "DATA_DIRECTORY_FAILED", "Check MeshMux data directory ownership; never delete SQLite or Headscale key files.")
	}

	backupDir := filepath.Join(operationDir, "backup")
	if err := ensureDirectory(backupDir, 0700); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "BACKUP_FAILED", "Check installer state disk space before applying files.")
	}
	snapshots, err := snapshotTargets(opts.Root, targets, state, hasState, backupDir)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", ie.Code, ie.Recovery)
		}
		return failAndRollback(result, state, previous, hasState, opts, nil, false, record, "apply", "BACKUP_FAILED", "No managed files were replaced; inspect the operation journal.")
	}

	applyFiles := map[string]string{
		runtimeBinaryPath:   runtimeStage,
		caddyBinaryPath:     caddyPath,
		headscaleBinaryPath: headscalePath,
	}
	for _, target := range keys {
		applyFiles[target] = stagedConfigs[target]
	}
	applyKeys := make([]string, 0, len(applyFiles))
	for target := range applyFiles {
		applyKeys = append(applyKeys, target)
	}
	sort.Strings(applyKeys)
	for _, target := range applyKeys {
		mode, owner := filePolicy(target)
		if err := copyAtomic(applyFiles[target], rooted(opts.Root, target), mode); err != nil {
			return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "FILE_APPLY_FAILED", "The installer is rolling back MeshMux-managed files; inspect the operation journal if rollback is incomplete.")
		}
		if opts.Root == "/" && owner != "" {
			if _, err := opts.Runner.Run(ctx, "chown", owner, target); err != nil {
				return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "FILE_OWNERSHIP_FAILED", "The installer is restoring managed files; check service account and group ownership.")
			}
		}
		digest, err := sha256File(rooted(opts.Root, target))
		if err != nil {
			return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "FILE_READBACK_FAILED", "The installer is restoring managed files; check the target filesystem.")
		}
		state.ManagedFiles[target] = digest
		if target == runtimeBinaryPath {
			state.ManagedFiles[target] = runtimeHash
		}
		if err := writeState(opts.Root, state); err != nil {
			return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "INSTALL_STATE_WRITE_FAILED", "Do not remove state or data; inspect disk space and run --repair.")
		}
	}
	if err := record("apply", "files_written", ""); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "OPERATION_LOG_FAILED", "Inspect the operation journal and installer state.")
	}
	units := []string{
		rooted(opts.Root, "/etc/systemd/system/meshmux-web.service"),
		rooted(opts.Root, "/etc/systemd/system/meshmux-headscale.service"),
		rooted(opts.Root, "/etc/systemd/system/meshmux-caddy.service"),
	}
	if _, err := opts.Runner.Run(ctx, "systemd-analyze", append([]string{"verify"}, units...)...); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "SYSTEMD_UNIT_INVALID", "Review the generated unit files; no service is considered installed until validation succeeds.")
	}
	if _, err := opts.Runner.Run(ctx, "fail2ban-client", "-t"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "FAIL2BAN_CONFIG_INVALID", "Review the MeshMux SSH jail and preserve existing Fail2ban configuration.")
	}
	if err := record("apply", "validated", ""); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "OPERATION_LOG_FAILED", "Inspect the operation journal and installer state.")
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "apply", "SYSTEMD_RELOAD_FAILED", "Restore MeshMux-managed units and inspect systemd.")
	}
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service"} {
		if err := activateUnit(ctx, opts.Runner, unit, repair); err != nil {
			code := "WEB_START_FAILED"
			if strings.Contains(unit, "headscale") {
				code = "HEADSCALE_START_FAILED"
			}
			return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", code, "The installer is rolling back managed files; inspect journalctl for this unit and retry with --repair.")
		}
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "is-active", "--quiet", "fail2ban.service"); err != nil {
		if _, startErr := opts.Runner.Run(ctx, "systemctl", "enable", "--now", "fail2ban.service"); startErr != nil {
			return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "FAIL2BAN_START_FAILED", "Review Fail2ban logs and SSH jail configuration; do not alter sshd or flush nftables.")
		}
	} else if _, err := opts.Runner.Run(ctx, "fail2ban-client", "reload"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "FAIL2BAN_RELOAD_FAILED", "Review Fail2ban logs and preserve existing jails and nftables rules.")
	}
	if _, err := opts.Runner.Run(ctx, "fail2ban-client", "status", "meshmux-sshd"); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "SSH_FAIL2BAN_JAIL_UNAVAILABLE", "Verify the detected SSH ports and MeshMux-specific Fail2ban jail.")
	}
	if err := activateUnit(ctx, opts.Runner, "meshmux-caddy.service", repair); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "CADDY_START_FAILED", "Check TCP 80/443 ownership and Caddy logs; no third-party web server was replaced.")
	}
	if err := opts.Verify(ctx, c, opts.Runner, opts.TLSProbe); err != nil {
		code := "SERVICE_VERIFY_FAILED"
		var ie *InstallError
		if errors.As(err, &ie) {
			code = ie.Code
		}
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", code, "Check DNS A/AAAA, TCP 80/443, certificate issuance, Headscale socket/DB and Fail2ban status; rerun --repair after fixing the cause.")
	}

	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.UpdatedAt = time.Now().UTC()
	state.LastOperation = operationID
	if err := writeState(opts.Root, state); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "INSTALL_STATE_WRITE_FAILED", "Services were started but state readback failed; inspect the operation journal before retrying.")
	}
	if err := record("verify", "pass", ""); err != nil {
		return failAndRollback(result, state, previous, hasState, opts, snapshots, true, record, "verify", "OPERATION_LOG_FAILED", "Inspect the operation journal and installer state.")
	}
	_ = os.RemoveAll(backupDir)
	_ = os.RemoveAll(stageDir)
	result.Stage, result.Status, result.Checks = "verify", "installed", checks
	result.Artifacts = componentsFor(artifacts)
	return result, nil
}

func failAndRollback(result InstallResult, state, previous InstallState, hadPrevious bool, opts ApplyOptions, snapshots []fileSnapshot, haveSnapshots bool, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	rollbackOK := true
	if haveSnapshots {
		rollbackOK = rollbackManaged(context.Background(), opts, snapshots, hadPrevious && previous.Status == "installed")
	}
	if hadPrevious && previous.Status == "installed" && rollbackOK {
		previous.LastOperation = state.OperationID
		previous.ErrorCode = code
		previous.Recovery = recovery
		previous.UpdatedAt = time.Now().UTC()
		_ = writeState(opts.Root, previous)
		result.Status = "rolled_back"
	} else {
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		if haveSnapshots && rollbackOK {
			state.ManagedFiles = map[string]string{}
		}
		_ = writeState(opts.Root, state)
		result.Status = "partial"
	}
	if !rollbackOK {
		code = "ROLLBACK_FAILED"
		recovery = "Do not delete /var/lib/meshmux or Headscale state. Inspect the operation journal and restore only recorded MeshMux-managed files."
		result.Status = "partial"
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		_ = writeState(opts.Root, state)
	}
	result.Stage, result.ErrorCode, result.Recovery = stage, code, recovery
	_ = record(stage, "failed", code)
	return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
}

func rollbackManaged(ctx context.Context, opts ApplyOptions, snapshots []fileSnapshot, restoreRunning bool) bool {
	ok := true
	for _, unit := range []string{"meshmux-caddy.service", "meshmux-web.service", "meshmux-headscale.service"} {
		_, _ = opts.Runner.Run(ctx, "systemctl", "stop", unit)
	}
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		if !s.Exists {
			if err := os.Remove(s.Target); err != nil && !os.IsNotExist(err) {
				ok = false
			}
			continue
		}
		if err := copyAtomic(s.Backup, s.Target, s.Mode.Perm()); err != nil {
			ok = false
			continue
		}
		if opts.Root == "/" {
			if err := os.Chown(s.Target, s.UID, s.GID); err != nil {
				ok = false
			}
		}
	}
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		ok = false
	}
	if restoreRunning && ok {
		for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service"} {
			if _, err := opts.Runner.Run(ctx, "systemctl", "start", unit); err != nil {
				ok = false
			}
		}
		_, _ = opts.Runner.Run(ctx, "fail2ban-client", "reload")
	} else if !restoreRunning {
		for _, unit := range []string{"meshmux-caddy.service", "meshmux-web.service", "meshmux-headscale.service"} {
			_, _ = opts.Runner.Run(ctx, "systemctl", "disable", unit)
		}
		_, _ = opts.Runner.Run(ctx, "fail2ban-client", "reload")
	}
	return ok
}

func verifyServices(ctx context.Context, c Config, runner CommandRunner, tlsProbe func(context.Context, string) error) error {
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service", "fail2ban.service"} {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
			code := "SERVICE_INACTIVE"
			if strings.Contains(unit, "headscale") {
				code = "HEADSCALE_START_FAILED"
			} else if strings.Contains(unit, "caddy") {
				code = "CADDY_START_FAILED"
			} else if strings.Contains(unit, "web") {
				code = "WEB_START_FAILED"
			} else if strings.Contains(unit, "fail2ban") {
				code = "FAIL2BAN_START_FAILED"
			}
			return &InstallError{Stage: "verify", Code: code, Recovery: "Inspect systemctl status and journalctl for the named service."}
		}
	}
	if err := waitForWebHealth(ctx, c.ManagementDomain); err != nil {
		return &InstallError{Stage: "verify", Code: "WEB_HEALTH_FAILED", Recovery: "Check meshmux-web.service, loopback port 9080, and the private SQLite directory."}
	}
	if _, err := runner.Run(ctx, headscaleBinaryPath, "--config", "/etc/meshmux/headscale.yaml", "nodes", "list"); err != nil {
		return &InstallError{Stage: "verify", Code: "HEADSCALE_HEALTH_FAILED", Recovery: "Check the Headscale Unix socket, SQLite database, and journalctl -u meshmux-headscale.service."}
	}
	listeners, err := runner.Run(ctx, "ss", "-H", "-lntup")
	if err != nil || !hasListenerPort(string(listeners), HeadscalePort) || !hasListenerPort(string(listeners), STUNPort) {
		return &InstallError{Stage: "verify", Code: "HEADSCALE_LISTENER_FAILED", Recovery: "Verify TCP 8080 and UDP 3478 are bound by the embedded Headscale service."}
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "status", "meshmux-sshd"); err != nil {
		return &InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Verify the actual SSH listener port and MeshMux SSH jail."}
	}
	if err := tlsProbe(ctx, c.ManagementDomain); err != nil {
		return &InstallError{Stage: "verify", Code: "TLS_ISSUANCE_FAILED", Recovery: "Check public DNS A/AAAA, inbound TCP 80/443, ACME rate limits, and the provider firewall; the installer does not change cloud security groups."}
	}
	return nil
}

func waitForWebHealth(ctx context.Context, domain string) error {
	deadline := time.Now().Add(30 * time.Second)
	client := &http.Client{Timeout: 3 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9080/healthz", nil)
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("WEB_HEALTH_FAILED")
}

func waitForHTTPS(ctx context.Context, domain string) error {
	deadline := time.Now().Add(180 * time.Second)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:443")
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/login", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("TLS_ISSUANCE_FAILED")
}

func hasListenerPort(output string, port int) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		pos := strings.LastIndex(addr, ":")
		if pos < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(addr[pos+1:], "]"))
		if err == nil && n == port {
			return true
		}
	}
	return false
}

func activateUnit(ctx context.Context, runner CommandRunner, unit string, repair bool) error {
	if repair {
		_, err := runner.Run(ctx, "systemctl", "restart", unit)
		return err
	}
	_, err := runner.Run(ctx, "systemctl", "enable", "--now", unit)
	return err
}

func architectureForRuntime() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func findArtifact(artifacts []Artifact, name string) Artifact {
	for _, a := range artifacts {
		if a.Component == name {
			return a
		}
	}
	return Artifact{}
}

func componentsFor(artifacts []Artifact) []Component {
	out := []Component{{Name: "MeshMux runtime", Version: "same executable as installer", Distribution: "self-copy SHA-256 verified"}}
	for _, a := range artifacts {
		out = append(out, Component{Name: a.Component, Version: a.Version, Distribution: "pinned official GitHub asset; SHA-256 verified"})
	}
	out = append(out,
		Component{Name: "Fail2ban", Version: "Debian 13 package", Distribution: "official Debian repository"},
		Component{Name: "nftables", Version: "Debian 13 package", Distribution: "official Debian repository"},
	)
	return out
}

func artifactErrorCode(err error) string {
	switch {
	case strings.Contains(err.Error(), "CHECKSUM"):
		return "ARTIFACT_CHECKSUM_MISMATCH"
	case strings.Contains(err.Error(), "UNTRUSTED"), strings.Contains(err.Error(), "MANIFEST"):
		return "ARTIFACT_MANIFEST_INVALID"
	default:
		return "ARTIFACT_DOWNLOAD_FAILED"
	}
}

func verifyBinaryVersion(ctx context.Context, runner CommandRunner, path, version string) error {
	output, err := runner.Run(ctx, path, "version")
	if err != nil || !strings.Contains(string(output), version) {
		return errors.New("BINARY_VERSION_INVALID")
	}
	return nil
}

func extractCaddyBinary(archivePath, target string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("CADDY_BINARY_MISSING")
		}
		if err != nil {
			return err
		}
		if header.Name != "caddy" {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size < 1 || header.Size > maxInstallerFile {
			return errors.New("CADDY_ARCHIVE_INVALID")
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, maxInstallerFile+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != header.Size || n > maxInstallerFile {
			_ = os.Remove(target)
			return errors.New("CADDY_ARCHIVE_INVALID")
		}
		return os.Chmod(target, 0755)
	}
}

func copyExecutable(source, target string) (string, error) {
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxInstallerFile {
		return "", errors.New("MESHMUX_BINARY_INVALID")
	}
	if err := copyAtomicFromReader(f, target, 0755); err != nil {
		return "", err
	}
	return sha256File(target)
}

func copyAtomic(source, target string, mode os.FileMode) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SOURCE_NOT_REGULAR")
	}
	return copyAtomicFromReader(f, target, mode)
}

func copyAtomicFromReader(source io.Reader, target string, mode os.FileMode) error {
	if err := ensureNoSymlinkAncestors(filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("TARGET_NOT_REGULAR")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".meshmux-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	n, copyErr := io.Copy(tmp, io.LimitReader(source, maxInstallerFile+1))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n > maxInstallerFile {
		return errors.New("FILE_WRITE_FAILED")
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(target)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func writeState(root string, state InstallState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeBytesAtomic(rooted(root, installerStatePath), append(data, '\n'), 0600)
}

func writeBytesAtomic(path string, data []byte, mode os.FileMode) error {
	if err := ensureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("TARGET_NOT_REGULAR")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".meshmux-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func appendOperationEvent(path string, event operationEvent) error {
	if err := ensureDirectory(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func ensureDirectory(path string, mode os.FileMode) error {
	if err := ensureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("DIRECTORY_UNSAFE")
	}
	return os.Chmod(path, mode.Perm())
}

func ensureNoSymlinkAncestors(path string) error {
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("SYMLINK_PATH_REJECTED")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func rooted(root, absolute string) string {
	if root == "" || root == "/" {
		return absolute
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)))
}

func managedTargets(configs map[string]string) []string {
	out := []string{runtimeBinaryPath, caddyBinaryPath, headscaleBinaryPath}
	for path := range configs {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func checkTargetOwnership(root string, targets []string, state InstallState, hasState bool) error {
	for _, target := range targets {
		info, err := os.Lstat(rooted(root, target))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the existing target path; MeshMux refuses symlinks and non-regular managed files."}
		}
		if !hasState {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_CONFLICT", Recovery: "A target file already exists without MeshMux ownership state; inspect it manually instead of overwriting it."}
		}
		if _, ok := state.ManagedFiles[target]; !ok {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_CONFLICT", Recovery: "This file is not recorded as MeshMux-managed; inspect it manually instead of overwriting it."}
		}
	}
	return nil
}

func checkDataOwnership(root string, hasState bool) error {
	if hasState {
		return nil
	}
	for _, dir := range []string{"/var/lib/meshmux", "/var/lib/meshmux-headscale", "/var/lib/meshmux-caddy"} {
		path := rooted(root, dir)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &InstallError{Stage: "preflight", Code: "DATA_PATH_UNSAFE", Recovery: "Inspect the existing data path; MeshMux will not follow symlinks or replace non-directories."}
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) > 0 {
			return &InstallError{Stage: "preflight", Code: "DATA_STATE_CONFLICT", Recovery: "Data already exists without an installer state record; back it up and inspect it manually. MeshMux will not adopt or delete it."}
		}
	}
	return nil
}

func checkSystemUsers(ctx context.Context, runner CommandRunner, hasState bool) error {
	for _, user := range []string{"meshmux", "meshmux-headscale", "meshmux-caddy"} {
		output, err := runner.Run(ctx, "getent", "passwd", user)
		if err == nil && len(strings.TrimSpace(string(output))) > 0 && !hasState {
			return &InstallError{Stage: "preflight", Code: "ACCOUNT_CONFLICT", Recovery: "A service account already exists without MeshMux ownership state; do not adopt it automatically."}
		}
	}
	return nil
}

func ensureSystemUsers(ctx context.Context, runner CommandRunner, root string, hasState bool) error {
	for _, item := range []struct{ name, home string }{
		{"meshmux", "/var/lib/meshmux"},
		{"meshmux-headscale", "/var/lib/meshmux-headscale"},
		{"meshmux-caddy", "/var/lib/meshmux-caddy"},
	} {
		output, err := runner.Run(ctx, "getent", "passwd", item.name)
		if err == nil && len(strings.TrimSpace(string(output))) > 0 {
			if !hasState {
				return &InstallError{Stage: "apply", Code: "ACCOUNT_CONFLICT", Recovery: "A service account exists without MeshMux ownership state; inspect it manually."}
			}
			continue
		}
		_, err = runner.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", item.home, "--create-home", "--shell", "/usr/sbin/nologin", item.name)
		if err != nil {
			return &InstallError{Stage: "apply", Code: "ACCOUNT_CREATE_FAILED", Recovery: "Check useradd availability and whether a conflicting account exists."}
		}
	}
	return nil
}

func ensureDataDirectories(ctx context.Context, opts ApplyOptions) error {
	for _, item := range []struct{ path, owner string }{
		{"/var/lib/meshmux", "meshmux:meshmux"},
		{"/var/lib/meshmux-headscale", "meshmux-headscale:meshmux-headscale"},
		{"/var/lib/meshmux-caddy", "meshmux-caddy:meshmux-caddy"},
	} {
		path := rooted(opts.Root, item.path)
		if err := ensureDirectory(path, 0700); err != nil {
			return err
		}
		if opts.Root == "/" {
			if _, err := opts.Runner.Run(ctx, "chown", item.owner, item.path); err != nil {
				return err
			}
		}
	}
	return nil
}

func snapshotTargets(root string, targets []string, state InstallState, hasState bool, backupDir string) ([]fileSnapshot, error) {
	var snapshots []fileSnapshot
	for _, target := range targets {
		path := rooted(root, target)
		info, err := os.Lstat(path)
		snapshot := fileSnapshot{Target: path, Backup: filepath.Join(backupDir, strings.TrimPrefix(strings.ReplaceAll(target, "/", "_"), "_"))}
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_UNSAFE", Recovery: "Stop and inspect the target path; symlinks and non-regular files are never replaced."}
		}
		if !hasState {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_CONFLICT", Recovery: "The target file is not recorded as MeshMux-managed."}
		}
		if _, ok := state.ManagedFiles[target]; !ok {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_CONFLICT", Recovery: "The target file is not recorded as MeshMux-managed."}
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return snapshots, errors.New("TARGET_OWNER_UNKNOWN")
		}
		if err := copyAtomic(path, snapshot.Backup, info.Mode().Perm()); err != nil {
			return snapshots, err
		}
		snapshot.Exists, snapshot.Mode, snapshot.UID, snapshot.GID = true, info.Mode(), int(stat.Uid), int(stat.Gid)
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func filePolicy(path string) (os.FileMode, string) {
	switch path {
	case "/etc/meshmux/Caddyfile":
		return 0640, "root:meshmux-caddy"
	case "/etc/meshmux/headscale.yaml":
		return 0640, "root:meshmux-headscale"
	case runtimeBinaryPath, caddyBinaryPath, headscaleBinaryPath:
		return 0755, "root:root"
	default:
		return 0644, "root:root"
	}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxInstallerFile {
		return "", errors.New("FILE_SIZE_INVALID")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
