package update

// The new binary's hidden install command (#11c-2, spec §4.2/§4.7/§5-Q1/§6).
// The transient unit starts this package, so this process is already outside
// the Agent's cgroup: it re-checks its own bytes against the approved package
// digest, runs the fixed non-interactive install of the recorded Node, restarts
// the Agent through one fixed systemctl argv, and records the phase and exit
// code in <operation_id>.result.json for the Agent to reclaim. It never writes
// the handoff marker (spec §4.7) and never claims the target is applied: the
// applied anchor is the chain's readback (spec §4.1).

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/node"
)

const (
	// agentServiceUnit is the only unit this command restarts. The transient
	// unit is not a child of the Agent (spec §4.2), so the restart cannot kill
	// the install or this process; the command does not wait for the Agent to
	// come back and says nothing about its health.
	agentServiceUnit = node.AgentUnit
	// updatePackageMaxBytes is the same package bound as the fetch path.
	updatePackageMaxBytes = packageSpace
)

// RunInstall is the body of `__internal-update-install`. The order is fixed and
// fail-closed: validate the argv fields, re-check the running package's digest
// (--expected-sha256) and architecture, read the recorded Node role, write the
// `staged` phase, write `installing` and run the fixed install argv, then write
// `installed-awaiting-restart` and issue the fixed restart. A failing install
// never restarts the Agent. Every phase is on disk before the step it names
// runs, so a crash leaves the Agent a truthful, narrow record instead of a
// guess (spec §4.7).
func RunInstall(ctx context.Context, cfg Config, runner node.CommandRunner) (UpdateResult, error) {
	if err := validateInstallConfig(cfg, runner); err != nil {
		return UpdateResult{}, err
	}
	self, err := installExecutable(cfg)
	if err != nil {
		return UpdateResult{}, err
	}
	// The self-check is first: no ledger read, no result file and no subprocess
	// may happen when the bytes on disk are not the approved package.
	if err := verifyInstallDigest(self, cfg.PackageSHA256); err != nil {
		return UpdateResult{}, err
	}
	if err := verifyInstallArch(self); err != nil {
		return UpdateResult{}, err
	}
	role, err := installRole(cfg)
	if err != nil {
		return UpdateResult{}, err
	}
	argv := installArgv(self, role, cfg.OperationID)
	resultPath := ResultPath(cfg.WorkDir, cfg.OperationID)
	result := UpdateResult{OperationID: cfg.OperationID, Phase: ResultPhaseStaged, ExitCode: 0,
		Digest: cfg.PackageSHA256, Target: cfg.Target, Timestamp: time.Now().Unix()}
	if err := WriteResult(resultPath, result); err != nil {
		return result, err
	}
	result.Phase = ResultPhaseInstalling
	result.Timestamp = time.Now().Unix()
	if err := WriteResult(resultPath, result); err != nil {
		return result, err
	}
	if _, err := runner.Run(ctx, argv[0], argv[1:]...); err != nil {
		result.ExitCode = commandExitCode(err)
		result.Timestamp = time.Now().Unix()
		if writeErr := WriteResult(resultPath, result); writeErr != nil {
			return result, writeErr
		}
		return result, fail("UPDATE_INSTALL_FAILED", "the new package's install failed; the chain is not applied")
	}
	// Install succeeded. The phase is recorded before the restart so a crash
	// during the restart still leaves the install's outcome on disk.
	result.Phase = ResultPhaseInstalledAwaitingRestart
	result.ExitCode = 0
	result.Timestamp = time.Now().Unix()
	if err := WriteResult(resultPath, result); err != nil {
		return result, err
	}
	if _, err := runner.Run(ctx, systemctlPath, "restart", agentServiceUnit); err != nil {
		result.ExitCode = commandExitCode(err)
		result.Timestamp = time.Now().Unix()
		if writeErr := WriteResult(resultPath, result); writeErr != nil {
			return result, writeErr
		}
		return result, fail("UPDATE_RESTART_FAILED", "the install finished but the Agent restart was not accepted")
	}
	return result, nil
}

// validateInstallConfig checks the fixed argv fields without touching the host.
// It reuses the handoff's rules so both hidden commands accept exactly the same
// target, digests, operation ID and staging directory shapes.
func validateInstallConfig(cfg Config, runner node.CommandRunner) error {
	switch {
	case !targetRE.MatchString(cfg.Target):
		return fail(backup.CodeTargetInvalid, "target is not a SemVer release")
	case !digestRE.MatchString(cfg.ManifestSHA256):
		return fail(backup.CodeDigestInvalid, "manifest SHA-256 is not 64 lowercase hex")
	case !digestRE.MatchString(cfg.PackageSHA256):
		return fail(backup.CodeDigestInvalid, "package SHA-256 is not 64 lowercase hex")
	case cfg.OperationID == "":
		return fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(cfg.OperationID):
		return fail(backup.CodeOperationInvalid, "operation ID is not 32 lowercase hex")
	case runner == nil:
		return fail("UPDATE_INSTALL_UNAVAILABLE", "no command runner is configured")
	}
	_, err := transientWorkDir(cfg.WorkDir)
	return err
}

// installExecutable names the running new package. Production leaves
// Config.SelfExecutable empty and uses os.Executable; tests point it at fixture
// bytes.
func installExecutable(cfg Config) (string, error) {
	if cfg.SelfExecutable != "" {
		return cfg.SelfExecutable, nil
	}
	path, err := os.Executable()
	if err != nil {
		return "", fail("UPDATE_PACKAGE_UNAVAILABLE", "the running executable path is unavailable")
	}
	return path, nil
}

// verifyInstallDigest is the --expected-sha256 self-check: the file this
// process was started from must be exactly the package the manifest verified
// before it is allowed to install anything. The read is bounded by the same
// package size the fetch path accepts.
func verifyInstallDigest(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return fail("UPDATE_PACKAGE_UNAVAILABLE", "the running package could not be read")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > updatePackageMaxBytes {
		return fail("UPDATE_PACKAGE_INVALID", "the running package is not a regular package file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fail("UPDATE_PACKAGE_UNAVAILABLE", "the running package could not be read")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fail("UPDATE_DIGEST_MISMATCH", "the running package does not match the approved SHA-256")
	}
	return nil
}

// verifyInstallArch re-pins the wrong-architecture rule on the self path: the
// staged package must be an ELF executable for this build's GOARCH. The
// transient unit names an architecture-specific staged file; this check
// refuses foreign bytes even when a digest was approved for them.
func verifyInstallArch(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return fail("UPDATE_PACKAGE_INVALID", "the running package is not an ELF executable")
	}
	defer file.Close()
	want, ok := elfMachines[runtime.GOARCH]
	if !ok {
		return fail("MANIFEST_ARCH_INVALID", "this build's architecture has no pinned package")
	}
	if file.Machine != want {
		return fail("MANIFEST_ARCH_INVALID", "the running package targets another architecture")
	}
	return nil
}

// elfMachines maps the supported architecture matrix to the ELF machine the
// self-check must find. A new architecture needs an entry here and in the
// versions matrix; nothing else in this package enumerates architectures.
var elfMachines = map[string]elf.Machine{
	versions.ArchitectureAMD64: elf.EM_X86_64,
	versions.ArchitectureARM64: elf.EM_AARCH64,
}

// installArgv is the one fixed install command line: the recorded Node role
// (edge or out), the recorded-state repair flags and the chain's operation ID.
// No caller text, no paths and no pairing input travel through argv.
func installArgv(self string, role node.Role, operationID string) []string {
	return []string{
		self,
		"install", string(role),
		"--repair",
		"--non-interactive",
		"--from-recorded-state",
		"--operation-id", operationID,
	}
}

// installRole resolves the role from the recorded Node ledger, never from a
// caller. The production read is the same effective-ledger rule the Agent and
// installer use, so a co-located Hub installs its local Line ledger.
func installRole(cfg Config) (node.Role, error) {
	if cfg.RecordedRole != nil {
		return cfg.RecordedRole()
	}
	state, exists, err := install.ReadNodeState("/")
	if err != nil {
		return "", fail("INSTALL_STATE_INVALID", "the recorded Node ledger could not be read")
	}
	if !exists || state.Node == nil {
		return "", fail("REPAIR_STATE_MISSING", "the host records no Node installation")
	}
	role, err := node.ParseRole(string(state.Node.Role))
	if err != nil {
		return "", fail("INSTALL_STATE_INVALID", "the recorded Node role is not edge or out")
	}
	return role, nil
}

// commandExitCode maps one failed fixed argv to the coarse exit code recorded
// in the result file. A process that reports no exit status still fails
// closed as 1; 0 never means failure.
func commandExitCode(err error) int {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		if code := coded.ExitCode(); code > 0 && code <= 255 {
			return code
		}
	}
	return 1
}
