// Package update validates a Web-approved target on the target node, fetches
// the pinned manifest and package, verifies its SHA-256, and hands the verified
// bytes to the new package's own install: the old binary never installs itself
// (pull-then-handoff, #11c-1).
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const DefaultWorkDir = "/var/lib/meshmux-agent/update"

// requiredSpace is the free space a handoff needs for the backup snapshot and
// the new package; it matches the installer's own preflight floor.
const requiredSpace = 1 << 30

// systemctlPath is the fixed systemd entry the handoff uses to restart the
// Agent. No caller or remote request can select another executable.
const systemctlPath = "/usr/bin/systemctl"

// Config is one approved update; the manifest body never travels through argv.
type Config struct {
	Target, ManifestSHA256, OperationID, WorkDir string
	FetchManifest                                func(context.Context) ([]byte, error)
	// CurrentVersion and Releases are the running build and the ordered
	// release history of the approved manifest. Task 6 supplies the history;
	// with none the executor can only honour the manifest's version binding.
	CurrentVersion string
	Releases       []string
	// NodeConfig, Space and Readback are the host seams of the handoff. The
	// defaults read the installed Agent configuration, stat / and hash the
	// installed executor.
	NodeConfig func() (node.Config, error)
	Space      func(path string, minimum uint64) error
	Readback   func() (string, error)
}

// Result reports what the handoff staged and observed. It never claims the
// target is installed before ReadbackDigest matched the verified package.
// A non-nil Result returned with an error is staged-only: VerifiedPath is set
// only after the digest matched.
type Result struct {
	VerifiedPath   string           `json:"verified_path"`
	Manifest       upgrade.Manifest `json:"manifest"`
	BackupPointer  string           `json:"backup_pointer,omitempty"`
	ReadbackDigest string           `json:"readback_digest,omitempty"`
}

// backupPointer is the rollback pointer of one release: it names the release
// being replaced before the new package runs. One file per target keeps every
// step of a multi-release catch-up independently addressable (11c-3 owns the
// restore semantics).
type backupPointer struct {
	OperationID    string `json:"operation_id"`
	FromVersion    string `json:"from_version"`
	Target         string `json:"target"`
	ManifestSHA256 string `json:"manifest_sha256"`
	PackageSHA256  string `json:"package_sha256"`
	VerifiedPath   string `json:"verified_path"`
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

var (
	// targetRE mirrors upgrade's unexported releaseVersion; keep the two in step.
	targetRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opIDRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Run validates the approved target, fetches the pinned manifest and package,
// then hands the verified bytes to the new package's install. The order is
// fixed: gates before the space check, the space check before the backup
// pointer, the pointer before any mutation, the new package before the Agent
// restart, and the readback last.
func Run(ctx context.Context, cfg Config, runner node.CommandRunner) (Result, error) {
	var m upgrade.Manifest
	switch {
	case !targetRE.MatchString(cfg.Target):
		return Result{}, fail("UPDATE_TARGET_INVALID", "target is not a SemVer release")
	case !digestRE.MatchString(cfg.ManifestSHA256):
		return Result{}, fail("UPDATE_DIGEST_INVALID", "manifest SHA-256 is not 64 lowercase hex")
	case cfg.OperationID == "":
		return Result{}, fail("OPERATION_REQUIRED", "an operation ID is required")
	case !opIDRE.MatchString(cfg.OperationID):
		return Result{}, fail("OPERATION_ID_INVALID", "operation ID is not 32 lowercase hex")
	case cfg.FetchManifest == nil:
		return Result{}, fail("MANIFEST_UNAVAILABLE", "no authenticated manifest channel")
	}
	if cfg.NodeConfig == nil {
		cfg.NodeConfig = installedNodeConfig
	}
	if cfg.Space == nil {
		cfg.Space = install.DiskAvailable
	}
	if cfg.Readback == nil {
		cfg.Readback = installedDigest
	}
	body, err := cfg.FetchManifest(ctx)
	if err != nil || len(body) == 0 {
		return Result{}, fail("MANIFEST_UNAVAILABLE", "the Hub manifest could not be fetched")
	}
	// The channel is a dual-arch set (U4). Parsing it before the digest only
	// selects the local projection; the approved per-arch SHA-256 still gates
	// every host action below, so no byte is trusted or executed before it.
	var set upgrade.ManifestSet
	if err := json.Unmarshal(body, &set); err != nil {
		return Result{}, fail("MANIFEST_INVALID", "the manifest set is not valid JSON")
	}
	if set.Schema != upgrade.SetSchema {
		return Result{}, fail("MANIFEST_SCHEMA_INVALID", "the Hub served an unknown manifest set schema")
	}
	// Select this Agent's own runtime.GOARCH entry. A missing table is refused
	// as MANIFEST_ARCH_INVALID; the Hub never supplies a caller-chosen arch.
	m, manifestBody, err := set.Projection(runtime.GOARCH)
	if err != nil {
		return Result{}, err
	}
	// The pin is exactly the selected per-arch manifest projection. The set
	// envelope cannot move the trust anchor, and another architecture's digest
	// never verifies this Agent's bytes.
	if hexDigest(manifestBody) != cfg.ManifestSHA256 {
		return Result{}, fail("UPDATE_DIGEST_MISMATCH", "the manifest does not match the approved SHA-256")
	}
	c, err := validateTarget(m, cfg.Target)
	if err != nil {
		return Result{}, err
	}
	if err := compatGate(m); err != nil {
		return Result{}, err
	}
	if err := adjacencyGate(cfg); err != nil {
		return Result{}, err
	}
	// The handoff reuses the recorded Agent configuration. Reading it is a
	// gate, not a mutation: a host without one is not a Node this executor may
	// upgrade (a Hub upgrades itself in 11d), so nothing is fetched or written.
	installed, err := cfg.NodeConfig()
	if err != nil {
		return Result{}, fail("AGENT_CONFIG_UNAVAILABLE", "the installed Agent configuration could not be read")
	}
	// The backup snapshot and the new package both land on the root
	// filesystem, exactly as the installer's own preflight checks it. Nothing
	// is fetched, written or executed when that space is not there.
	if err := cfg.Space("/", requiredSpace); err != nil {
		return Result{}, fail("UPDATE_NO_SPACE", "the handoff needs free space for the backup snapshot and the new package")
	}
	path, err := fetchPackage(ctx, cfg.WorkDir, cfg.Target, c)
	if err != nil {
		return Result{}, err
	}
	result := Result{VerifiedPath: path, Manifest: m}
	pointer, err := writeBackupPointer(cfg, c, path)
	if err != nil {
		return result, err
	}
	result.BackupPointer = pointer
	if err := handoff(ctx, installed, cfg.OperationID, path, runner); err != nil {
		return result, err
	}
	digest, err := cfg.Readback()
	if err != nil || digest != c.SHA256 {
		return result, fail("UPDATE_READBACK_MISMATCH", "the installed executor does not match the verified package digest")
	}
	result.ReadbackDigest = digest
	return result, nil
}

// compatGate refuses a target this host cannot adopt: the stored policy schema
// must be the one the manifest names (UPDATE_SCHEMA_INCOMPATIBLE), and every
// route policy revision must name a known layer above zero. The target gate
// checks the manifest's own shape; this gate is the migration contract.
func compatGate(m upgrade.Manifest) error {
	if m.PolicySchema != upgrade.PolicySchema {
		return fail("UPDATE_SCHEMA_INCOMPATIBLE", "the target names another stored policy schema")
	}
	for layer, revision := range m.RoutePolicyRevisions {
		if (layer != "client" && layer != "server") || revision < 1 {
			return fail("MANIFEST_POLICY_REVISION_INVALID", "only client/server revisions above zero are valid")
		}
	}
	return nil
}

// adjacencyGate applies the one-release-at-a-time rule when the approved
// manifest carries the ordered history. Without a history there is nothing to
// compare against, so the manifest's own version binding is the only gate.
func adjacencyGate(cfg Config) error {
	if len(cfg.Releases) == 0 || cfg.CurrentVersion == "" {
		return nil
	}
	return upgrade.AdjacentRelease(cfg.Releases, cfg.CurrentVersion, cfg.Target)
}

// writeBackupPointer records the release being replaced before anything runs.
// The file is written atomically so a crash leaves either no pointer or the
// complete one, never a truncated rollback target.
func writeBackupPointer(cfg Config, c upgrade.Component, path string) (string, error) {
	pointer := backupPointer{OperationID: cfg.OperationID, FromVersion: cfg.CurrentVersion,
		Target: cfg.Target, ManifestSHA256: cfg.ManifestSHA256, PackageSHA256: c.SHA256, VerifiedPath: path}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return "", fail("UPDATE_BACKUP_FAILED", "the rollback pointer could not be encoded")
	}
	final := filepath.Join(cfg.WorkDir, "backup-"+cfg.Target+".json")
	if os.WriteFile(final+".part", data, 0600) != nil {
		return "", fail("UPDATE_BACKUP_FAILED", "the rollback pointer could not be written")
	}
	if os.Rename(final+".part", final) != nil {
		_ = os.Remove(final + ".part")
		return "", fail("UPDATE_BACKUP_FAILED", "the rollback pointer could not be published")
	}
	return final, nil
}

// handoff execs the verified package's own install with a fixed argv and then
// restarts the Agent. The install entry is the private one only: --repair
// reuses the recorded identity and --non-interactive refuses every prompt, so
// no stdin is ever read on a Web-driven upgrade.
func handoff(ctx context.Context, installed node.Config, operationID, path string, runner node.CommandRunner) error {
	args := []string{"install", string(installed.Role), "--hub", installed.HubURL,
		"--node", installed.NodeID, "--vless-port", strconv.Itoa(installed.VLESSPort),
		"--ssh-port", strconv.Itoa(installed.SSHPort), "--operation-id", operationID,
		"--yes", "--repair", "--non-interactive"}
	if _, err := runner.Run(ctx, path, args...); err != nil {
		return fail("UPDATE_INSTALL_FAILED", "the new package's install refused the handoff; the previous release is preserved")
	}
	if _, err := runner.Run(ctx, systemctlPath, "restart", node.AgentUnit); err != nil {
		return fail("UPDATE_RESTART_FAILED", "the verified package is installed but the Agent did not restart")
	}
	return nil
}

// installedNodeConfig reads the recorded Agent configuration the handoff
// reuses, through the same 0600-and-owner rule as HubManifest.
func installedNodeConfig() (node.Config, error) {
	var cfg node.Config
	if err := readAgentFile(node.AgentConfigPath, &cfg, "AGENT_CONFIG_UNAVAILABLE"); err != nil {
		return node.Config{}, err
	}
	if err := cfg.ValidateInstalled(); err != nil {
		return node.Config{}, err
	}
	return cfg, nil
}

// installedDigest hashes the installed executor, the readback the handoff
// compares with the verified package.
func installedDigest() (string, error) {
	data, err := os.ReadFile(node.AgentBinaryPath)
	if err != nil || len(data) == 0 {
		return "", fail("UPDATE_READBACK_UNAVAILABLE", "the installed executor could not be read")
	}
	return hexDigest(data), nil
}

// validateTarget is the gate for a *target* release, which is by definition not
// the table of the running build. It therefore checks what an upgrade must
// honour rather than table equality: the target's own schema, its
// architecture, and a pinned meshmuxd component whose source class matches its
// Dev flag. The stored policy schema is the separate compat gate, because that
// is the migration contract rather than a manifest-shape check.
// upgrade.Manifest.Validate stays the running-build self-check and is not
// applied here.
func validateTarget(m upgrade.Manifest, target string) (upgrade.Component, error) {
	if m.Schema != upgrade.Schema {
		return upgrade.Component{}, fail("MANIFEST_SCHEMA_INVALID", "the target names another manifest schema")
	}
	if m.Version != target || !targetRE.MatchString(m.Version) {
		return upgrade.Component{}, fail("UPDATE_TARGET_INVALID", "the manifest does not describe the approved target")
	}
	if m.Architecture != runtime.GOARCH {
		return upgrade.Component{}, fail("MANIFEST_ARCH_INVALID", "the manifest is for another architecture")
	}
	for _, c := range m.Components {
		if c.Name == "meshmuxd" && c.Architecture == runtime.GOARCH && digestRE.MatchString(c.SHA256) && trustedSource(c) {
			return c, nil
		}
	}
	return upgrade.Component{}, fail("MANIFEST_COMPONENT_INVALID", "the manifest has no pinned meshmuxd package")
}

// trustedSource restores the source-class rule the running-build table check
// used to provide: a release comes from a GitHub release URL, a dev build from
// a local or intranet source, and both must be a dev- build exactly when Dev is
// set. A digest alone never makes an arbitrary URL executable.
func trustedSource(c upgrade.Component) bool {
	if c.Dev {
		return strings.HasPrefix(c.Version, "dev-") &&
			(strings.HasPrefix(c.Source, "file://") || strings.HasPrefix(c.Source, "https://"))
	}
	return strings.HasPrefix(c.Source, "https://github.com/")
}

func fetchPackage(ctx context.Context, dir, target string, c upgrade.Component) (string, error) {
	data, err := readSource(ctx, c.Source)
	if err != nil {
		return "", err
	}
	if hexDigest(data) != c.SHA256 {
		return "", fail("UPDATE_DIGEST_MISMATCH", "the package does not match the manifest SHA-256")
	}
	if os.MkdirAll(dir, 0700) != nil {
		return "", fail("UPDATE_STAGE_FAILED", "the private staging directory could not be created")
	}
	final := filepath.Join(dir, "meshmuxd-"+target+"-"+c.Architecture)
	if os.WriteFile(final+".part", data, 0700) != nil {
		return "", fail("UPDATE_STAGE_FAILED", "the verified package could not be written")
	}
	if os.Rename(final+".part", final) != nil {
		_ = os.Remove(final + ".part")
		return "", fail("UPDATE_STAGE_FAILED", "the verified package could not be published")
	}
	return final, nil
}

// readSource accepts only the two source classes a manifest may declare: a
// pinned GitHub release over https, or a dev file:// build. The caller verifies
// the digest before any byte can be executed.
func readSource(ctx context.Context, source string) ([]byte, error) {
	if path, ok := strings.CutPrefix(source, "file://"); ok {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 || len(data) > 128<<20 {
			return nil, fail("UPDATE_DOWNLOAD_FAILED", "the manifest source is unavailable")
		}
		return data, nil
	}
	if !strings.HasPrefix(source, "https://") {
		return nil, fail("UPDATE_SOURCE_INVALID", "only an https or dev file source is allowed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, fail("UPDATE_SOURCE_INVALID", "the manifest source is not a valid URL")
	}
	res, err := downloadClient.Do(req)
	if err != nil {
		return nil, fail("UPDATE_DOWNLOAD_FAILED", "the package could not be downloaded")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fail("UPDATE_DOWNLOAD_FAILED", "the package host refused the download")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 128<<20+1))
	if err != nil || len(data) == 0 || len(data) > 128<<20 {
		return nil, fail("UPDATE_DOWNLOAD_FAILED", "the package download was incomplete")
	}
	return data, nil
}

var downloadClient = &http.Client{Timeout: 90 * time.Second}

func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HubManifest reads the two root-owned Agent files and fetches the manifest
// over the authenticated channel; no manifest body ever comes from argv. Codes
// name the failing file: AGENT_CONFIG_UNAVAILABLE for agent.json,
// AGENT_IDENTITY_UNAVAILABLE for identity.json, and the validation codes below.
func HubManifest(ctx context.Context) ([]byte, error) {
	var cfg node.Config
	var identity node.Identity
	if err := readAgentFile(node.AgentConfigPath, &cfg, "AGENT_CONFIG_UNAVAILABLE"); err != nil {
		return nil, err
	}
	if err := readAgentFile(node.IdentityPath, &identity, "AGENT_IDENTITY_UNAVAILABLE"); err != nil {
		return nil, err
	}
	if err := cfg.ValidateInstalled(); err != nil {
		return nil, errors.New("AGENT_CONFIG_INVALID")
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return nil, errors.New("AGENT_IDENTITY_MISMATCH")
	}
	client, err := node.NewClient(cfg, identity, nil)
	if err != nil {
		return nil, errors.New("AGENT_CONTROLLER_UNAVAILABLE")
	}
	body, err := client.Manifest(ctx)
	if err != nil || len(body) == 0 {
		return nil, errors.New("MANIFEST_UNAVAILABLE")
	}
	return body, nil
}

// readAgentFile opens one Agent-owned file: a regular 0600 file whose owner is
// this process's effective uid, the same rule node.readPrivateFile enforces.
func readAgentFile(path string, v any, code string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New(code)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New(code)
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, v) != nil {
		return errors.New(code)
	}
	return nil
}
