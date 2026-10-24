// Package update validates a Web-approved target on the target node, fetches
// the pinned manifest and package, verifies its SHA-256, and starts the new
// package's own install as a transient systemd unit outside the Agent's cgroup:
// the old binary never installs itself and never restarts the Agent
// (pull-then-handoff, #11c-1; transient handoff, #11c-2).
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
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const DefaultWorkDir = "/var/lib/meshmux-agent/update"

const (
	// packageSpace is the largest staged package the fetch path accepts
	// (updatePackageMaxBytes in install_cmd.go).
	packageSpace = 128 << 20
	// snapshotSpace bounds one installer snapshot: the Agent binary and the
	// co-located sing-box kernel (each bounded by packageSpace) plus unit
	// files, agent.json, the LKG pair and the ledger.
	snapshotSpace = 256 << 20
	// spaceHeadroom covers journals, result files, ledger writes and
	// filesystem slack while the copies below coexist.
	spaceHeadroom = 128 << 20
)

// requiredSpace is the free space a handoff needs on the root filesystem,
// re-derived for 11c-3 (spec §4.14). At the moment of an upgrade the following
// copies share that filesystem:
//
//  1. the staged new package               <= packageSpace  (128 MiB)
//  2. the installer's snapshot source      <= snapshotSpace (256 MiB)
//  3. the promoted rollback payload copy   <= snapshotSpace (256 MiB)
//  4. the N-1 retained generation          <= snapshotSpace (256 MiB)
//  5. journals, results, ledger and slack  <= spaceHeadroom (128 MiB)
//
// N-1 is backupKeepConfirmed. The total is 1024 MiB, so the floor is never
// weaker than the installer's own 1 GiB preflight (TestSpaceFloorDerivation).
const requiredSpace = packageSpace + 3*snapshotSpace + spaceHeadroom

// nodeDBSchema is the stored database schema of a Node host. A Node Agent owns
// no database; a Hub records its own schema when 11d backs up the Web DB.
const nodeDBSchema int64 = 0

// systemctlPath is the fixed systemd entry used for the unit liveness query and
// no other command. No caller or remote request can select another executable.
const systemctlPath = "/usr/bin/systemctl"

// Config is one approved update; the manifest body never travels through argv.
type Config struct {
	Target, ManifestSHA256, OperationID, WorkDir string
	// PackageSHA256 is the verified package digest the transient unit re-checks
	// before it installs. Run fills it from the component it verified; it is
	// never a caller-supplied trust anchor.
	PackageSHA256 string
	FetchManifest func(context.Context) ([]byte, error)
	// CurrentVersion and Releases are the running build and the ordered
	// release history of the approved manifest. Task 6 supplies the history;
	// with none the executor can only honour the manifest's version binding.
	CurrentVersion string
	Releases       []string
	// NodeConfig and Space are the host seams of the handoff. The defaults read
	// the installed Agent configuration and stat /.
	NodeConfig func() (node.Config, error)
	Space      func(path string, minimum uint64) error
	// BackupRoot and BackupSource are the rollback seams. An empty BackupRoot
	// is the sibling of WorkDir (the spec path for DefaultWorkDir); the source
	// is the installer-provided snapshot promoted into the 0700 store. 11c-3
	// Task 4 wires the retained installer snapshot here.
	BackupRoot   string
	BackupSource func() (string, error)

	// SelfExecutable and RecordedRole are the seams of the new binary's
	// install step (RunInstall). Production leaves both empty: the running
	// executable is os.Executable() and the role comes from the installed Node
	// ledger. Tests use them to point at fixture bytes and a fixture role
	// without touching the host.
	SelfExecutable string
	RecordedRole   func() (node.Role, error)

	// FromAgentSHA256 is the old package's digest for the transient revert
	// executor (RunRevert). It is filled from the rollback record, never from
	// a caller.
	FromAgentSHA256 string
	// Root is the installed-system root of the revert command. Production
	// leaves it empty ("/"); tests restore into a fixture tree.
	Root string
}

// Result reports what the handoff staged and observed. It never claims the
// target is installed: the install runs in a transient unit after this process
// returns, and applied is the approved chain's readback verdict (spec §4.1),
// not this receipt. VerifiedPath is set only after the digest matched.
type Result struct {
	VerifiedPath string           `json:"verified_path"`
	Manifest     upgrade.Manifest `json:"manifest"`
	// BackupPointer names the verified rollback record of this operation
	// (upgrade-backups/<op>/record.json). It is the only rollback pointer:
	// 11c-3 Task 4 removed the per-target backup-<target>.json file.
	BackupPointer string `json:"backup_pointer,omitempty"`
	// ReadbackDigest is the installed executor digest when a caller observed
	// it. The transient handoff leaves it empty: the unit installs later.
	ReadbackDigest string `json:"readback_digest,omitempty"`
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

var (
	// targetRE mirrors upgrade's unexported releaseVersion; keep the two in step.
	targetRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opIDRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Run validates the approved target, fetches the pinned manifest and package,
// then starts the verified package's install as one transient systemd unit. The
// order is fixed: gates before the space check, the space check before the
// rollback record, the record and its readback before the package fetch, and
// the unit last. Run returns once the unit is enqueued; it never waits for the
// install and never claims the target is applied — that verdict is the chain's
// readback (spec §4.1), which the restarted Agent observes.
func Run(ctx context.Context, cfg Config, runner node.CommandRunner) (Result, error) {
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
	// The transient unit's fixed argv is validated here, before anything is
	// fetched or written: an unclean staging directory or an unrepresentable
	// target is refused while the host is still untouched. The package digest
	// comes from the component verified above, never from the caller.
	cfg.PackageSHA256 = c.SHA256
	argv, err := BuildTransientArgv(cfg)
	if err != nil {
		return Result{}, err
	}
	// The handoff reuses the recorded Agent configuration. Reading it is a
	// gate, not a mutation: a host without one is not a Node this executor may
	// upgrade (a Hub upgrades itself in 11d), so nothing is fetched or written.
	// The transient unit re-reads the same file itself, so this process keeps
	// no copy of it. Its recorded Agent digest is the old-binary anchor of the
	// rollback record.
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
	// The rollback source is copied and re-verified before the package is
	// fetched. The order is pinned (spec §4.4/§6): snapshot copy -> payload
	// digest -> record -> requireVerifiedBackup -> fetch -> handoff. A refusal
	// changes nothing on the installed system; only the private 0700/0600
	// rollback store may gain a copy. Without an installer snapshot there is
	// nothing to copy, so the handoff is refused before a record can claim a
	// rollback source exists. On a Node the installed package is the Agent
	// binary, so both from_* anchors name the same recorded artifact (11d
	// supplies the Hub's separate installer-ledger digest).
	if cfg.BackupSource == nil {
		return Result{}, fail("UPDATE_BACKUP_MISSING", "the installer snapshot is unavailable")
	}
	snapshot, err := cfg.BackupSource()
	if err != nil {
		return Result{}, fail("UPDATE_BACKUP_MISSING", "the installer snapshot is unavailable")
	}
	// The installer's manifest claims the exact old package it recorded. That
	// digest is the from_* anchor the revert later trusts; agent.json is the
	// fallback for a snapshot written before the manifest existed.
	fromPackage, err := snapshotAnchor(snapshot, installed.AgentSHA256)
	if err != nil {
		return Result{}, err
	}
	recordPath, err := WriteBackupRecord(cfg.backupRoot(), BackupSpec{
		OperationID: cfg.OperationID, FromVersion: cfg.CurrentVersion, TargetVersion: cfg.Target,
		DBSchema: nodeDBSchema, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: cfg.ManifestSHA256, PackageSHA256: cfg.PackageSHA256,
		FromPackageSHA256: fromPackage, FromAgentSHA256: fromPackage,
		SnapshotDir: snapshot,
	})
	if err != nil {
		return Result{}, err
	}
	if err := requireVerifiedBackup(cfg.backupRoot(), cfg.OperationID, cfg.CurrentVersion, nodeDBSchema, upgrade.PolicySchema); err != nil {
		return Result{}, err
	}
	path, err := fetchPackage(ctx, cfg.WorkDir, cfg.Target, c)
	if err != nil {
		return Result{}, err
	}
	result := Result{VerifiedPath: path, Manifest: m, BackupPointer: recordPath}
	if err := handoff(ctx, argv, runner); err != nil {
		return result, err
	}
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

// snapshotAnchor resolves the old-package anchor from the installer snapshot.
// A manifest-bearing snapshot must name the Agent binary, and that digest must
// agree with agent.json when both are present: the rollback source has to be
// the release this host actually runs. A snapshot without a manifest is the
// pre-Task-4 shape and keeps the agent.json anchor.
func snapshotAnchor(snapshot, installedAgentSHA string) (string, error) {
	manifestPath := filepath.Join(snapshot, install.SnapshotManifestName)
	if _, err := os.Lstat(manifestPath); os.IsNotExist(err) {
		return installedAgentSHA, nil
	}
	manifest, err := install.ReadSnapshotManifest(snapshot)
	if err != nil {
		return "", fail("UPDATE_BACKUP_CORRUPT", "the installer rollback snapshot is not a valid manifest tree")
	}
	anchor := ""
	for _, entry := range manifest.Files {
		if entry.Target == node.AgentBinaryPath && entry.Exists {
			anchor = entry.SHA256
			break
		}
	}
	if anchor == "" {
		return "", fail("UPDATE_BACKUP_CORRUPT", "the installer rollback snapshot does not name the Agent binary")
	}
	if installedAgentSHA != "" && anchor != installedAgentSHA {
		return "", fail("UPDATE_BACKUP_MISMATCH", "the installer snapshot belongs to another installed release")
	}
	return anchor, nil
}

// requireVerifiedBackup is the 11c-3 handoff precondition (spec §4.4, §6). It
// extends the 11c-1 compatGate family to the rollback contract: the record this
// operation just wrote must name exactly the installed state, be staged, and
// hold files a revert can restore. The pinned order is copy -> verify ->
// handoff: VerifyBackupRecord re-reads the payload digest and its private modes
// from disk, so the package is never fetched and the unit is never started
// against an unverified rollback source. The function only reads; the copy it
// verifies is the sole 0700 store write.
func requireVerifiedBackup(root, operationID, fromVersion string, dbSchema int64, policySchema int) error {
	record, err := VerifyBackupRecord(root, operationID, fromVersion, dbSchema, policySchema)
	if err != nil {
		return err
	}
	// A record that exists but cannot back a revert is corrupt as a rollback
	// source. MISSING stays reserved for no record at all and MISMATCH for
	// another installed state, so no fourth refusal code is introduced.
	if record.State != BackupStateStaged {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record is not a staged handoff source")
	}
	if !record.RollbackComplete() {
		return fail("UPDATE_BACKUP_CORRUPT", "the rollback record holds nothing to restore")
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

// handoff starts the verified package's own install as one transient systemd
// unit and returns as soon as systemd has accepted the job. The unit — not this
// process — runs install, restarts the Agent and writes its result file, so the
// restart it performs cannot kill it (spec §4.2). This process never installs,
// never restarts and never claims the target is applied.
func handoff(ctx context.Context, argv []string, runner node.CommandRunner) error {
	if len(argv) == 0 || argv[0] != systemdRunPath {
		return fail("UPDATE_UNIT_START_FAILED", "the transient unit argv is not the fixed systemd-run command")
	}
	if _, err := runner.Run(ctx, argv[0], argv[1:]...); err != nil {
		return fail("UPDATE_UNIT_START_FAILED", "systemd did not accept the transient install unit; the previous release is untouched")
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
	// The unit's ExecStart and the staged file share one name helper, so the
	// bytes verified here are exactly the bytes the unit later executes.
	final, err := transientStagedPath(dir, target, c.Architecture)
	if err != nil {
		return "", err
	}
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
