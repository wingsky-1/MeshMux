// Package update validates a Web-approved target on the target node, fetches
// the pinned manifest and package, and leaves SHA-256 verified bytes on disk.
// It never installs: the handoff to the new package is Task 4 (#11c-1).
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

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

const DefaultWorkDir = "/var/lib/meshmux-agent/update"

// Config is one approved update; the manifest body never travels through argv.
type Config struct {
	Target, ManifestSHA256, OperationID, WorkDir string
	FetchManifest                                func(context.Context) ([]byte, error)
}

// Result reports what was staged; it never claims the target is installed.
// A non-nil Result returned with an error is staged-only: VerifiedPath is set
// only after the digest matched, and no handoff has run.
type Result struct {
	VerifiedPath string           `json:"verified_path"`
	Manifest     upgrade.Manifest `json:"manifest"`
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

var (
	// targetRE mirrors upgrade's unexported releaseVersion; keep the two in step.
	targetRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	opIDRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// errHandoff is the Task 4 seam: until then a verified package is staged
	// only, never applied, and no subprocess has run.
	errHandoff = fail("UPDATE_HANDOFF_NOT_IMPLEMENTED", "verified package staged; the handoff segment is not installed")
)

// Run validates the approved target, fetches the pinned manifest and package,
// then stops after the verified bytes are on disk. runner is the future handoff
// boundary: it is stored and never executed in this segment.
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
	body, err := cfg.FetchManifest(ctx)
	if err != nil || len(body) == 0 {
		return Result{}, fail("MANIFEST_UNAVAILABLE", "the Hub manifest could not be fetched")
	}
	if hexDigest(body) != cfg.ManifestSHA256 {
		return Result{}, fail("UPDATE_DIGEST_MISMATCH", "the manifest does not match the approved SHA-256")
	}
	if json.Unmarshal(body, &m) != nil {
		return Result{}, fail("MANIFEST_INVALID", "the manifest is not valid JSON")
	}
	c, err := validateTarget(m, cfg.Target)
	if err != nil {
		return Result{}, err
	}
	path, err := fetchPackage(ctx, cfg.WorkDir, cfg.Target, c)
	if err != nil {
		return Result{}, err
	}
	_ = runner // Task 4 executes the fixed argv through this boundary.
	return Result{VerifiedPath: path, Manifest: m}, errHandoff
}

// validateTarget is the gate for a *target* release, which is by definition not
// the table of the running build. It therefore checks what an upgrade must
// honour rather than table equality: the target's own schema and policy
// schema, its architecture, and a pinned meshmuxd component whose source class
// matches its Dev flag. upgrade.Manifest.Validate stays the running-build
// self-check and is not applied here.
func validateTarget(m upgrade.Manifest, target string) (upgrade.Component, error) {
	if m.Schema != upgrade.Schema {
		return upgrade.Component{}, fail("MANIFEST_SCHEMA_INVALID", "the target names another manifest schema")
	}
	if m.PolicySchema != upgrade.PolicySchema {
		return upgrade.Component{}, fail("MANIFEST_POLICY_SCHEMA_INVALID", "the target names another policy schema")
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
