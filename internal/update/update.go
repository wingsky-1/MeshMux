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
type Result struct {
	VerifiedPath string           `json:"verified_path"`
	Manifest     upgrade.Manifest `json:"manifest"`
}

func fail(code, detail string) error { return errors.New(code + ": " + detail) }

var (
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
	if json.Unmarshal(body, &m) != nil || m.Schema != upgrade.Schema {
		return Result{}, fail("MANIFEST_INVALID", "the manifest is not this binary's contract")
	}
	if m.Version != cfg.Target {
		return Result{}, fail("UPDATE_TARGET_INVALID", "the manifest does not describe the approved target")
	}
	c, ok := packageComponent(m)
	if !ok {
		return Result{}, fail("MANIFEST_COMPONENT_INVALID", "the manifest has no pinned meshmuxd package")
	}
	path, err := fetchPackage(ctx, cfg.WorkDir, cfg.Target, c)
	if err != nil {
		return Result{}, err
	}
	_ = runner // Task 4 executes the fixed argv through this boundary.
	return Result{VerifiedPath: path, Manifest: m}, errHandoff
}

func packageComponent(m upgrade.Manifest) (upgrade.Component, bool) {
	for _, c := range m.Components {
		dev := c.Dev && (strings.HasPrefix(c.Source, "file://") || strings.HasPrefix(c.Source, "https://"))
		release := !c.Dev && strings.HasPrefix(c.Source, "https://github.com/")
		if c.Name == "meshmuxd" && c.Architecture == runtime.GOARCH && digestRE.MatchString(c.SHA256) && (dev || release) {
			return c, true
		}
	}
	return upgrade.Component{}, false
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
	if err != nil || res.StatusCode != http.StatusOK {
		return nil, fail("UPDATE_DOWNLOAD_FAILED", "the package could not be downloaded")
	}
	defer res.Body.Close()
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
// over the authenticated channel; no manifest body ever comes from argv.
func HubManifest(ctx context.Context) ([]byte, error) {
	var cfg node.Config
	var identity node.Identity
	for _, f := range []struct {
		path string
		v    any
	}{{node.AgentConfigPath, &cfg}, {node.IdentityPath, &identity}} {
		if info, err := os.Lstat(f.path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("AGENT_CONFIG_UNAVAILABLE")
		}
		if data, err := os.ReadFile(f.path); err != nil || json.Unmarshal(data, f.v) != nil {
			return nil, errors.New("AGENT_CONFIG_UNAVAILABLE")
		}
	}
	if cfg.ValidateInstalled() != nil || identity.ValidateFor(cfg) != nil {
		return nil, errors.New("AGENT_IDENTITY_UNAVAILABLE")
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
