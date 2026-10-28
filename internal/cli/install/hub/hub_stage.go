package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

// hubStageErrors carries the exact Hub stage failure templates. The Hub
// recovery wording must stay verbatim and guard-checked, so InstallHub owns
// every literal and this phase only selects the applicable entry. The download
// recovery is text-only because its code comes from the wrapped error.
type hubStageErrors struct {
	stageCache               *core.InstallError
	artifactDownloadRecovery string
	artifactChecksum         *core.InstallError
	artifactStage            *core.InstallError
	artifactManifest         *core.InstallError
	artifactFormat           *core.InstallError
	caddyVersion             *core.InstallError
	headscaleVersion         *core.InstallError
	meshmuxBinary            *core.InstallError
	sharedBinary             *core.InstallError
	stageTemporary           *core.InstallError
	caddyConfig              *core.InstallError
	stageValidation          *core.InstallError
	headscaleConfig          *core.InstallError
	operationLog             *core.InstallError
}

// hubStaged reports what the Hub stage phase prepared for the apply phase.
// Mutable operation state is updated through the pointers hubStageArtifacts
// receives, never returned for the caller to reassign.
type hubStaged struct {
	stageDir      string
	caddyPath     string
	headscalePath string
	runtimeStage  string
	runtimeHash   string
	keys          []string
	stagedConfigs map[string]string
}

// hubStageArtifacts is the InstallHub staging phase: it downloads and verifies
// every pinned artifact, extracts and probes Caddy and Headscale, stages the
// running MeshMux runtime, renders the managed configuration into the stage,
// and validates Caddy and Headscale before any file is applied. The failure
// texts stay parameters so the call site keeps the exact Hub wording.
func hubStageArtifacts(ctx context.Context, result *core.InstallResult, state *core.InstallState, previous core.InstallState, hasState bool, opts core.ApplyOptions, record func(string, string, string) error, operationID string, artifacts []core.Artifact, targetFiles map[string]string, failures hubStageErrors) (hubStaged, error) {
	failCode := func(stage, code, recovery string) (hubStaged, error) {
		res, err := core.FailAndRollback(*result, *state, previous, hasState, opts, nil, false, record, stage, code, recovery)
		*result = res
		return hubStaged{}, err
	}
	fail := func(failure *core.InstallError) (hubStaged, error) {
		return failCode(failure.Stage, failure.Code, failure.Recovery)
	}
	stageDir := core.Rooted(opts.Root, "/var/cache/meshmux-installer/"+operationID)
	if err := core.EnsureDirectory(stageDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := core.EnsureDirectory(artifactsDir, 0700); err != nil {
		return fail(failures.stageCache)
	}

	stagedArtifacts := map[string]string{}
	for _, a := range artifacts {
		path, downloadErr := opts.DownloadArtifact(ctx, a, artifactsDir)
		if downloadErr != nil {
			return failCode("stage", core.ArtifactErrorCode(downloadErr), failures.artifactDownloadRecovery)
		}
		if err := core.VerifyFile(path, a.SHA256); err != nil {
			return fail(failures.artifactChecksum)
		}
		if a.Component == "headscale" {
			if err := os.Chmod(path, 0755); err != nil {
				return fail(failures.artifactStage)
			}
		}
		stagedArtifacts[a.Component] = path
		state.Artifacts[a.Component] = a.SHA256
	}
	caddyArchive, okCaddy := stagedArtifacts["caddy"]
	headscalePath, okHeadscale := stagedArtifacts["headscale"]
	if !okCaddy || !okHeadscale {
		return fail(failures.artifactManifest)
	}
	caddyArtifact := core.FindArtifact(artifacts, "caddy")
	headscaleArtifact := core.FindArtifact(artifacts, "headscale")
	caddyPath := filepath.Join(stageDir, "meshmux-caddy")
	if caddyArtifact.Format == "tar.gz" {
		if err := core.ExtractCaddyBinary(caddyArchive, caddyPath); err != nil {
			return fail(failures.artifactFormat)
		}
	} else {
		caddyPath = caddyArchive
	}
	if err := core.VerifyBinaryVersion(ctx, opts.Runner, caddyPath, caddyArtifact.Version); err != nil {
		return fail(failures.caddyVersion)
	}
	if err := core.VerifyBinaryVersion(ctx, opts.Runner, headscalePath, headscaleArtifact.Version); err != nil {
		return fail(failures.headscaleVersion)
	}
	runtimeStage := filepath.Join(stageDir, "meshmuxd")
	executable := opts.Executable
	if executable == "" {
		executable = "/proc/self/exe"
	}
	runtimeHash, err := core.CopyExecutable(executable, runtimeStage)
	if err != nil {
		return fail(failures.meshmuxBinary)
	}
	// A co-located Line pins the exact Hub runtime build it reuses. The Hub
	// must not move to a different build while that pin exists: the Line
	// would silently run a different MeshMux binary than the one it
	// verified. The coordinated Web upgrade that changes both layouts at
	// once is Issue #11; this profile only refuses the unsafe single-sided
	// change.
	if err := core.CheckLocalLineSharedBinary(opts.Root, runtimeHash); err != nil {
		var ie *core.InstallError
		if errors.As(err, &ie) {
			return fail(ie)
		}
		return fail(failures.sharedBinary)
	}

	configDir := filepath.Join(stageDir, "config")
	if err := core.EnsureDirectory(configDir, 0700); err != nil {
		return fail(failures.stageTemporary)
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
			return fail(failures.stageTemporary)
		}
		stagedConfigs[target] = path
	}
	if _, err := opts.Runner.Run(ctx, caddyPath, "validate", "--config", stagedConfigs[core.CaddyConfigPath], "--adapter", "caddyfile"); err != nil {
		return fail(failures.caddyConfig)
	}
	// Configtest must never initialize the final SQLite database or production
	// Noise/DERP keys as root. All mutable paths are redirected to a 0700
	// operation-local scratch directory, following the my-sub staging pattern.
	validationDir := filepath.Join(stageDir, "headscale-validation")
	if err := core.EnsureDirectory(validationDir, 0700); err != nil {
		return fail(failures.stageValidation)
	}
	validationConfig := filepath.Join(validationDir, "headscale.yaml")
	isolatedYAML := strings.ReplaceAll(targetFiles[core.HeadscaleConfigPath], "/var/lib/meshmux-headscale/", validationDir+"/")
	isolatedYAML = strings.ReplaceAll(isolatedYAML, "/run/meshmux-headscale/", validationDir+"/")
	if err := os.WriteFile(validationConfig, []byte(isolatedYAML), 0600); err != nil {
		return fail(failures.stageValidation)
	}
	if _, err := opts.Runner.Run(ctx, headscalePath, "--config", validationConfig, "configtest"); err != nil {
		return fail(failures.headscaleConfig)
	}
	if err := record("stage", "validated", ""); err != nil {
		return fail(failures.operationLog)
	}
	return hubStaged{
		stageDir:      stageDir,
		caddyPath:     caddyPath,
		headscalePath: headscalePath,
		runtimeStage:  runtimeStage,
		runtimeHash:   runtimeHash,
		keys:          keys,
		stagedConfigs: stagedConfigs,
	}, nil
}
