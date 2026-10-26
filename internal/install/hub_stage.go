package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// hubStageErrors carries the exact Hub stage failure templates. The Hub
// recovery wording must stay verbatim and guard-checked, so InstallHub owns
// every literal and this phase only selects the applicable entry. The download
// recovery is text-only because its code comes from the wrapped error.
type hubStageErrors struct {
	stageCache               *InstallError
	artifactDownloadRecovery string
	artifactChecksum         *InstallError
	artifactStage            *InstallError
	artifactManifest         *InstallError
	artifactFormat           *InstallError
	caddyVersion             *InstallError
	headscaleVersion         *InstallError
	meshmuxBinary            *InstallError
	sharedBinary             *InstallError
	stageTemporary           *InstallError
	caddyConfig              *InstallError
	stageValidation          *InstallError
	headscaleConfig          *InstallError
	operationLog             *InstallError
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
func hubStageArtifacts(ctx context.Context, result *InstallResult, state *InstallState, previous InstallState, hasState bool, opts ApplyOptions, record func(string, string, string) error, operationID string, artifacts []Artifact, targetFiles map[string]string, failures hubStageErrors) (hubStaged, error) {
	failCode := func(stage, code, recovery string) (hubStaged, error) {
		res, err := failAndRollback(*result, *state, previous, hasState, opts, nil, false, record, stage, code, recovery)
		*result = res
		return hubStaged{}, err
	}
	fail := func(failure *InstallError) (hubStaged, error) {
		return failCode(failure.Stage, failure.Code, failure.Recovery)
	}
	stageDir := rooted(opts.Root, "/var/cache/meshmux-installer/"+operationID)
	if err := ensureDirectory(stageDir, 0700); err != nil {
		return fail(failures.stageCache)
	}
	artifactsDir := filepath.Join(stageDir, "artifacts")
	if err := ensureDirectory(artifactsDir, 0700); err != nil {
		return fail(failures.stageCache)
	}

	stagedArtifacts := map[string]string{}
	for _, a := range artifacts {
		path, downloadErr := opts.DownloadArtifact(ctx, a, artifactsDir)
		if downloadErr != nil {
			return failCode("stage", artifactErrorCode(downloadErr), failures.artifactDownloadRecovery)
		}
		if err := VerifyFile(path, a.SHA256); err != nil {
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
	caddyArtifact := findArtifact(artifacts, "caddy")
	headscaleArtifact := findArtifact(artifacts, "headscale")
	caddyPath := filepath.Join(stageDir, "meshmux-caddy")
	if caddyArtifact.Format == "tar.gz" {
		if err := extractCaddyBinary(caddyArchive, caddyPath); err != nil {
			return fail(failures.artifactFormat)
		}
	} else {
		caddyPath = caddyArchive
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, caddyPath, caddyArtifact.Version); err != nil {
		return fail(failures.caddyVersion)
	}
	if err := verifyBinaryVersion(ctx, opts.Runner, headscalePath, headscaleArtifact.Version); err != nil {
		return fail(failures.headscaleVersion)
	}
	runtimeStage := filepath.Join(stageDir, "meshmuxd")
	executable := opts.Executable
	if executable == "" {
		executable = "/proc/self/exe"
	}
	runtimeHash, err := copyExecutable(executable, runtimeStage)
	if err != nil {
		return fail(failures.meshmuxBinary)
	}
	// A co-located Line pins the exact Hub runtime build it reuses. The Hub
	// must not move to a different build while that pin exists: the Line
	// would silently run a different MeshMux binary than the one it
	// verified. The coordinated Web upgrade that changes both layouts at
	// once is Issue #11; this profile only refuses the unsafe single-sided
	// change.
	if err := checkLocalLineSharedBinary(opts.Root, runtimeHash); err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return fail(ie)
		}
		return fail(failures.sharedBinary)
	}

	configDir := filepath.Join(stageDir, "config")
	if err := ensureDirectory(configDir, 0700); err != nil {
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
	if _, err := opts.Runner.Run(ctx, caddyPath, "validate", "--config", stagedConfigs[caddyConfigPath], "--adapter", "caddyfile"); err != nil {
		return fail(failures.caddyConfig)
	}
	// Configtest must never initialize the final SQLite database or production
	// Noise/DERP keys as root. All mutable paths are redirected to a 0700
	// operation-local scratch directory, following the my-sub staging pattern.
	validationDir := filepath.Join(stageDir, "headscale-validation")
	if err := ensureDirectory(validationDir, 0700); err != nil {
		return fail(failures.stageValidation)
	}
	validationConfig := filepath.Join(validationDir, "headscale.yaml")
	isolatedYAML := strings.ReplaceAll(targetFiles[headscaleConfigPath], "/var/lib/meshmux-headscale/", validationDir+"/")
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
