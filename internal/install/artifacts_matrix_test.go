package install

// The launcher-facing surface of the installer is a fixed table of versions and
// one architecture matrix. These tests are the drift gate for the "single
// source" rule: a release bump must change a constant, not one literal in a URL
// and another in a plan row.

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/versions"
)

// TestPinnedTablesCoverTheSupportedMatrix proves every pinned table (Hub, node,
// executor) carries one entry per supported architecture and nothing else.
func TestPinnedTablesCoverTheSupportedMatrix(t *testing.T) {
	for _, table := range []struct {
		name   string
		pinned func(string) []Artifact
	}{
		{"hub", PinnedArtifacts},
		{"node", PinnedNodeArtifacts},
		{"executor", PinnedMeshmuxd},
	} {
		for _, architecture := range versions.SupportedArchitectures() {
			artifacts := table.pinned(architecture)
			if len(artifacts) == 0 {
				t.Fatalf("%s table has no entry for %s", table.name, architecture)
			}
			for _, artifact := range artifacts {
				if !strings.Contains(artifact.Source, architecture) {
					t.Fatalf("%s/%s artifact source names another architecture: %q", table.name, architecture, artifact.Source)
				}
				if !versions.IsSupportedArchitecture(architecture) {
					t.Fatalf("%s carries an unsupported architecture %q", table.name, architecture)
				}
			}
		}
		for _, architecture := range []string{"riscv64", "386", ""} {
			if got := table.pinned(architecture); len(got) != 0 {
				t.Fatalf("%s table leaked %d entries for unsupported %q", table.name, len(got), architecture)
			}
		}
	}
}

// TestArtifactSourcesDeriveFromThePinnedVersion proves the download URL is a
// function of the version constant, so bumping the version cannot leave a stale
// literal behind in the source column.
func TestArtifactSourcesDeriveFromThePinnedVersion(t *testing.T) {
	for _, architecture := range versions.SupportedArchitectures() {
		for _, artifact := range append(PinnedArtifacts(architecture), PinnedNodeArtifacts(architecture)...) {
			if !strings.Contains(artifact.Source, artifact.Version) {
				t.Fatalf("%s source %q does not name its pinned version %q", artifact.Component, artifact.Source, artifact.Version)
			}
		}
		for _, artifact := range PinnedMeshmuxd(architecture) {
			// 12e replaces the dev pin with a published GitHub release asset.
			// Until then the executor is a dev- build from the Hub-hosted
			// development directory, named after its architecture (not after the
			// dev version), and only the version constant moves.
			if !strings.HasPrefix(artifact.Version, devBuildVersion) {
				t.Fatalf("executor pin = %q, want the dev pin %q until 12e publishes it",
					artifact.Version, devBuildVersion)
			}
			if want := devBuildSource(architecture); artifact.Source != want {
				t.Fatalf("executor source = %q, want %q", artifact.Source, want)
			}
		}
	}
}

// TestPlanComponentsUseThePinnedVersions keeps the human-facing plan rows in
// step with the artifact tables; a version bump must not leave 2.11.7 in prose.
func TestPlanComponentsUseThePinnedVersions(t *testing.T) {
	plan := BuildPlan("0123456789abcdef0123456789abcdef", Config{
		ManagementDomain: "console.example.invalid", SubscriptionDomain: "sub.example.invalid",
		HeadscaleDomain: "mesh.example.invalid",
	}, versions.ArchitectureAMD64, nil, []int{22})
	want := map[string]string{
		"Caddy":     CaddyVersion,
		"Headscale": HeadscaleVersion,
	}
	for _, component := range plan.Components {
		if version, ok := want[component.Name]; ok && component.Version != version {
			t.Fatalf("plan %s = %q, want %q", component.Name, component.Version, version)
		}
		if component.Name == "sing-box" && !strings.HasPrefix(component.Version, KernelVersion) {
			t.Fatalf("plan sing-box = %q, want it to start with %q", component.Version, KernelVersion)
		}
	}
}

// TestArchitectureForRuntimeFollowsTheMatrix keeps the runtime projection and
// the supported matrix from drifting.
func TestArchitectureForRuntimeFollowsTheMatrix(t *testing.T) {
	got := architectureForRuntime()
	if got != "" && !versions.IsSupportedArchitecture(got) {
		t.Fatalf("architectureForRuntime() = %q, which is outside the matrix", got)
	}
	for _, architecture := range versions.SupportedArchitectures() {
		if err := validateNodeArchitecture(architecture); err != nil {
			t.Fatalf("validateNodeArchitecture(%q) = %v", architecture, err)
		}
	}
	if err := validateNodeArchitecture("riscv64"); err == nil {
		t.Fatal("validateNodeArchitecture(riscv64) must refuse an architecture outside the matrix")
	}
}
