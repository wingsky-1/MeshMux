package install

// The launcher-facing surface of the installer is a fixed table of versions and
// one architecture matrix. These tests are the drift gate for the "single
// source" rule: a release bump must change a constant, not one literal in a URL
// and another in a plan row.

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// TestPinnedTablesCoverTheSupportedMatrix proves every pinned table (Hub, node)
// carries one entry per supported architecture and nothing else. The executor
// table is deliberately excluded: it is derived from the running build and the
// deployed dev drop, so an architecture this build cannot name verifiable bytes
// for has no entry at all (TestExecutorPinIsVerifiable covers that rule).
func TestPinnedTablesCoverTheSupportedMatrix(t *testing.T) {
	for _, table := range []struct {
		name   string
		pinned func(string) []Artifact
	}{
		{"hub", PinnedArtifacts},
		{"node", PinnedNodeArtifacts},
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
			// Until then the executor pin names the running build (this
			// architecture) or the deployed dev drop, so its source is the fixed
			// drop path of exactly this architecture and its digest is one a
			// reader can re-derive.
			if want := "file://" + versions.DevArtifactPath(architecture); artifact.Source != want {
				t.Fatalf("executor source = %q, want %q", artifact.Source, want)
			}
			if !versions.IsDevVersion(artifact.Version) {
				t.Fatalf("executor version = %q, want the dev pre-release of this build", artifact.Version)
			}
			if !backup.DigestPattern.MatchString(artifact.SHA256) {
				t.Fatalf("executor digest = %q, want SHA-256 hex", artifact.SHA256)
			}
		}
	}
}

// TestExecutorPinIsVerifiable pins the property that replaced the placeholder
// pin: a development build never names bytes it cannot verify. The running
// architecture pins /proc/self/exe, so its entry must exist and must equal the
// running digest; another architecture is pinned only from a checksum document
// the build wrote, and without one the table stays empty rather than naming an
// unverified file.
func TestExecutorPinIsVerifiable(t *testing.T) {
	original := versions.DevArtifactDir
	versions.DevArtifactDir = t.TempDir()
	t.Cleanup(func() { versions.DevArtifactDir = original })

	self, err := buildinfo.Digest()
	if err != nil {
		t.Fatal(err)
	}
	pins := PinnedMeshmuxd(runtime.GOARCH)
	if len(pins) != 1 || pins[0].SHA256 != self {
		t.Fatalf("running-architecture pin = %+v, want the running executable digest %q", pins, self)
	}
	if !strings.HasPrefix(pins[0].Source, "file://") {
		t.Fatalf("executor source = %q, want a file source", pins[0].Source)
	}

	other := versions.ArchitectureARM64
	if runtime.GOARCH == versions.ArchitectureARM64 {
		other = versions.ArchitectureAMD64
	}
	// No drop on disk: the other architecture is refused instead of guessed.
	if got := PinnedMeshmuxd(other); len(got) != 0 {
		t.Fatalf("unpublished architecture pin = %+v, want no entry", got)
	}

	digest := strings.Repeat("a", 64)
	writeDevDrop(t, other, digest)
	pins = PinnedMeshmuxd(other)
	if len(pins) != 1 || pins[0].SHA256 != digest {
		t.Fatalf("drop pin = %+v, want the documented digest %q", pins, digest)
	}

	// A group-writable checksum document is not a trust anchor.
	sums := versions.DevChecksumsPath()
	if err := os.Chmod(sums, 0666); err != nil {
		t.Fatal(err)
	}
	if got := PinnedMeshmuxd(other); len(got) != 0 {
		t.Fatalf("loose checksum document was trusted: %+v", got)
	}
}

// writeDevDrop writes one sha256sum-format checksum document for the given
// architecture's artifact. The artifact bytes are not needed: the pin is read
// from the document, and the fetch path re-hashes the real file.
func writeDevDrop(t *testing.T, architecture, digest string) {
	t.Helper()
	if err := os.MkdirAll(versions.DevArtifactDir, 0755); err != nil {
		t.Fatal(err)
	}
	body := digest + "  " + versions.DevArtifactName(architecture) + "\n"
	if err := os.WriteFile(versions.DevChecksumsPath(), []byte(body), 0644); err != nil {
		t.Fatal(err)
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
