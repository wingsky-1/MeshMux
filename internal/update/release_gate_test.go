package update

// The GitHub release branch of the restricted executor (ruling U1). v1.0.0
// ships the real flow: a non-dev meshmuxd pin with a https://github.com release
// source must pass the full target gate, and the dev file:// pin is only the
// transitional shape. This is a gate test: nothing is downloaded, written or
// executed.

import (
	"runtime"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// releaseManifest is the target release of the shipped flow: a non-dev
// meshmuxd component published as a GitHub release asset, still pinned by
// SHA-256.
func releaseManifest() upgrade.Manifest {
	return upgrade.Manifest{
		Schema: upgrade.Schema, Version: "1.0.1", Architecture: runtime.GOARCH,
		PolicySchema: upgrade.PolicySchema,
		Components: []upgrade.Component{{
			Name: "meshmuxd", Version: "1.0.1", Architecture: runtime.GOARCH,
			Source: "https://github.com/wingsky-1/MeshMux/releases/download/v1.0.1/meshmuxd-linux-" + runtime.GOARCH,
			SHA256: strings.Repeat("a", 64), Format: "elf",
		}},
	}
}

// TestReleaseMeshmuxdPassesTargetGate is the U1 acceptance at gate level: the
// release component passes validateTarget and the compat gate, so the shipped
// (non-dev, GitHub) flow is not a later-porting promise. It also pins that the
// dev source class is not what makes a release acceptable.
func TestReleaseMeshmuxdPassesTargetGate(t *testing.T) {
	m := releaseManifest()
	component, err := ValidateTarget(m, m.Version)
	if err != nil {
		t.Fatalf("release target refused: %v", err)
	}
	if component.Dev || !strings.HasPrefix(component.Source, "https://github.com/") {
		t.Fatalf("component = %+v, want the GitHub release shape", component)
	}
	if err := compatGate(m); err != nil {
		t.Fatalf("release manifest failed the compat gate: %v", err)
	}
	if trustedSource(upgrade.Component{Version: "1.0.1", Source: component.Source, Dev: true}) {
		t.Fatal("a release URL was accepted as a dev build")
	}
	// The same component without a GitHub source stays refused: the release
	// branch is not a widening of what may be executed.
	foreign := releaseManifest()
	foreign.Components[0].Source = "https://example.invalid/meshmuxd"
	if _, err := ValidateTarget(foreign, foreign.Version); err == nil || codeOf(err) != "MANIFEST_COMPONENT_INVALID" {
		t.Fatalf("foreign release source = %v, want MANIFEST_COMPONENT_INVALID", err)
	}
	// The transitional dev pin still passes the same gate, so both source
	// classes are proven before the dev path is retired.
	dev := releaseManifest()
	dev.Components[0].Dev = true
	dev.Components[0].Version = "dev-20261023"
	dev.Components[0].Source = "file:///var/lib/meshmux/dev/meshmuxd"
	if _, err := ValidateTarget(dev, dev.Version); err != nil {
		t.Fatalf("dev target refused: %v", err)
	}
}
