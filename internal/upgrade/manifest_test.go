package upgrade

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/headscale"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// TestForArchPinsEveryComponent pins the #11a manifest contract: one MeshMux
// version, the four fixed components with source/architecture/SHA-256, and the
// policy schema of this binary.
func TestForArchPinsEveryComponent(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		m, err := ForArch(arch)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if m.Schema != Schema || m.Version != node.CurrentAgentVersion || m.Architecture != arch || m.PolicySchema != 8 {
			t.Fatalf("%s: header = %+v", arch, m)
		}
		want := map[string]string{"caddy": "2.11.7", "headscale": headscale.HeadscaleVersion,
			"sing-box": node.KernelVersion, "mihomo": node.MihomoVersion}
		if len(m.Components) != len(want) {
			t.Fatalf("%s: components = %+v", arch, m.Components)
		}
		for _, c := range m.Components {
			if want[c.Name] != c.Version || c.Architecture != arch ||
				!strings.HasPrefix(c.Source, "https://github.com/") || !digestSHA.MatchString(c.SHA256) {
				t.Fatalf("%s: unpinned component %+v", arch, c)
			}
		}
	}
	if headscale.HeadscaleVersion != "0.29.5" || node.KernelVersion != "1.14.3" || node.MihomoVersion != "1.19.32" {
		t.Fatal("component baseline drifted from the documented v1.0.0 release")
	}
}

// TestManifestValidateRejectsTampering covers a foreign or tampered manifest,
// including an unsupported architecture.
func TestManifestValidateRejectsTampering(t *testing.T) {
	base, err := ForArch("amd64")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Manifest)
		code   string
	}{
		{"foreign schema", func(m *Manifest) { m.Schema = "meshmux-release/v2" }, "MANIFEST_SCHEMA_INVALID"},
		{"version not semver", func(m *Manifest) { m.Version = "latest" }, "MANIFEST_VERSION_INVALID"},
		{"newer policy schema", func(m *Manifest) { m.PolicySchema = 9 }, "MANIFEST_POLICY_SCHEMA_INVALID"},
		{"older policy schema", func(m *Manifest) { m.PolicySchema = 7 }, "MANIFEST_POLICY_SCHEMA_INVALID"},
		{"unknown policy layer", func(m *Manifest) { m.RoutePolicyRevisions = map[string]int64{"mesh": 1} }, "MANIFEST_POLICY_REVISION_INVALID"},
		{"zero policy revision", func(m *Manifest) { m.RoutePolicyRevisions = map[string]int64{"client": 0} }, "MANIFEST_POLICY_REVISION_INVALID"},
		{"missing component", func(m *Manifest) { m.Components = m.Components[1:] }, "MANIFEST_COMPONENT_INVALID"},
		{"duplicate component", func(m *Manifest) { m.Components[0] = m.Components[1] }, "MANIFEST_COMPONENT_INVALID"},
		{"digest uppercase", func(m *Manifest) { m.Components[0].SHA256 = strings.ToUpper(m.Components[0].SHA256) }, "MANIFEST_COMPONENT_INVALID"},
		{"untrusted source", func(m *Manifest) { m.Components[0].Source = "https://example.invalid/x" }, "MANIFEST_COMPONENT_INVALID"},
		{"other architecture", func(m *Manifest) { m.Components[0].Architecture = "arm64" }, "MANIFEST_COMPONENT_INVALID"},
	}
	for _, tc := range cases {
		m := base
		m.Components = append([]Component(nil), base.Components...)
		tc.mutate(&m)
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), tc.code) {
			t.Fatalf("%s: err = %v, want %s", tc.name, err, tc.code)
		}
	}
	if _, err := ForArch("mips"); err == nil || !strings.Contains(err.Error(), "MANIFEST_ARCH_INVALID") {
		t.Fatalf("unknown architecture err = %v", err)
	}
	base.Components[0].SHA256 = strings.Repeat("0", 64)
	if again, _ := ForArch("amd64"); again.Components[0].SHA256 == base.Components[0].SHA256 {
		t.Fatal("a caller mutated the pinned component table")
	}
}
