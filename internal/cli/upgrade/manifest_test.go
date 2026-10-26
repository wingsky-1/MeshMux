package upgrade

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/meshnet"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// TestForArchPinsEveryComponent pins the #11a manifest contract: one MeshMux
// version, the five fixed components with source/architecture/SHA-256, and the
// policy schema of this binary. meshmuxd is the pre-release dev build, so its
// pin is a dev- version with a file:// source rather than a GitHub release.
func TestForArchPinsEveryComponent(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		m, err := ForArch(arch)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if m.Schema != Schema || m.Version != node.CurrentAgentVersion() || m.Architecture != arch || m.PolicySchema != 8 {
			t.Fatalf("%s: header = %+v", arch, m)
		}
		want := map[string]string{"caddy": "2.11.7", "headscale": meshnet.HeadscaleVersion,
			"sing-box": node.KernelVersion, "mihomo": node.MihomoVersion, "meshmuxd": "dev-20261023"}
		if len(m.Components) != len(want) {
			t.Fatalf("%s: components = %+v", arch, m.Components)
		}
		for _, c := range m.Components {
			if want[c.Name] != c.Version || c.Architecture != arch || !digestSHA.MatchString(c.SHA256) {
				t.Fatalf("%s: unpinned component %+v", arch, c)
			}
			if c.Dev {
				if !strings.HasPrefix(c.Version, "dev-") || !strings.HasPrefix(c.Source, "file://") {
					t.Fatalf("%s: unpinned dev component %+v", arch, c)
				}
				continue
			}
			if !strings.HasPrefix(c.Source, "https://github.com/") {
				t.Fatalf("%s: unpinned component %+v", arch, c)
			}
		}
	}
	if meshnet.HeadscaleVersion != "0.29.5" || node.KernelVersion != "1.14.3" || node.MihomoVersion != "1.19.32" {
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

// TestManifestRejectsSkippedRelease pins the adjacent-release rule: a node may
// only move to the immediate successor of its running version, so rollback
// always targets the release the node itself just verified.
func TestManifestRejectsSkippedRelease(t *testing.T) {
	history := []string{"1.0.0", "1.0.1", "1.0.2"}
	if err := AdjacentRelease(history, "1.0.0", "1.0.1"); err != nil {
		t.Fatalf("adjacent release refused: %v", err)
	}
	for _, tc := range []struct{ current, target string }{
		{"1.0.0", "1.0.2"}, // skipped 1.0.1
		{"1.0.1", "1.0.3"}, // target is not a known release
		{"1.0.2", "1.0.1"}, // backward is not an upgrade
		{"1.0.0", "1.0.0"}, // same version is not an upgrade
		{"0.9.9", "1.0.0"}, // current is not a known release
	} {
		if err := AdjacentRelease(history, tc.current, tc.target); err == nil ||
			!strings.Contains(err.Error(), "UPGRADE_NOT_ADJACENT") {
			t.Fatalf("%s -> %s: err = %v, want UPGRADE_NOT_ADJACENT", tc.current, tc.target, err)
		}
	}
}

// TestManifestRequiresMeshmuxd proves the executor binary is part of the fixed
// table: a manifest without it is incomplete and refused.
func TestManifestRequiresMeshmuxd(t *testing.T) {
	base, err := ForArch("amd64")
	if err != nil {
		t.Fatal(err)
	}
	m := base
	m.Components = nil
	for _, c := range base.Components {
		if c.Name != "meshmuxd" {
			m.Components = append(m.Components, c)
		}
	}
	if len(m.Components) != len(base.Components)-1 {
		t.Fatalf("test table still holds meshmuxd: %+v", m.Components)
	}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "MANIFEST_COMPONENT_INVALID") {
		t.Fatalf("manifest without meshmuxd err = %v, want MANIFEST_COMPONENT_INVALID", err)
	}
}

// TestManifestAcceptsDevFileSource pins the pre-release dev build rule: a Dev
// component carries a dev- version and a file:// source but still a SHA-256.
// The same component without Dev is a release claim and must be refused.
func TestManifestAcceptsDevFileSource(t *testing.T) {
	m, err := ForArch("amd64")
	if err != nil {
		t.Fatal(err)
	}
	index := -1
	for i, c := range m.Components {
		if c.Name == "meshmuxd" {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("manifest has no meshmuxd component")
	}
	dev := m.Components[index]
	if !dev.Dev || !strings.HasPrefix(dev.Version, "dev-") ||
		!strings.HasPrefix(dev.Source, "file://") || !digestSHA.MatchString(dev.SHA256) {
		t.Fatalf("meshmuxd dev pin = %+v", dev)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("dev file source refused: %v", err)
	}
	m.Components = append([]Component(nil), m.Components...)
	m.Components[index].Dev = false
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "MANIFEST_COMPONENT_INVALID") {
		t.Fatalf("dev build declared as release err = %v, want MANIFEST_COMPONENT_INVALID", err)
	}
}

// cloneSet returns an independent copy so one mutation case cannot leak into the
// pinned tables.
func cloneSet(base ManifestSet) ManifestSet {
	out := ManifestSet{Schema: base.Schema, Version: base.Version, PolicySchema: base.PolicySchema,
		Manifests: make(map[string]Manifest, len(base.Manifests))}
	for arch, m := range base.Manifests {
		m.Components = append([]Component(nil), m.Components...)
		out.Manifests[arch] = m
	}
	return out
}

// TestForArchSetCarriesBothPinnedTables pins the dual-arch set contract (U4):
// one release and policy schema, both architecture tables, and a per-arch
// projection whose bytes are exactly upgrade.ForArch(arch). That byte identity
// is what lets the approval pin one projection and the Agent verify the same
// bytes after selecting its runtime.GOARCH entry from the served set.
func TestForArchSetCarriesBothPinnedTables(t *testing.T) {
	set, err := ForArchSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Schema != SetSchema || set.Version != node.CurrentAgentVersion() || set.PolicySchema != PolicySchema {
		t.Fatalf("set header = %+v", set)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("pinned set refused: %v", err)
	}
	if len(set.Manifests) != 2 {
		t.Fatalf("set carries %d architecture tables, want both", len(set.Manifests))
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var served ManifestSet
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatalf("served set does not decode: %v", err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		want, err := ForArch(arch)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		rawBytes, err := json.Marshal(served.Manifests[arch])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rawBytes, wantBytes) {
			t.Fatalf("%s projection bytes differ from ForArch:\n got: %s\nwant: %s", arch, rawBytes, wantBytes)
		}
		projected, projectedBytes, err := served.Projection(arch)
		if err != nil || projected.Architecture != arch || !bytes.Equal(projectedBytes, wantBytes) {
			t.Fatalf("%s projection = %+v, %q, %v", arch, projected, projectedBytes, err)
		}
	}
	if _, _, err := served.Projection("mips"); err == nil || !strings.Contains(err.Error(), "MANIFEST_ARCH_INVALID") {
		t.Fatalf("unknown architecture projection err = %v", err)
	}
}

// TestManifestSetValidateRejectsTampering refuses a partial set, a foreign set
// schema and a set whose entry contradicts its key, header or the pinned table.
func TestManifestSetValidateRejectsTampering(t *testing.T) {
	base, err := ForArchSet()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*ManifestSet)
		code   string
	}{
		{"foreign set schema", func(s *ManifestSet) { s.Schema = "meshmux-release-set/v2" }, "MANIFEST_SET_SCHEMA_INVALID"},
		{"version not semver", func(s *ManifestSet) { s.Version = "latest" }, "MANIFEST_VERSION_INVALID"},
		{"policy schema mismatch", func(s *ManifestSet) { s.PolicySchema = 9 }, "MANIFEST_POLICY_SCHEMA_INVALID"},
		{"missing arm64", func(s *ManifestSet) { delete(s.Manifests, "arm64") }, "MANIFEST_SET_INCOMPLETE"},
		{"extra architecture", func(s *ManifestSet) { s.Manifests["riscv64"] = s.Manifests["amd64"] }, "MANIFEST_SET_INCOMPLETE"},
		{"architecture under wrong key", func(s *ManifestSet) {
			m := s.Manifests["amd64"]
			m.Architecture = "arm64"
			s.Manifests["amd64"] = m
		}, "MANIFEST_ARCH_INVALID"},
		{"entry version mismatch", func(s *ManifestSet) {
			m := s.Manifests["amd64"]
			m.Version = "9.9.9"
			s.Manifests["amd64"] = m
		}, "MANIFEST_VERSION_INVALID"},
		{"entry policy mismatch", func(s *ManifestSet) {
			m := s.Manifests["amd64"]
			m.PolicySchema = 7
			s.Manifests["amd64"] = m
		}, "MANIFEST_POLICY_SCHEMA_INVALID"},
		{"tampered component", func(s *ManifestSet) {
			m := s.Manifests["amd64"]
			m.Components = m.Components[1:]
			s.Manifests["amd64"] = m
		}, "MANIFEST_COMPONENT_INVALID"},
	}
	for _, tc := range cases {
		set := cloneSet(base)
		tc.mutate(&set)
		if err := set.Validate(); err == nil || !strings.Contains(err.Error(), tc.code) {
			t.Fatalf("%s: err = %v, want %s", tc.name, err, tc.code)
		}
	}
}

// TestVersionSingleSource pins N7 of #11d spec §5.3: the release manifest
// projection, node.CurrentAgentVersion and buildinfo.Version are one value, not
// three copies that happen to agree. Saving and restoring the injected version
// moves both projections together; there is no second assignment site a caller
// could forget. It must not run in parallel: it mutates the process-wide build
// identity.
func TestVersionSingleSource(t *testing.T) {
	original := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = original })
	for _, version := range []string{"1.0.0", "1.4.2", "2.0.0-rc.1"} {
		buildinfo.Version = version
		if got := node.CurrentAgentVersion(); got != version {
			t.Fatalf("node.CurrentAgentVersion() = %q, want %q", got, version)
		}
		m, err := ForArch("amd64")
		if err != nil {
			t.Fatal(err)
		}
		if m.Version != version {
			t.Fatalf("ForArch version = %q, want %q", m.Version, version)
		}
		set, err := ForArchSet()
		if err != nil {
			t.Fatal(err)
		}
		if set.Version != version || set.Manifests["arm64"].Version != version {
			t.Fatalf("ForArchSet versions = %q/%q, want %q", set.Version, set.Manifests["arm64"].Version, version)
		}
		// The version is inside the canonical JSON, so a version injection
		// moves every manifest digest. Nothing may pin a digest across versions.
		body, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`"version":"`+version+`"`)) {
			t.Fatalf("canonical manifest does not carry the injected version: %s", body)
		}
	}
	buildinfo.Version = original
	if got := node.CurrentAgentVersion(); got != original {
		t.Fatalf("restored version = %q, want %q", got, original)
	}
}
