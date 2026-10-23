// Package upgrade is the read-only release manifest of issue #11a: MeshMux
// version, the fixed component table of one Debian architecture, the policy
// schema and the route policy revision slot. It describes a release only and
// never downloads, applies, rolls back or enqueues a task (#11b-11e).
//
// It reuses install's pinned artifact tables as data and node's version
// constants, so internal/web shows the release without importing the privileged
// installer.
package upgrade

import (
	"errors"
	"regexp"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// Schema identifies the manifest document; another schema is another contract.
const Schema = "meshmux-release/v1"

// PolicySchema is the stored route policy schema (10d-1); a manifest naming
// another value cannot be applied by this binary.
const PolicySchema = 8

// Component is one fixed release asset. Architecture is explicit so an amd64
// digest is never paired with an arm64 source.
type Component struct {
	Name, Version, Architecture, Source, SHA256, Format string
}

// Manifest is the release description the Hub shows and verifies.
type Manifest struct {
	Schema               string           `json:"schema"`
	Version              string           `json:"version"`
	Architecture         string           `json:"architecture"`
	PolicySchema         int              `json:"policy_schema"`
	RoutePolicyRevisions map[string]int64 `json:"route_policy_revisions,omitempty"`
	Components           []Component      `json:"components"`
}

// mihomo is the pinned subscription client of the publish gate. It is not a node
// package, so its pins live here; scripts/ci-subscription-clients.sh verifies the
// same release assets.
var mihomo = map[string]Component{
	"amd64": {"mihomo", node.MihomoVersion, "amd64", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20", "gz"},
	"arm64": {"mihomo", node.MihomoVersion, "arm64", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-arm64-v1.19.32.gz", "9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0", "gz"},
}

// ForArch assembles the immutable manifest of one supported architecture. An
// unknown architecture is refused, never given a partial or floating release.
func ForArch(architecture string) (Manifest, error) {
	components, ok := pinnedComponents(architecture)
	if !ok {
		return Manifest{}, errors.New("MANIFEST_ARCH_INVALID: no pinned release for this architecture")
	}
	m := Manifest{Schema: Schema, Version: node.CurrentAgentVersion, Architecture: architecture,
		PolicySchema: PolicySchema, Components: components}
	return m, m.Validate()
}

// pinnedComponents derives the table from the existing single sources of truth.
func pinnedComponents(architecture string) ([]Component, bool) {
	hub, kernel, client := install.PinnedArtifacts(architecture), install.PinnedNodeArtifacts(architecture), mihomo[architecture]
	if len(hub) == 0 || len(kernel) == 0 || client.Name == "" {
		return nil, false
	}
	out := make([]Component, 0, len(hub)+len(kernel)+1)
	for _, a := range append(append(hub, kernel...), install.Artifact{Component: client.Name, Version: client.Version, Source: client.Source, SHA256: client.SHA256, Format: client.Format}) {
		out = append(out, Component{a.Component, a.Version, architecture, a.Source, a.SHA256, a.Format})
	}
	return out, true
}

var (
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestSHA      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Validate refuses any manifest this binary must not act on: a foreign schema,
// an unpinned version or digest, another policy schema, an unknown policy layer
// or a component table that differs from the pinned release.
func (m Manifest) Validate() error {
	if m.Schema != Schema {
		return errors.New("MANIFEST_SCHEMA_INVALID: unknown manifest schema")
	}
	if !releaseVersion.MatchString(m.Version) {
		return errors.New("MANIFEST_VERSION_INVALID: version is not a SemVer release")
	}
	if m.PolicySchema != PolicySchema {
		return errors.New("MANIFEST_POLICY_SCHEMA_INVALID: policy schema does not match this binary")
	}
	for layer, revision := range m.RoutePolicyRevisions {
		if (layer != "client" && layer != "server") || revision < 1 {
			return errors.New("MANIFEST_POLICY_REVISION_INVALID: only client/server revisions above zero are valid")
		}
	}
	canonical, ok := pinnedComponents(m.Architecture)
	if !ok || len(m.Components) != len(canonical) {
		return errors.New("MANIFEST_COMPONENT_INVALID: unknown architecture or incomplete component table")
	}
	byName := make(map[string]Component, len(canonical))
	for _, c := range m.Components {
		if !digestSHA.MatchString(c.SHA256) || !strings.HasPrefix(c.Source, "https://github.com/") {
			return errors.New("MANIFEST_COMPONENT_INVALID: component source or digest is not pinned")
		}
		if _, duplicate := byName[c.Name]; duplicate {
			return errors.New("MANIFEST_COMPONENT_INVALID: duplicate component")
		}
		byName[c.Name] = c
	}
	for _, want := range canonical {
		if byName[want.Name] != want {
			return errors.New("MANIFEST_COMPONENT_INVALID: component does not match the pinned release")
		}
	}
	return nil
}
