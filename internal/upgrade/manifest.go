// Package upgrade is the release domain of issue #11: what a MeshMux release is
// (the read-only manifest of #11a) and which release a task converges a node to
// (the release target of #11b, merged here from internal/jobs by the internal
// regroup Task 6). It downloads, applies, rolls back and enqueues nothing
// itself (#11b-11e): the manifest describes a release, the target names one, and
// the executor, apply and rollback live in the #11c series.
//
// It reuses install's pinned artifact tables as data and node's version
// constants, so internal/web shows the release without importing the privileged
// installer. The set endpoint carries both architecture tables; a node selects
// its own runtime.GOARCH projection locally. The target half performs no I/O: no
// table, no queue, no process.
package upgrade

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

// Schema identifies the manifest document; another schema is another contract.
const Schema = "meshmux-release/v1"

// SetSchema identifies the dual-arch manifest set served to Agents (U4). Each
// entry keeps the single-arch Schema above, so an entry's projection is exactly
// the document an approval pins.
const SetSchema = "meshmux-release-set/v1"

// PolicySchema is the stored route policy schema (10d-1); a manifest naming
// another value cannot be applied by this binary.
const PolicySchema = 8

// supportedArchitectures is the fixed Debian architecture matrix of this build.
// A set always carries every entry: a missing table is a partial release.
var supportedArchitectures = []string{"amd64", "arm64"}

// Component is one fixed release asset. Architecture is explicit so an amd64
// digest is never paired with an arm64 source. Dev marks a pre-release dev
// build: a dev- version with a file:// or https:// source instead of a GitHub
// release, still pinned by SHA-256 (12e switches meshmuxd to a release).
type Component struct {
	Name, Version, Architecture, Source, SHA256, Format string
	Dev                                                 bool
}

// Manifest is the release description the Hub shows and verifies.
type Manifest struct {
	Schema               string           `json:"schema"`
	Version              string           `json:"version"`
	Architecture         string           `json:"architecture"`
	PolicySchema         int              `json:"policy_schema"`
	RoutePolicyRevisions map[string]int64 `json:"route_policy_revisions,omitempty"`
	Components           []Component      `json:"components"`
	// DatabaseMigration is the hub target's migration class (#11d spec §5.8):
	// empty is additive. It rides the target gate in internal/update, not
	// Validate below, because Validate is the running build's self-check. The
	// field is part of the manifest bytes, so manifest_sha256 pins it.
	DatabaseMigration string `json:"database_migration,omitempty"`
}

// mihomo is the pinned subscription client of the publish gate. It is not a node
// package, so its pins live here; scripts/ci-subscription-clients.sh verifies the
// same release assets.
var mihomo = map[string]Component{
	"amd64": {"mihomo", node.MihomoVersion, "amd64", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20", "gz", false},
	"arm64": {"mihomo", node.MihomoVersion, "arm64", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-arm64-v1.19.32.gz", "9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0", "gz", false},
}

// ManifestSet is the release description of one build across the supported
// architectures. The Agent selects its own runtime.GOARCH entry and verifies
// that entry's canonical bytes against its approved per-arch SHA-256; the set
// never carries a caller-selected file, URL or version. PolicySchema and
// Version are repeated at the top so a partial or mixed set is refused before
// any entry is trusted.
type ManifestSet struct {
	Schema       string              `json:"schema"`
	Version      string              `json:"version"`
	PolicySchema int                 `json:"policy_schema"`
	Manifests    map[string]Manifest `json:"manifests"`
}

// ForArch assembles the immutable manifest of one supported architecture. An
// unknown architecture is refused, never given a partial or floating release.
func ForArch(architecture string) (Manifest, error) {
	components, ok := pinnedComponents(architecture)
	if !ok {
		return Manifest{}, errors.New("MANIFEST_ARCH_INVALID: no pinned release for this architecture")
	}
	m := Manifest{Schema: Schema, Version: node.CurrentAgentVersion(), Architecture: architecture,
		PolicySchema: PolicySchema, Components: components}
	return m, m.Validate()
}

// ForArchSet assembles this build's dual-arch set. Every supported architecture
// is projected through ForArch, so each embedded table is byte-identical to the
// single-arch document the approval pins.
func ForArchSet() (ManifestSet, error) {
	set := ManifestSet{Schema: SetSchema, Version: node.CurrentAgentVersion(), PolicySchema: PolicySchema,
		Manifests: make(map[string]Manifest, len(supportedArchitectures))}
	for _, architecture := range supportedArchitectures {
		m, err := ForArch(architecture)
		if err != nil {
			return ManifestSet{}, err
		}
		set.Manifests[architecture] = m
	}
	if err := set.Validate(); err != nil {
		return ManifestSet{}, err
	}
	return set, nil
}

// Projection returns one architecture's manifest and its canonical JSON bytes.
// For a set built by ForArchSet those bytes are exactly json.Marshal(ForArch):
// the Agent hashes this projection against the approved SHA-256, so a set
// envelope can never shift the trust anchor. A missing or mismatched entry is
// refused instead of falling back to another architecture.
func (s ManifestSet) Projection(architecture string) (Manifest, []byte, error) {
	m, ok := s.Manifests[architecture]
	if !ok {
		return Manifest{}, nil, errors.New("MANIFEST_ARCH_INVALID: the manifest set has no table for this architecture")
	}
	if m.Architecture != architecture {
		return Manifest{}, nil, errors.New("MANIFEST_ARCH_INVALID: the manifest entry names another architecture")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, nil, errors.New("MANIFEST_INVALID: the manifest projection could not be encoded")
	}
	return m, body, nil
}

// Validate refuses a partial or mixed set: every supported architecture table
// must be present exactly once, agree with the set header, and pass the same
// running-build self-check as Manifest.Validate. This is the Hub's serving
// contract; a target release on the Agent side is checked by update's
// ValidateTarget instead, because its component table is not the running
// build's table.
func (s ManifestSet) Validate() error {
	if s.Schema != SetSchema {
		return errors.New("MANIFEST_SET_SCHEMA_INVALID: unknown manifest set schema")
	}
	if !releaseVersion.MatchString(s.Version) {
		return errors.New("MANIFEST_VERSION_INVALID: version is not a SemVer release")
	}
	if s.PolicySchema != PolicySchema {
		return errors.New("MANIFEST_POLICY_SCHEMA_INVALID: policy schema does not match this binary")
	}
	if len(s.Manifests) != len(supportedArchitectures) {
		return errors.New("MANIFEST_SET_INCOMPLETE: the set must carry every supported architecture")
	}
	for _, architecture := range supportedArchitectures {
		m, ok := s.Manifests[architecture]
		if !ok {
			return errors.New("MANIFEST_SET_INCOMPLETE: the set must carry every supported architecture")
		}
		if m.Architecture != architecture {
			return errors.New("MANIFEST_ARCH_INVALID: the manifest entry names another architecture")
		}
		if m.Version != s.Version {
			return errors.New("MANIFEST_VERSION_INVALID: the manifest entry names another version")
		}
		if m.PolicySchema != s.PolicySchema {
			return errors.New("MANIFEST_POLICY_SCHEMA_INVALID: the manifest entry names another policy schema")
		}
		if err := m.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// pinnedComponents derives the table from the existing single sources of truth.
func pinnedComponents(architecture string) ([]Component, bool) {
	hub, kernel := install.PinnedArtifacts(architecture), install.PinnedNodeArtifacts(architecture)
	daemon, client := install.PinnedMeshmuxd(architecture), mihomo[architecture]
	if len(hub) == 0 || len(kernel) == 0 || len(daemon) != 1 || client.Name == "" {
		return nil, false
	}
	fixed := make([]install.Artifact, 0, len(hub)+len(kernel)+len(daemon)+1)
	fixed = append(fixed, hub...)
	fixed = append(fixed, kernel...)
	fixed = append(fixed, daemon...)
	fixed = append(fixed, install.Artifact{Component: client.Name, Version: client.Version, Source: client.Source, SHA256: client.SHA256, Format: client.Format})
	out := make([]Component, 0, len(fixed))
	for _, a := range fixed {
		out = append(out, Component{a.Component, a.Version, architecture, a.Source, a.SHA256, a.Format, strings.HasPrefix(a.Version, "dev-")})
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
		if !digestSHA.MatchString(c.SHA256) {
			return errors.New("MANIFEST_COMPONENT_INVALID: component source or digest is not pinned")
		}
		if c.Dev {
			// A dev build is never a release: dev- version and a pinned local
			// or intranet source, with the digest above as trust anchor.
			if !strings.HasPrefix(c.Version, "dev-") || len(c.Version) == len("dev-") ||
				!(strings.HasPrefix(c.Source, "file://") || strings.HasPrefix(c.Source, "https://")) {
				return errors.New("MANIFEST_COMPONENT_INVALID: dev component is not pinned to a dev- build")
			}
		} else if !strings.HasPrefix(c.Source, "https://github.com/") {
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

// AdjacentRelease refuses a version jump: target must be the immediate
// successor of current in the ordered release history. Skipping a release would
// make rollback target an unverified N-2, so it fails with UPGRADE_NOT_ADJACENT.
func AdjacentRelease(history []string, current, target string) error {
	for i, version := range history {
		if version != current {
			continue
		}
		if i+1 < len(history) && history[i+1] == target {
			return nil
		}
		break
	}
	return errors.New("UPGRADE_NOT_ADJACENT: upgrade one release at a time")
}
