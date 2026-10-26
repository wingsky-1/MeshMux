package hubupgrade

// The root-preset target manifest gate of #11d (spec §5.8). A target manifest is
// a trust anchor, not a Web input: the Web only names a version, and only the
// root-owned file for that version may authorize a package digest.
//
// The gate is deliberately not upgrade.Manifest.Validate: that is the running
// build's self-check and compares the component table with this binary's
// compiled pins, so every real update would be refused. The target-shape rules
// (schema, version, arch, pinned meshmuxd source class, 64-hex digest) live in
// internal/update.ValidateTarget; this gate adds the stored policy schema, the
// strictly-newer rule and database_migration, then freezes the manifest bytes'
// SHA-256 for the record and journal.
//
// Every refusal is MANIFEST_UNAVAILABLE with zero writes: a missing file, a
// non-root owner, a loose mode, unknown fields, trailing data, an illegal
// migration value and an unsupported release all fail the same way.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/update"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
	"github.com/wingsky-1/MeshMux/internal/versions"
)

const manifestMaxBytes = 1 << 20

// Database migration classes of the target manifest. An omitted field is
// additive: an upgrade only becomes destructive when the manifest says so.
const (
	MigrationAdditive     = "additive"
	MigrationIrreversible = "irreversible"
)

// TargetManifest is one authenticated target: the parsed document, the digest
// of exactly the bytes that were authenticated, and the pinned package the
// target names.
type TargetManifest struct {
	Manifest          upgrade.Manifest
	SHA256            string
	Package           upgrade.Component
	DatabaseMigration string
}

// ReadRootManifest authenticates <manifestDir>/manifest-<target>.json for the
// production owner root. It is the production entry point; rootexec and the Web
// producer never pass an owner of their own.
func ReadRootManifest(manifestDir, target string) (TargetManifest, error) {
	return readRootManifest(manifestDir, target, 0)
}

// ReadRootManifestFor is the owner-parameterized gate. Production uses
// ReadRootManifest (root); the root dispatcher names the expected account so a
// B-level fixture can prove the owner rule without chowning to root, exactly as
// backup.Read/Verify name their expected account.
func ReadRootManifestFor(manifestDir, target string, expectedOwner int) (TargetManifest, error) {
	return readRootManifest(manifestDir, target, expectedOwner)
}

// readRootManifest is the testable half: the expected account is explicit so a
// B-level fixture can prove the owner rule without chowning to root.
func readRootManifest(manifestDir, target string, expectedOwner int) (TargetManifest, error) {
	if !targetRE.MatchString(target) {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the requested target is not a SemVer release")
	}
	if manifestDir == "" || !filepath.IsAbs(manifestDir) {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest directory is not absolute")
	}
	dirInfo, err := os.Lstat(manifestDir)
	if err != nil {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest directory is unavailable")
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() ||
		dirInfo.Mode().Perm()&0022 != 0 || !ownedBy(expectedOwner, dirInfo) {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest directory is not a root-owned private-enough directory")
	}
	path := filepath.Join(manifestDir, "manifest-"+target+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "no root manifest exists for the requested target")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0644 || !ownedBy(expectedOwner, info) || info.Size() > manifestMaxBytes {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest is not a 0644 file owned by root")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest could not be read")
	}
	var manifest upgrade.Manifest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest is not a strict manifest document")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return TargetManifest{}, fail(versions.CodeManifestUnavailable, "the root manifest carries trailing data")
	}
	component, migration, err := validateHubTarget(manifest, target)
	if err != nil {
		return TargetManifest{}, err
	}
	sum := sha256.Sum256(body)
	return TargetManifest{
		Manifest:          manifest,
		SHA256:            hex.EncodeToString(sum[:]),
		Package:           component,
		DatabaseMigration: migration,
	}, nil
}

// validateHubTarget applies the target-shape gate, then the two rules that only
// the Hub owns: the stored policy schema must be this build's, and the target
// must be strictly newer than the running release. The migration class is
// normalized so a caller never treats an empty field as unknown.
func validateHubTarget(manifest upgrade.Manifest, target string) (upgrade.Component, string, error) {
	if manifest.Schema != upgrade.Schema {
		return upgrade.Component{}, "", fail(versions.CodeManifestUnavailable, "the root manifest names another manifest schema")
	}
	component, err := update.ValidateTarget(manifest, target)
	if err != nil {
		return upgrade.Component{}, "", fail(versions.CodeManifestUnavailable, "the root manifest failed the target gate")
	}
	if manifest.PolicySchema != upgrade.PolicySchema {
		return upgrade.Component{}, "", fail(versions.CodeManifestUnavailable, "the root manifest names another route policy schema")
	}
	cmp, err := compareRelease(manifest.Version, buildinfo.Version)
	if err != nil || cmp <= 0 {
		return upgrade.Component{}, "", fail(versions.CodeManifestUnavailable, "the target is not newer than the running release")
	}
	switch manifest.DatabaseMigration {
	case "", MigrationAdditive:
		return component, MigrationAdditive, nil
	case MigrationIrreversible:
		return component, MigrationIrreversible, nil
	default:
		return upgrade.Component{}, "", fail(versions.CodeManifestUnavailable, "the root manifest names an unknown database_migration")
	}
}
