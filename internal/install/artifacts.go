package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/backup"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/versions"
)

type Artifact struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format"`
}

// HeadscaleVersion re-exports the pinned release from the leaf internal/versions
// so the Hub has one definition. The artifact manifest, the version handshake in
// internal/meshnet and the generated configuration all read the same constant; a
// drift test in this package fails if they ever disagree.
//
// The re-export deliberately does not name the adapter: internal/install stages
// a Headscale binary, it never talks to the control plane, and importing the
// meshnet domain here would pull a domain into the privileged installer for one
// string. Reading the leaf keeps the installer's dependency surface unchanged.
const HeadscaleVersion = versions.HeadscaleVersion

// CaddyVersion and KernelVersion are the two pinned release strings used by
// more than one table entry or by plan prose. HeadscaleVersion comes from the
// versions leaf. Building the download URL from the version keeps a bump from
// leaving a stale "v1.14.3" literal behind in the source column.
const (
	CaddyVersion  = "2.11.7"
	KernelVersion = node.KernelVersion
)

func caddySource(architecture string) string {
	return "https://github.com/caddyserver/caddy/releases/download/v" + CaddyVersion +
		"/caddy_" + CaddyVersion + "_linux_" + architecture + ".tar.gz"
}

func kernelSource(architecture string) string {
	return "https://github.com/SagerNet/sing-box/releases/download/v" + KernelVersion +
		"/sing-box-" + KernelVersion + "-linux-" + architecture + ".tar.gz"
}

// Digests copied from the upstream GitHub release asset SHA-256 metadata.
// No "latest" or user-supplied release URL is permitted in a host operation.
var artifacts = map[string][]Artifact{
	versions.ArchitectureAMD64: {
		{Component: "caddy", Version: CaddyVersion, Source: caddySource(versions.ArchitectureAMD64), SHA256: "727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b", Format: "tar.gz"},
		{Component: "headscale", Version: HeadscaleVersion, Source: "https://github.com/juanfont/headscale/releases/download/v" + HeadscaleVersion + "/headscale_" + HeadscaleVersion + "_linux_amd64", SHA256: "e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980", Format: "elf"},
	},
	versions.ArchitectureARM64: {
		{Component: "caddy", Version: CaddyVersion, Source: caddySource(versions.ArchitectureARM64), SHA256: "d8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42", Format: "tar.gz"},
		{Component: "headscale", Version: HeadscaleVersion, Source: "https://github.com/juanfont/headscale/releases/download/v" + HeadscaleVersion + "/headscale_" + HeadscaleVersion + "_linux_arm64", SHA256: "3afddd207b89ac22cfad4235cc163c6e538cc59ada139e7c0bf47640c5d9e945", Format: "elf"},
	},
}

// Node artifacts are kept separate from the Hub allowlist. Extending the
// shared verifier must not make a Node kernel acceptable to Hub installs.
var nodeArtifacts = map[string][]Artifact{
	versions.ArchitectureAMD64: {
		{Component: "sing-box", Version: KernelVersion, Source: kernelSource(versions.ArchitectureAMD64), SHA256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee", Format: "tar.gz"},
	},
	versions.ArchitectureARM64: {
		{Component: "sing-box", Version: KernelVersion, Source: kernelSource(versions.ArchitectureARM64), SHA256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e", Format: "tar.gz"},
	},
}

// meshmuxd is the executor itself. Until 12e publishes it on GitHub Releases it
// ships as a Hub-hosted dev build: a dev- version and a file:// or intranet
// https:// source, with SHA-256 as the only trust anchor. No dev build is
// published yet, so these digests pin no existing artifact: replace them with
// the published build's digest before serving an upgrade, until then
// verification fails closed rather than trusting an unpinned file.
var meshmuxdArtifacts = map[string][]Artifact{
	versions.ArchitectureAMD64: {
		{Component: "meshmuxd", Version: devBuildVersion, Source: devBuildSource(versions.ArchitectureAMD64), SHA256: "7f4b5db4d75b5ceea146a4c0f7d0f13598bb4d9e1d1e8cceedd9ad368c163035", Format: "elf"},
	},
	versions.ArchitectureARM64: {
		{Component: "meshmuxd", Version: devBuildVersion, Source: devBuildSource(versions.ArchitectureARM64), SHA256: "de695531ef06285e0bbdd4a12d24d05ef4a74b1e54e86390f2673030fca25b9a", Format: "elf"},
	},
}

// devBuildVersion and devBuildSource name the pre-release executor pin in one
// place: the version must carry the dev- prefix the manifest treats as a
// pre-release, and the source stays the Hub-hosted development directory until
// 12e publishes a GitHub release.
const devBuildVersion = "dev-20261023"

func devBuildSource(architecture string) string {
	return "file:///var/lib/meshmux/dev/meshmuxd-linux-" + architecture
}

func PinnedArtifacts(arch string) []Artifact {
	a := artifacts[arch]
	out := make([]Artifact, len(a))
	copy(out, a)
	return out
}

// PinnedMeshmuxd copies the executor pin so a caller cannot mutate the table.
func PinnedMeshmuxd(arch string) []Artifact {
	a := meshmuxdArtifacts[arch]
	out := make([]Artifact, len(a))
	copy(out, a)
	return out
}

func PinnedNodeArtifacts(arch string) []Artifact {
	a := nodeArtifacts[arch]
	out := make([]Artifact, len(a))
	copy(out, a)
	return out
}

// artifactDownloadTimeout is the one bound of a pinned-artifact download. It is
// the installer's own budget: a Hub install must not hang on a slow GitHub
// asset, and every download in this package shares it.
const artifactDownloadTimeout = 90 * time.Second

var validDigest = backup.DigestPattern

// VerifyFile checks exact byte content, not a filename, URL or upstream-provided header.
func VerifyFile(path string, expected string) error {
	if !validDigest.MatchString(expected) {
		return errors.New("ARTIFACT_DIGEST_INVALID")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ARTIFACT_UNAVAILABLE: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxInstallerFile {
		return errors.New("ARTIFACT_TYPE_OR_SIZE_INVALID")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return fmt.Errorf("ARTIFACT_READ_FAILED: %w", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("ARTIFACT_CHECKSUM_MISMATCH")
	}
	return nil
}

// DownloadVerified stages a fixed release into a 0700 scratch directory.
// A bad or incomplete download is deleted and never returned to a caller.
func DownloadVerified(ctx context.Context, client *http.Client, a Artifact, dir string) (string, error) {
	if !validDigest.MatchString(a.SHA256) || a.Source == "" {
		return "", errors.New("ARTIFACT_MANIFEST_INVALID")
	}
	found := trustedArtifact(a)
	if !found {
		return "", errors.New("ARTIFACT_SOURCE_UNTRUSTED")
	}
	if client == nil {
		client = &http.Client{Timeout: artifactDownloadTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Source, nil)
	if err != nil {
		return "", errors.New("ARTIFACT_REQUEST_INVALID")
	}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength > maxInstallerFile {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	f, err := os.CreateTemp(dir, ".meshmux-artifact-*")
	if err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, maxInstallerFile+1))
	if err != nil || n == 0 || n > maxInstallerFile {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("ARTIFACT_CHECKSUM_MISMATCH")
	}
	if err := f.Sync(); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	name := strings.ReplaceAll(a.Component+"-"+a.Version+"-"+filepath.Base(a.Source), "/", "_")
	final := filepath.Join(dir, name)
	if _, err := os.Lstat(final); err == nil {
		if err := VerifyFile(final, a.SHA256); err != nil {
			return "", errors.New("ARTIFACT_EXISTING_CONFLICT")
		}
		return final, nil
	} else if !os.IsNotExist(err) {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	// Atomic link avoids accidentally replacing an already staged artifact.
	if err := os.Link(f.Name(), final); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	return final, nil
}

func trustedArtifact(a Artifact) bool {
	for _, manifests := range []map[string][]Artifact{artifacts, nodeArtifacts} {
		for _, list := range manifests {
			for _, pinned := range list {
				if pinned == a {
					return true
				}
			}
		}
	}
	return false
}
