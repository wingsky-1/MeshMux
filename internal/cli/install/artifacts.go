package install

// The pinned artifact tables live in install/core; this file re-exports the
// table types and the verification entry points the upgrade lane reads.
//
// Nothing here is re-declared: the URL, version and digest for each pinned
// component have one definition, in install/core/artifacts.go.

import (
	"context"
	"net/http"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

type Artifact = core.Artifact

const (
	HeadscaleVersion = core.HeadscaleVersion
	CaddyVersion     = core.CaddyVersion
	KernelVersion    = core.KernelVersion
)

func PinnedArtifacts(arch string) []Artifact { return core.PinnedArtifacts(arch) }

func PinnedMeshmuxd(arch string) []Artifact { return core.PinnedMeshmuxd(arch) }

func PinnedNodeArtifacts(arch string) []Artifact { return core.PinnedNodeArtifacts(arch) }

// VerifyFile checks one file against a pinned SHA-256 digest.
func VerifyFile(path, expected string) error { return core.VerifyFile(path, expected) }

// DownloadVerified downloads one pinned artifact into dir and verifies it.
func DownloadVerified(ctx context.Context, client *http.Client, a Artifact, dir string) (string, error) {
	return core.DownloadVerified(ctx, client, a, dir)
}
