package install

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/meshnet"
)

// upstreamDigests records the SHA-256 of the official release assets of each
// Headscale release this repository has deliberately pinned. It is the
// independent record the manifest is checked against: bumping HeadscaleVersion
// without adding the digests read from that release's GitHub asset metadata
// fails here, so a version bump cannot silently pair a new label with an old
// binary (or an unverified download).
var upstreamDigests = map[string]map[string]string{
	"0.29.5": {
		"amd64": "e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980",
		"arm64": "3afddd207b89ac22cfad4235cc163c6e538cc59ada139e7c0bf47640c5d9e945",
	},
}

// TestPinnedHeadscaleVersionMatchesAdapter is the drift guard between the
// installer's artifact manifest and the Headscale CLI adapter. The adapter's
// fixed argv table and its version handshake were written against one release;
// the manifest decides which binary is downloaded. If a bump changed only one of
// them, the handshake would refuse every change on a host the installer just
// provisioned, or the installer would stage a binary the adapter never verified.
//
// After the internal regroup (Task 6) the pin has three readers that must agree:
// the leaf internal/versions (which install re-exports and the artifact table
// reads), and the adapter's own literal in internal/meshnet (kept there so the
// adapter stays a zero-internal-import leaf). This test fails if a future edit
// reintroduces a third literal or forgets the matching digests.
func TestPinnedHeadscaleVersionMatchesAdapter(t *testing.T) {
	if HeadscaleVersion != versions.HeadscaleVersion {
		t.Fatalf("install.HeadscaleVersion = %q, versions = %q", HeadscaleVersion, versions.HeadscaleVersion)
	}
	if HeadscaleVersion != meshnet.HeadscaleVersion {
		t.Fatalf("install.HeadscaleVersion = %q, adapter = %q", HeadscaleVersion, meshnet.HeadscaleVersion)
	}
	// The host layout of the adapter and the installer must describe the same
	// binary and configuration file; otherwise the installer provisions one path
	// while the Hub runs another.
	if headscaleBinaryPath != meshnet.BinaryPath {
		t.Errorf("installer stages %q, adapter runs %q", headscaleBinaryPath, meshnet.BinaryPath)
	}
	if got := meshnet.ConfigPath; got != "/etc/meshmux/headscale.yaml" {
		t.Errorf("adapter config path = %q", got)
	}

	digests, recorded := upstreamDigests[meshnet.HeadscaleVersion]
	if !recorded {
		t.Fatalf("no upstream digests recorded for Headscale %q: read the release asset SHA-256 metadata and add them to upstreamDigests", meshnet.HeadscaleVersion)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		pinned := PinnedArtifacts(arch)
		var found bool
		for _, a := range pinned {
			if a.Component != "headscale" {
				continue
			}
			found = true
			if a.Version != meshnet.HeadscaleVersion {
				t.Errorf("%s headscale artifact version = %q, adapter = %q", arch, a.Version, meshnet.HeadscaleVersion)
			}
			// The download URL is derived from the same constant, so a literal
			// that disagrees with Version would stage a binary the handshake
			// rejects.
			wantPrefix := "https://github.com/juanfont/headscale/releases/download/v" + meshnet.HeadscaleVersion + "/headscale_" + meshnet.HeadscaleVersion + "_linux_" + arch
			if a.Source != wantPrefix {
				t.Errorf("%s headscale source = %q, want %q", arch, a.Source, wantPrefix)
			}
			if a.SHA256 != digests[arch] {
				t.Errorf("%s headscale digest = %q, want the recorded upstream %q", arch, a.SHA256, digests[arch])
			}
			if a.Format != "elf" {
				t.Errorf("%s headscale format = %q", arch, a.Format)
			}
		}
		if !found {
			t.Fatalf("%s has no pinned headscale artifact", arch)
		}
	}
}

// TestRenderedHeadscaleConfigStatesPinnedVersion keeps the generated
// configuration comment honest: an operator reading the applied file must see
// the release the adapter enforces, not a stale literal.
func TestRenderedHeadscaleConfigStatesPinnedVersion(t *testing.T) {
	c := Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"}
	files, err := candidateFiles(c, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	config := files["/etc/meshmux/headscale.yaml"]
	want := "# Headscale " + meshnet.HeadscaleVersion + ","
	if !strings.HasPrefix(config, want) {
		t.Fatalf("rendered Headscale config starts with %q, want %q", firstLine(config), want)
	}
	if meshnet.HeadscaleVersion != "0.29.5" && strings.Contains(config, "0.29.5") {
		t.Fatal("rendered Headscale config still contains the previous release literal")
	}
	// The adapter reads unix_socket from this file, so the generated value must
	// stay the fixed local socket of the Hub layout.
	if !strings.Contains(config, "unix_socket: /run/meshmux-headscale/headscale.sock") {
		t.Fatal("rendered Headscale config does not name the local unix socket")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
