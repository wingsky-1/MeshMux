package node

import (
	"fmt"

	"github.com/wingsky-1/MeshMux/internal/node/protocol"
)

// KernelVersion is the only sing-box version accepted by the node contract.
const KernelVersion = protocol.SingBoxVersion

// KernelRelease pins the official sing-box archive and binary digests.
type KernelRelease struct {
	Version       string `json:"version"`
	SourceURL     string `json:"source_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

// kernelArchiveURL derives the official archive URL from the single pinned
// kernel version, so a version bump cannot leave the label and the download
// behind in two places.
func kernelArchiveURL(architecture string) string {
	return fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz",
		KernelVersion, KernelVersion, architecture)
}

// KernelReleaseFor returns the immutable release manifest for a supported
// Debian architecture. Unknown inputs never fall through to a floating release.
// The archive and binary digests are the independent pin: they are checked
// against the downloaded artifact, so they are deliberately literals per
// architecture rather than derived.
func KernelReleaseFor(architecture string) (KernelRelease, bool) {
	switch architecture {
	case "amd64":
		return KernelRelease{
			Version:       KernelVersion,
			SourceURL:     kernelArchiveURL(architecture),
			ArchiveSHA256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
			BinarySHA256:  "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93",
		}, true
	case "arm64":
		return KernelRelease{
			Version:       KernelVersion,
			SourceURL:     kernelArchiveURL(architecture),
			ArchiveSHA256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
			BinarySHA256:  "299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689",
		}, true
	default:
		return KernelRelease{}, false
	}
}
