package node

import "github.com/wingsky-1/MeshMux/internal/node/protocol"

// KernelVersion is the only sing-box version accepted by the node contract.
const KernelVersion = protocol.SingBoxVersion

// KernelRelease pins the official sing-box archive and binary digests.
type KernelRelease struct {
	Version       string `json:"version"`
	SourceURL     string `json:"source_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

// KernelReleaseFor returns the immutable release manifest for a supported
// Debian architecture. Unknown inputs never fall through to a floating release.
func KernelReleaseFor(architecture string) (KernelRelease, bool) {
	switch architecture {
	case "amd64":
		return KernelRelease{
			Version:       KernelVersion,
			SourceURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz",
			ArchiveSHA256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
			BinarySHA256:  "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93",
		}, true
	case "arm64":
		return KernelRelease{
			Version:       KernelVersion,
			SourceURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-arm64.tar.gz",
			ArchiveSHA256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
			BinarySHA256:  "299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689",
		}, true
	default:
		return KernelRelease{}, false
	}
}
