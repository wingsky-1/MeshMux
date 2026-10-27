package node

// Hub-side gate binaries. The publish gate asks the two client kernels to
// accept the assembled documents before anything is stored or staged:
//
//   - sing-box 1.14.3 is the node kernel and the pinned version of the Line
//     candidate, so the Line check and the publish check cannot disagree.
//   - Mihomo 1.19.32 is the pinned subscription client. It is not a node
//     kernel, so its path is deployment configuration instead of a fixed host
//     layout, and a missing binary is a refusal rather than a silent skip.
//
// The commands are fixed argv: "check -c <file>" and "-t -f <file> -d <dir>".
// No shell, no URL and no caller-supplied flag exists in either wrapper.

import (
	"context"
	"errors"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const (
	// MihomoVersion is the pinned Mihomo release. It must equal
	// scripts/ci-subscription-clients.sh MIHOMO_VERSION and the exporter
	// integration test, so an upgrade cannot silently leave the publish gate
	// checking a different kernel than CI.
	MihomoVersion = "1.19.32"
	// SingBoxPublishVersion documents the sing-box release the publish gate
	// checks against; it is the same pinned kernel the Line runs.
	SingBoxPublishVersion = KernelVersion
)

// Stable publish-gate codes. Only the code and a short output summary leave the
// verifier: the assembled documents carry node secrets, so their bytes and the
// full kernel output never reach a response or a log line.
const (
	// CodePublishCheckSingBox: sing-box refused the assembled candidate.
	CodePublishCheckSingBox = "PUBLISH_CHECK_SINGBOX_FAILED"
	// CodePublishCheckMihomo: Mihomo refused the assembled client document.
	CodePublishCheckMihomo = "PUBLISH_CHECK_MIHOMO_FAILED"
	// CodePublishSingBoxMissing: the pinned sing-box kernel is not available,
	// so the Line gate cannot run. It is a refusal, never a skipped check.
	CodePublishSingBoxMissing = "PUBLISH_SINGBOX_UNAVAILABLE"
	// CodePublishMihomoMissing: the pinned Mihomo binary is not available, so
	// the client gate cannot run. It is a refusal, never a skipped check.
	CodePublishMihomoMissing = "PUBLISH_MIHOMO_UNAVAILABLE"
	// CodePublishMihomoVersion: the binary at the configured path is not the
	// pinned release. A different kernel would validate a different schema.
	CodePublishMihomoVersion = "PUBLISH_MIHOMO_VERSION_INVALID"
)

// publishCheckOutputLines bounds the summary kept from one kernel run. A
// refusal needs a reason, not a transcript of a document.
const publishCheckOutputLines = 8

// CheckSingBoxDocument asks the pinned sing-box binary whether one assembled
// document is valid. The binary is the caller's verified kernel path; an empty
// path is a refusal so a gate can never be skipped by omission.
func CheckSingBoxDocument(ctx context.Context, runner CommandRunner, binary, configPath string) error {
	if strings.TrimSpace(binary) == "" || configPath == "" {
		return errors.New(CodePublishCheckSingBox + ": the check needs the pinned sing-box binary and a document path")
	}
	if _, err := runner.Run(ctx, binary, "check", "-c", configPath); err != nil {
		return errors.New(CodePublishCheckSingBox)
	}
	return nil
}

// CheckMihomoDocument asks the pinned Mihomo binary whether one assembled
// client document is valid. The version is proven first: `mihomo -v` must name
// MihomoVersion exactly, so a host that carries a different release cannot pass
// a document this build never validated.
func CheckMihomoDocument(ctx context.Context, runner CommandRunner, binary, configPath, dataDir string) (string, error) {
	if strings.TrimSpace(binary) == "" {
		return "", errors.New(CodePublishMihomoMissing + ": the pinned mihomo binary is not configured")
	}
	version, err := runner.Run(ctx, binary, "-v")
	if err != nil {
		return "", errors.New(CodePublishMihomoVersion + ": the binary is not the pinned mihomo " + MihomoVersion)
	}
	if _, ok := protocol.ReportedVersion(string(version), MihomoVersion); !ok {
		return "", errors.New(CodePublishMihomoVersion + ": the binary is not the pinned mihomo " + MihomoVersion)
	}
	if configPath == "" || dataDir == "" {
		return "", errors.New(CodePublishCheckMihomo + ": the check needs a document path and a scratch directory")
	}
	output, err := runner.Run(ctx, binary, "-t", "-f", configPath, "-d", dataDir)
	if err != nil {
		summary := summarizeCheckOutput(output)
		if summary == "" {
			return "", errors.New(CodePublishCheckMihomo)
		}
		return summary, errors.New(CodePublishCheckMihomo)
	}
	return "", nil
}

// summarizeCheckOutput keeps at most a few non-empty kernel lines, strips
// control characters and caps each line. A kernel refusal is useful as a
// reason; the document being checked must not be echoed back.
func summarizeCheckOutput(output []byte) string {
	lines := make([]string, 0, publishCheckOutputLines)
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, raw))
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		lines = append(lines, line)
		if len(lines) == publishCheckOutputLines {
			break
		}
	}
	return strings.Join(lines, " | ")
}
