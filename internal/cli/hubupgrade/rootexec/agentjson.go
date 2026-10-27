package rootexec

// The agent.json half of the coordinated Line re-pin (#11d Task 6, spec §5.6
// step 6④).
//
// The file is installer-owned (root:root 0600) and its bytes are what the
// co-located Agent boots from. A re-pin must rewrite exactly the same document
// shape as nodeManagedFiles, changing only agent_version/agent_sha256, or the
// next `--from-recorded-state` repair would see a file the installer would not
// have produced. RenderNodeAgentConfig is exported by internal/install for this
// single reason; the byte-equality test pins it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const agentConfigMaxBytes = 1 << 20

// renderAgentConfig is the one encoder this package may use. It delegates to
// the installer so the two writers cannot drift.
func renderAgentConfig(cfg node.Config) ([]byte, error) {
	body, err := install.RenderNodeAgentConfig(cfg)
	if err != nil {
		return nil, fail(codePrecheck, "the Agent configuration could not be rendered")
	}
	return body, nil
}

// readAgentConfig reads agent.json strictly: a private 0600 root-owned regular
// file, no unknown fields, no trailing document. It returns both the parsed
// configuration and the exact bytes, because the ledger's managed_files entry
// names the bytes, not a re-encoding of them.
func readAgentConfig(path string, expectedOwner int) (node.Config, []byte, error) {
	var cfg node.Config
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !statOwnedBy(info, expectedOwner) ||
		info.Size() < 1 || info.Size() > agentConfigMaxBytes {
		return cfg, nil, fail(codePrecheck, "agent.json is not a private root-owned 0600 file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return cfg, nil, fail(codePrecheck, "agent.json could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return cfg, nil, fail(codePrecheck, "agent.json changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, agentConfigMaxBytes+1))
	if err != nil || len(body) > agentConfigMaxBytes {
		return cfg, nil, fail(codePrecheck, "agent.json could not be read within its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, nil, fail(codePrecheck, "agent.json is not a strict Agent configuration")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cfg, nil, fail(codePrecheck, "agent.json carries trailing data")
	}
	return cfg, body, nil
}

func sha256Of(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
