package common

// The publish gate's kernel boundary. It is deliberately tiny and fixed:
//
//   - sing-box is the node kernel; its path is the installer-owned binary, and
//     the check runs the same argv the Agent runs ("check -c <file>").
//   - mihomo is the pinned subscription client. Its path comes from deployment
//     configuration because the Hub does not install a client kernel. A missing
//     binary is a refusal (PUBLISH_MIHOMO_UNAVAILABLE), never a skipped check.
//
// Both checks write the document to a private scratch file under the Hub data
// directory, run one argv without a shell and always remove the file. A
// document carries node secrets, so the file is 0600 and its content is never
// echoed into a response or a log line.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// gateDirName is the private scratch subdirectory the gate writes into. It is
// relative to the Hub data directory, so the documents never leave the private
// boundary.
const gateDirName = "publish-gate"

// PublishVerifier checks assembled documents with the pinned kernels. It is an
// interface so tests can inject a fixture verifier without a real binary; the
// production value is execPublishVerifier.
type PublishVerifier interface {
	CheckSingBox(ctx context.Context, document []byte) (string, error)
	CheckMihomo(ctx context.Context, document []byte) (string, error)
}

// PublishGateConfig is the deployment configuration of the gate. An empty
// MihomoPath disables the Mihomo gate only when a client layer is not being
// published; publishing a client layer without it fails with its own code.
type PublishGateConfig struct {
	SingBoxPath string
	MihomoPath  string
	Runner      node.CommandRunner
}

// execPublishVerifier runs the fixed kernel checks.
type execPublishVerifier struct {
	cfg  PublishGateConfig
	dir  string
	name func() (string, error)
}

func NewPublishVerifier(cfg PublishGateConfig, dir string) (PublishVerifier, error) {
	if strings.TrimSpace(cfg.SingBoxPath) == "" {
		return nil, errors.New(node.CodePublishSingBoxMissing + ": the pinned sing-box binary is not configured")
	}
	if err := executablePresent(cfg.SingBoxPath); err != nil {
		return nil, errors.New(node.CodePublishSingBoxMissing + ": the pinned sing-box binary is missing at the configured path")
	}
	if cfg.Runner == nil {
		cfg.Runner = node.ExecRunner{}
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New(CodePublishGate + ": the gate needs an absolute scratch directory")
	}
	return &execPublishVerifier{cfg: cfg, dir: dir, name: randomGateName}, nil
}

// executablePresent reports whether one configured gate binary is a regular,
// executable file. The path comes from deployment configuration only.
func executablePresent(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("absent")
	}
	return nil
}

// randomGateName returns one unpredictable scratch file suffix. Entropy
// failure is a refusal: a fixed name would let concurrent gate runs share a
// file and turn a failed check into an unverified pass.
func randomGateName() (string, error) {
	var b [8]byte
	// crypto/rand.Read crashes the process on a broken entropy source in Go
	// 1.27; io.ReadFull lets this gate report the failure instead.
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", errors.New(CodePublishGate + ": the gate scratch name could not be generated")
	}
	return hex.EncodeToString(b[:]), nil
}

func (v *execPublishVerifier) CheckSingBox(ctx context.Context, document []byte) (string, error) {
	path, cleanup, err := v.write(KernelSingBox, document)
	if err != nil {
		return "", err
	}
	defer cleanup()
	if err := node.CheckSingBoxDocument(ctx, v.cfg.Runner, v.cfg.SingBoxPath, path); err != nil {
		return "", err
	}
	return KernelSingBox + " " + node.SingBoxPublishVersion + " accepted the assembled document", nil
}

func (v *execPublishVerifier) CheckMihomo(ctx context.Context, document []byte) (string, error) {
	// Presence is checked per call, not once at startup: a binary removed after
	// the service started must fail the gate instead of validating nothing.
	if err := executablePresent(v.cfg.MihomoPath); err != nil {
		return "", errors.New(node.CodePublishMihomoMissing + ": the pinned mihomo binary is missing at the configured path")
	}
	path, cleanup, err := v.write(KernelMihomo, document)
	if err != nil {
		return "", err
	}
	defer cleanup()
	detail, err := node.CheckMihomoDocument(ctx, v.cfg.Runner, v.cfg.MihomoPath, path, v.dir)
	if err != nil {
		return detail, err
	}
	return KernelMihomo + " " + node.MihomoVersion + " accepted the assembled document", nil
}

// write stores one document in a 0600 scratch file inside the private gate
// directory. The file name is random, so two concurrent publishes never share
// a path, and the directory is created 0700.
func (v *execPublishVerifier) write(kernel string, document []byte) (string, func(), error) {
	if len(document) == 0 || len(document) > 4<<20 {
		return "", func() {}, errors.New(CodePublishGate + ": the document is empty or too large")
	}
	dir := filepath.Join(v.dir, gateDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", func() {}, errors.New(CodePublishGate + ": the gate scratch directory is unavailable")
	}
	ext := ".json"
	if kernel == KernelMihomo {
		ext = ".yaml"
	}
	name, err := v.name()
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, kernel+"-"+name+ext)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", func() {}, errors.New(CodePublishGate + ": the gate scratch file was not created")
	}
	cleanup := func() { _ = os.Remove(path) }
	if _, err = f.Write(document); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return "", func() {}, errors.New(CodePublishGate + ": the gate scratch file was not written")
	}
	return path, cleanup, nil
}

var _ PublishVerifier = (*execPublishVerifier)(nil)
