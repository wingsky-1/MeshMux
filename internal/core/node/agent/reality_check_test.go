package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRealityNativeCheck accepts a rendered v2 candidate with the pinned
// native sing-box binary. It is opt-in and never touches a host service: the
// test only reads and executes the binary named by
// MESHMUX_REALITY_CHECK_BINARY after that binary's digest matches the pinned
// release for the test architecture.
//
// The candidate carries synthetic secrets (VLESS UUIDs and a freshly
// generated REALITY private key). No failure message prints the document, a
// credential, the key or the command output.
func TestRealityNativeCheck(t *testing.T) {
	binaryPath := os.Getenv("MESHMUX_REALITY_CHECK_BINARY")
	if binaryPath == "" {
		t.Skip("MESHMUX_REALITY_CHECK_BINARY is not set: set it to an absolute path of the pinned sing-box binary")
	}
	if !filepath.IsAbs(binaryPath) {
		t.Fatal("MESHMUX_REALITY_CHECK_BINARY must be an absolute path")
	}
	release, ok := KernelReleaseFor(runtime.GOARCH)
	if !ok {
		t.Fatalf("no pinned sing-box release for architecture %s", runtime.GOARCH)
	}
	info, err := os.Lstat(binaryPath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("MESHMUX_REALITY_CHECK_BINARY is not a regular file")
	}
	digest, err := nativeCheckSHA256(binaryPath)
	if err != nil {
		t.Fatal("could not hash MESHMUX_REALITY_CHECK_BINARY")
	}
	if digest != release.BinarySHA256 {
		t.Fatalf("binary SHA-256 does not match the pinned %s release", runtime.GOARCH)
	}

	// The version is checked before any candidate is handed to the binary.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(ctx, binaryPath, "version").Output()
	if err != nil {
		t.Fatal("pinned sing-box binary did not report its version")
	}
	fields := strings.Fields(strings.SplitN(string(versionOutput), "\n", 2)[0])
	if len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" || fields[2] != release.Version {
		t.Fatalf("binary version is not the pinned %s release", release.Version)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("could not generate the synthetic REALITY key")
	}
	reality := &RealityConfig{
		ServerName:      "handshake.example.invalid",
		HandshakeServer: "127.0.0.1",
		HandshakePort:   443,
		PrivateKey:      base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
		ShortID:         "0123456789abcdef",
	}
	users := []VLESSUser{
		{CredentialID: strings.Repeat("1", 32), UUID: "11111111-1111-4111-8111-111111111111"},
		{CredentialID: strings.Repeat("2", 32), UUID: "22222222-2222-4222-8222-222222222222"},
	}

	cases := []struct {
		name  string
		users []VLESSUser
	}{
		{name: "two users", users: users},
		{name: "after removing one user", users: users[:1]},
		{name: "after removing the last user", users: []VLESSUser{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := Candidate{
				NodeID:        strings.Repeat("a", 32),
				Role:          RoleEdge,
				Revision:      2,
				VLESSPort:     8443,
				KernelVersion: KernelVersion,
				Users:         testCase.users,
				Reality:       reality,
			}
			document, err := CompileCandidate(candidate)
			if err != nil {
				t.Fatalf("%s: candidate did not compile", testCase.name)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err = os.WriteFile(path, document, 0600); err != nil {
				t.Fatalf("%s: could not write the temporary candidate", testCase.name)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binaryPath, "check", "-c", path)
			command.Stdout = io.Discard
			command.Stderr = io.Discard
			if err := command.Run(); err != nil {
				t.Fatalf("%s: pinned sing-box rejected the candidate", testCase.name)
			}
		})
	}
}

// nativeCheckSHA256 streams the candidate binary through SHA-256 so the test
// does not hold the whole executable in memory.
func nativeCheckSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
