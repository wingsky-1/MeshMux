package node

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// The synthetic secret set one v2 candidate carries. The values never leave
// this test process: every assertion only compares bytes, and a failure
// reports the name of the check that broke, never the secret that broke it.
const (
	v2SecretUUID      = "7f3a91c2-5d48-4b6e-8a1f-2c3d4e5f6a7b"
	v2SecretShortID   = "0123456789abcdef"
	v2SecretKeyMarker = "tnILRhHeIrUXzzvieuqqZkSh8BvSiMYsWeZJjyjP8fg"
)

// v2SecretMarkers names the secret markers without ever printing their
// values. A failure reports the marker name, not the marker.
var v2SecretMarkers = []struct {
	name  string
	value string
}{
	{"vless uuid", v2SecretUUID},
	{"reality private key", v2SecretKeyMarker},
	{"reality short id", v2SecretShortID},
}

func v2SecretCandidate(revision int64) CandidateDocument {
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Revision = revision
	candidate.Users = []VLESSUser{{
		CredentialID: strings.Repeat("7", 32),
		UUID:         v2SecretUUID,
	}}
	candidate.Reality = &RealityConfig{
		ServerName:      "www.example.invalid",
		HandshakeServer: "handshake.example.invalid",
		HandshakePort:   443,
		PrivateKey:      v2SecretKeyMarker,
		ShortID:         v2SecretShortID,
	}
	return NewCandidateDocument(candidate)
}

// TestReadbackEvidenceCarriesNoSecret pins that the readback detail stays
// evidence only. It reports the active revision and the configuration
// digest, never a UUID, a private key or a short id.
func TestReadbackEvidenceCarriesNoSecret(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	document := v2SecretCandidate(7)
	documentData, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	config, err := CompileCandidate(document.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rooted(root, ActiveCandidatePath), documentData, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rooted(root, ActiveConfigPath), config, 0640); err != nil {
		t.Fatal(err)
	}
	readback, err := ReadbackLocal(context.Background(), cfg, root, runner)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := json.Marshal(readback)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range v2SecretMarkers {
		if bytes.Contains(detail, []byte(marker.value)) {
			t.Fatalf("readback detail leaked the %s", marker.name)
		}
	}
	for _, field := range []string{"credential_id", "private_key", "short_id"} {
		if bytes.Contains(detail, []byte(field)) {
			t.Fatalf("readback detail leaked the %s field", field)
		}
	}
	if !bytes.Contains(detail, []byte("config_sha256")) {
		t.Fatal("readback detail lost the configuration digest")
	}
}

// TestApplyKeepsSecretsInsideThePrivateBoundary pins the file modes of every
// copy of a v2 configuration: the candidate document and the staged files
// stay 0600, the active configuration stays 0640 for the kernel account, and
// no copy is group or world readable.
func TestApplyKeepsSecretsInsideThePrivateBoundary(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: v2SecretCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	result := runtime.Execute(context.Background(),
		task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9))
	if result.Status != "healthy" {
		t.Fatalf("apply status = %q, error = %q", result.Status, result.ErrorCode)
	}

	// The staged copies are written by the stage and the apply transaction.
	// Both stages must leave them private, so the modes are checked for the
	// revision that was actually staged.
	checks := []struct {
		name string
		path string
		want os.FileMode
	}{
		{"active candidate", rooted(root, ActiveCandidatePath), 0600},
		{"staged candidate", stagedCandidatePath(root, 9), 0600},
		{"staged config", stagedConfigPath(root, 9), 0600},
		{"active config", rooted(root, ActiveConfigPath), 0640},
	}
	for _, check := range checks {
		info, err := os.Lstat(check.path)
		if err != nil {
			t.Fatalf("the %s file is missing", check.name)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("the %s file is not regular", check.name)
		}
		if got := info.Mode().Perm(); got != check.want {
			t.Fatalf("the %s file has mode %o, want %o", check.name, got, check.want)
		}
		if check.want == 0600 && info.Mode().Perm()&0077 != 0 {
			t.Fatalf("the %s file is group or world readable", check.name)
		}
	}

	// The staged copy carries the candidate secrets and stays private to the
	// Agent; the active copy carries them for the kernel account only.
	for _, check := range checks[1:] {
		content, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatalf("the %s file is unreadable", check.name)
		}
		for _, marker := range v2SecretMarkers {
			if !bytes.Contains(content, []byte(marker.value)) {
				t.Fatalf("the %s file does not carry the %s", check.name, marker.name)
			}
		}
	}
}

// TestRuntimeLogsCarryNoSecret pins that a full apply cycle never writes a
// credential or a private key into the Agent log. The log is inspected for
// the secret markers only; it is never printed.
func TestRuntimeLogsCarryNoSecret(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	controller := &runtimeTestController{candidate: v2SecretCandidate(9)}
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := runtime.Execute(context.Background(),
		task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9))
	if result.Status != "healthy" {
		t.Fatalf("apply status = %q, error = %q", result.Status, result.ErrorCode)
	}
	for _, marker := range v2SecretMarkers {
		if bytes.Contains(log.Bytes(), []byte(marker.value)) {
			t.Fatalf("the agent log leaked the %s", marker.name)
		}
	}
}

// TestCandidateBodyBoundAccommodatesTheMaximumUserSet pins that the Hub
// transport bound accepts the largest legal candidate document and stays a
// real bound instead of an unbounded buffer.
func TestCandidateBodyBoundAccommodatesTheMaximumUserSet(t *testing.T) {
	body, err := json.Marshal(NewCandidateDocument(v2Candidate(largeV2UserSet()...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > maxConfigBody {
		t.Fatalf("the maximum candidate document is %d bytes, want <= %d", len(body), maxConfigBody)
	}
	if maxConfigBody < 1024*1024 {
		t.Fatalf("the candidate body bound is %d, want at least 1 MiB", maxConfigBody)
	}
}

// TestStagedConfigPathStaysInsideTheAgentDirectory pins that the staged
// copies of a secret configuration live under the private Agent directory
// and never under a world readable path.
func TestStagedConfigPathStaysInsideTheAgentDirectory(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		stagedCandidatePath(root, 9),
		stagedConfigPath(root, 9),
	} {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(relative, strings.TrimPrefix(stagedDir, "/")+string(filepath.Separator)) {
			t.Fatalf("a staged path is outside the Agent staged directory")
		}
	}
}
