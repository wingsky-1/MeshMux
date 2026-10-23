package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// fixtureNodeConfig is the recorded Agent configuration a handoff reuses; the
// real one is read from /etc/meshmux/agent.json.
func fixtureNodeConfig() node.Config {
	return node.Config{HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222}
}

func fixtureInstalled() (node.Config, error) { return fixtureNodeConfig(), nil }

// handoffRunner records the fixed argv of the handoff and lets a test observe
// the filesystem at the exact moment the new package would run.
type handoffRunner struct {
	calls  [][]string
	atExec func()
}

func (r *handoffRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.atExec != nil {
		r.atExec()
	}
	return nil, nil
}

// TestHandoffBacksUpBeforeMutating is the rollback-pointer property: the
// pointer that names the release being replaced exists before the new package
// runs, the handoff execs exactly one fixed argv, restarts the Agent, and
// returns the digest it read back.
func TestHandoffBacksUpBeforeMutating(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	runner := &handoffRunner{}
	var pointer backupPointer
	checked := false
	runner.atExec = func() {
		if checked {
			return
		}
		checked = true
		data, err := os.ReadFile(filepath.Join(cfg.WorkDir, "backup-"+cfg.Target+".json"))
		if err != nil {
			t.Fatalf("backup pointer missing before the handoff exec: %v", err)
		}
		if err := json.Unmarshal(data, &pointer); err != nil {
			t.Fatalf("backup pointer is not JSON: %v", err)
		}
	}

	result, err := Run(context.Background(), cfg, runner)
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	want := []string{result.VerifiedPath, "install", "edge", "--hub", "https://hub.example.invalid",
		"--node", strings.Repeat("a", 32), "--vless-port", "8443", "--ssh-port", "2222",
		"--operation-id", cfg.OperationID, "--yes", "--repair", "--non-interactive"}
	if len(runner.calls) != 2 || strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("calls = %q, want %q then the Agent restart", runner.calls, want)
	}
	if got := runner.calls[1]; len(got) != 3 || got[0] != "/usr/bin/systemctl" ||
		got[1] != "restart" || got[2] != node.AgentUnit {
		t.Fatalf("restart argv = %q", got)
	}
	if pointer.OperationID != cfg.OperationID || pointer.FromVersion != cfg.CurrentVersion ||
		pointer.Target != cfg.Target || pointer.ManifestSHA256 != cfg.ManifestSHA256 ||
		pointer.PackageSHA256 != shaOf(pkg) {
		t.Fatalf("pointer = %+v", pointer)
	}
	if result.BackupPointer == "" || result.ReadbackDigest != shaOf(pkg) {
		t.Fatalf("result = %+v", result)
	}
}

// TestHandoffRefusesSchemaMismatch pins the stored-policy gate and the route
// policy revision rule the target gate does not check. The revision case is
// driven through Run so the gate is proven wired, not merely present.
func TestHandoffRefusesSchemaMismatch(t *testing.T) {
	base := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	for _, tc := range []struct {
		name   string
		code   string
		mutate func(*upgrade.Manifest)
	}{
		{"foreign policy schema", "UPDATE_SCHEMA_INCOMPATIBLE", func(m *upgrade.Manifest) {
			m.PolicySchema = upgrade.PolicySchema + 1
		}},
		{"unknown policy layer", "MANIFEST_POLICY_REVISION_INVALID", func(m *upgrade.Manifest) {
			m.RoutePolicyRevisions = map[string]int64{"mesh": 1}
		}},
		{"zero policy revision", "MANIFEST_POLICY_REVISION_INVALID", func(m *upgrade.Manifest) {
			m.RoutePolicyRevisions = map[string]int64{"client": 0}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			tc.mutate(&m)
			if code := codeOf(compatGate(m)); code != tc.code {
				t.Fatalf("code = %q, want %q", code, tc.code)
			}
		})
	}

	// The same rule through Run: the gate is wired before the package is
	// fetched, so a target with a foreign revision is refused with no exec.
	pkg := []byte("fixture package\n")
	m := fixtureManifest(t, pkg, shaOf(pkg))
	m.RoutePolicyRevisions = map[string]int64{"mesh": 1}
	runner := &fixtureRunner{}
	if _, err := Run(context.Background(), fixtureConfig(t, m), runner); codeOf(err) != "MANIFEST_POLICY_REVISION_INVALID" {
		t.Fatalf("code = %q, want MANIFEST_POLICY_REVISION_INVALID (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused handoff executed %v", runner.calls)
	}
}

// TestUpdatePreflightSpace is the disk-full refusal: the fixture reports less
// space than the handoff needs, so nothing is fetched, nothing runs, and the
// previous install is untouched.
func TestUpdatePreflightSpace(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	cfg.Space = func(string, uint64) error { return errors.New("fixture: no space") }
	runner := &fixtureRunner{}
	result, err := Run(context.Background(), cfg, runner)
	if code := codeOf(err); code != "UPDATE_NO_SPACE" {
		t.Fatalf("code = %q, want UPDATE_NO_SPACE (err %v)", code, err)
	}
	if len(runner.calls) != 0 || result.BackupPointer != "" || result.VerifiedPath != "" {
		t.Fatalf("refused handoff mutated: calls %q, result %+v", runner.calls, result)
	}
	if entries, readErr := os.ReadDir(cfg.WorkDir); readErr == nil && len(entries) != 0 {
		t.Fatalf("refused handoff left files behind: %v", entries)
	}
}

// TestHandoffRefusesNonAdjacentTarget is the one-release-at-a-time rule: a
// target two releases ahead of the running build is refused before any exec.
func TestHandoffRefusesNonAdjacentTarget(t *testing.T) {
	pkg := []byte("fixture package\n")
	m := fixtureManifest(t, pkg, shaOf(pkg))
	m.Version = "1.0.2"
	cfg := fixtureConfig(t, m)
	cfg.Target = "1.0.2"
	cfg.CurrentVersion, cfg.Releases = "1.0.0", []string{"1.0.0", "1.0.1", "1.0.2"}
	runner := &fixtureRunner{}
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "UPGRADE_NOT_ADJACENT" {
		t.Fatalf("code = %q, want UPGRADE_NOT_ADJACENT (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused handoff executed %v", runner.calls)
	}
}

// TestHandoffRequiresMatchingReadback is the receipt rule: an Agent that comes
// back reporting another digest is a failure, never an applied upgrade.
func TestHandoffRequiresMatchingReadback(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	cfg.Readback = func() (string, error) { return strings.Repeat("f", 64), nil }
	result, err := Run(context.Background(), cfg, &fixtureRunner{})
	if code := codeOf(err); code != "UPDATE_READBACK_MISMATCH" {
		t.Fatalf("code = %q, want UPDATE_READBACK_MISMATCH (err %v)", code, err)
	}
	if result.ReadbackDigest != "" || result.BackupPointer == "" {
		t.Fatalf("result = %+v", result)
	}
}

// TestHandoffRefusesUnreadableAgentConfig pins the pre-mutation ordering of the
// host seam: no install runs when the recorded configuration cannot be read.
func TestHandoffRefusesUnreadableAgentConfig(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	cfg.NodeConfig = func() (node.Config, error) { return node.Config{}, errors.New("fixture: missing") }
	runner := &fixtureRunner{}
	if _, err := Run(context.Background(), cfg, runner); codeOf(err) != "AGENT_CONFIG_UNAVAILABLE" {
		t.Fatalf("code = %q, want AGENT_CONFIG_UNAVAILABLE (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused handoff executed %v", runner.calls)
	}
}
