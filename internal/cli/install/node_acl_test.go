package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// The Out source allowlist is retired: the installer now accepts only the
// neutral, rule-free inet meshmux_out table and rewrites a legacy guard. These
// tests pin that contract through the same functions the install path uses.

type nftStubRunner struct {
	output []byte
	err    error
	calls  []string
}

func (r *nftStubRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "nft" {
		return r.output, r.err
	}
	return nil, nil
}

func neutralNFTDocument() string {
	return `{"nftables":[` +
		`{"table":{"family":"inet","name":"meshmux_out"}},` +
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}]}`
}

func legacyNFTDocument() string {
	return `{"nftables":[` +
		`{"table":{"family":"inet","name":"meshmux_out"}},` +
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}},` +
		`{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"203.0.113.7"}},` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"accept":null}]}}]}`
}

// writeOutACLFixture builds one isolated Out root whose active candidate and
// config make nodeValidLKG exercise its ACL branch, and writes the given ACL
// script at the managed path.
func writeOutACLFixture(t *testing.T, acl []byte) (string, node.Config, node.Candidate) {
	t.Helper()
	root := t.TempDir()
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleOut, VLESSPort: 8443, SSHPort: 2222,
	}
	cand := node.Candidate{
		NodeID: cfg.NodeID, Role: node.RoleOut, Revision: 1,
		VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
	}
	if err := os.MkdirAll(rooted(root, nodeAgentStateDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rooted(root, nodeKernelDataDir), 0750); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(node.NewCandidateDocument(cand))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(root, node.ActiveCandidatePath), document, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rooted(root, node.ActiveCandidatePath), 0600); err != nil {
		t.Fatal(err)
	}
	compiled, err := node.CompileCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBytesAtomic(rooted(root, node.ActiveConfigPath), compiled, 0640); err != nil {
		t.Fatal(err)
	}
	aclPath := rooted(root, node.ACLPath)
	if err := os.WriteFile(aclPath, acl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
		t.Fatal(err)
	}
	return root, cfg, cand
}

// TestNodeACLReadbackRequiresTheRetiredNeutralTable pins the installer readback:
// the live table must be the MeshMux table and input chain with no rule. A
// legacy accept or dport drop would filter clients the Out link key admits.
func TestNodeACLReadbackRequiresTheRetiredNeutralTable(t *testing.T) {
	neutral, err := node.CompileACL(node.Candidate{Role: node.RoleOut, NodeID: strings.Repeat("a", 32), Revision: 1, VLESSPort: 8443, KernelVersion: node.KernelVersion}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, cfg, cand := writeOutACLFixture(t, neutral)

	ok := &nftStubRunner{output: []byte(neutralNFTDocument())}
	if err := verifyNodeACLReadback(context.Background(), ok, root, cfg, cand, 8443); err != nil {
		t.Fatalf("neutral table rejected: %v", err)
	}

	cases := []struct {
		name   string
		output string
		err    error
	}{
		{"legacy allowlist", legacyNFTDocument(), nil},
		{"wrong priority", strings.Replace(neutralNFTDocument(), `"prio":-10`, `"prio":0`, 1), nil},
		{"foreign table", strings.Replace(neutralNFTDocument(), `"meshmux_out"`, `"other"`, 1), nil},
		{"missing chain", `{"nftables":[{"table":{"family":"inet","name":"meshmux_out"}}]}`, nil},
		{"nft failed", "", errors.New("exit")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &nftStubRunner{output: []byte(tc.output), err: tc.err}
			err := verifyNodeACLReadback(context.Background(), runner, root, cfg, cand, 8443)
			if err == nil || !strings.Contains(err.Error(), "OUT_ACL_READBACK_FAILED") {
				t.Fatalf("bad table = %v, want OUT_ACL_READBACK_FAILED", err)
			}
		})
	}

	// A legacy allowlist file is not LKG, so repair must rewrite it.
	legacy, err := node.CompileACL(cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(root, node.ACLPath), append(legacy, []byte("legacy\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(root, cfg); ok {
		t.Fatal("a non-canonical ACL was accepted as LKG")
	}
}

// TestNodeLKGAcceptsOnlyTheNeutralOutACL pins the LKG half: the neutral render
// is a valid last-known-good data plane, a legacy allowlist render is not.
func TestNodeLKGAcceptsOnlyTheNeutralOutACL(t *testing.T) {
	neutral, err := node.CompileACL(node.Candidate{Role: node.RoleOut, NodeID: strings.Repeat("a", 32), Revision: 1, VLESSPort: 8443, KernelVersion: node.KernelVersion}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, cfg, _ := writeOutACLFixture(t, neutral)
	if _, ok := nodeValidLKG(root, cfg); !ok {
		t.Fatal("neutral Out ACL was not accepted as LKG")
	}
	legacy, err := node.CompileACL(node.Candidate{Role: node.RoleOut, NodeID: cfg.NodeID, Revision: 1, VLESSPort: 8443, KernelVersion: node.KernelVersion}, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(root, node.ACLPath), append(legacy, []byte("# legacy\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(root, cfg); ok {
		t.Fatal("a legacy ACL render was accepted as LKG")
	}
}

// TestNodeRepairRewritesLegacyOutACL drives the repair path end to end: a
// first install writes the neutral table, a stale legacy file is replaced, and
// the neutral file survives a later repair unchanged.
func TestNodeRepairRewritesLegacyOutACL(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	aclPath := rooted(f.root, node.ACLPath)
	neutral, err := os.ReadFile(aclPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := node.CompileACL(f.candidate.Candidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(neutral) != string(expected) {
		t.Fatalf("first install did not write the neutral ACL:\n%s", neutral)
	}
	if err := os.WriteFile(aclPath, []byte("flush ruleset\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("foreign ACL was accepted as LKG")
	}
	if _, err := f.install(t, true, ""); err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	current, err := os.ReadFile(aclPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(expected) {
		t.Fatalf("repair did not rewrite the neutral ACL:\n%s", current)
	}
}

func mustCompileCandidate(t *testing.T, candidate node.Candidate) []byte {
	t.Helper()
	compiled, err := node.CompileCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// writeNodeAppliedState rewrites the Agent runtime state. allowed is retired
// and written only so a fixture can emulate a state file from an older Agent.
func writeNodeAppliedState(t *testing.T, root string, cfg node.Config, allowed []string) {
	t.Helper()
	type state struct {
		Schema         string    `json:"schema"`
		NodeID         string    `json:"node_id"`
		Role           node.Role `json:"role"`
		Revision       int64     `json:"revision"`
		LKGDigest      string    `json:"lkg_digest"`
		AllowedSources []string  `json:"allowed_sources,omitempty"`
	}
	body, err := json.Marshal(state{
		Schema: "meshmux-node-state/v1", NodeID: cfg.NodeID, Role: cfg.Role,
		Revision: 1, LKGDigest: strings.Repeat("d", 64), AllowedSources: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := rooted(root, node.RuntimeStatePath)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}
