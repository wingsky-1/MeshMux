package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// aclJSONWithAccepts renders the `nft -j` document of the fixture's Out guard
// with one accept rule per source, before the two drops.
func aclJSONWithAccepts(port int, sources ...string) string {
	var rules []string
	rules = append(rules,
		`{"table":{"family":"inet","name":"meshmux_out"}}`,
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}`)
	for _, source := range sources {
		family := "ip"
		if strings.Contains(source, ":") {
			family = "ip6"
		}
		right := `"` + source + `"`
		if address, bits, ok := strings.Cut(source, "/"); ok {
			right = `{"prefix":{"addr":"` + address + `","len":` + bits + `}}`
		}
		rules = append(rules, `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[`+
			`{"match":{"op":"==","left":{"payload":{"protocol":"`+family+`","field":"saddr"}},"right":`+right+`}},`+
			`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":`+strconv.Itoa(port)+`}},`+
			`{"accept":null}]}}`)
	}
	for _, proto := range []string{"tcp", "udp"} {
		rules = append(rules, `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[`+
			`{"match":{"op":"==","left":{"payload":{"protocol":"`+proto+`","field":"dport"}},"right":`+strconv.Itoa(port)+`}},`+
			`{"drop":null}]}}`)
	}
	return `{"nftables":[` + strings.Join(rules, ",") + `]}`
}

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

// aclFixture is one isolated Out host root with a managed ACL file and,
// optionally, an Agent runtime state that records an applied allowlist.
type aclFixture struct {
	root    string
	cfg     node.Config
	cand    node.Candidate
	aclPath string
}

func newACLFixture(t *testing.T) *aclFixture {
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
	// The active candidate and config make nodeValidLKG exercise the ACL branch
	// instead of returning early, so the LKG assertions below are meaningful.
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
	return &aclFixture{root: root, cfg: cfg, cand: cand, aclPath: rooted(root, node.ACLPath)}
}

func (f *aclFixture) writeACL(t *testing.T, allowed []string) {
	t.Helper()
	acl, err := node.CompileACL(f.cand, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.aclPath, acl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.aclPath, 0600); err != nil {
		t.Fatal(err)
	}
}

// writeAppliedState writes the Agent runtime state that records the applied
// allowlist. This is the installer's only trusted anchor for what the Hub
// authorized.
func (f *aclFixture) writeAppliedState(t *testing.T, allowed []string) {
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
		Schema: "meshmux-node-state/v1", NodeID: f.cfg.NodeID, Role: f.cfg.Role,
		Revision: 1, LKGDigest: strings.Repeat("d", 64), AllowedSources: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := rooted(f.root, node.RuntimeStatePath)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestNodeACLReadbackAnchorsOnAppliedState pins the installer assert against the
// trusted anchor: the live table must equal the allowlist state.json records as
// applied, and must still be a complete guard. The managed ACL file is never the
// expectation.
func TestNodeACLReadbackAnchorsOnAppliedState(t *testing.T) {
	f := newACLFixture(t)
	f.writeACL(t, []string{"203.0.113.7"})
	f.writeAppliedState(t, []string{"203.0.113.7"})

	ok := &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32"))}
	if err := verifyNodeACLReadback(context.Background(), ok, f.root, f.cfg, f.cand, 8443); err != nil {
		t.Fatalf("exact observed guard rejected: %v", err)
	}

	cases := []struct {
		name   string
		output string
		err    error
	}{
		{"policy accept only", `{"nftables":[{"table":{"family":"inet","name":"meshmux_out"}},{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}]}`, nil},
		{"extra accept", aclJSONWithAccepts(8443, "203.0.113.7/32", "198.51.100.0/24"), nil},
		{"missing accept", aclJSONWithAccepts(8443), nil},
		{"missing udp drop", strings.Replace(aclJSONWithAccepts(8443, "203.0.113.7/32"), `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":8443}},{"drop":null}]}}`, "", 1), nil},
		{"wrong priority", strings.Replace(aclJSONWithAccepts(8443, "203.0.113.7/32"), `"prio":-10`, `"prio":0`, 1), nil},
		{"foreign table", strings.Replace(aclJSONWithAccepts(8443, "203.0.113.7/32"), `"meshmux_out"`, `"other"`, 1), nil},
		{"nft failed", "", errors.New("exit")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &nftStubRunner{output: []byte(tc.output), err: tc.err}
			err := verifyNodeACLReadback(context.Background(), runner, f.root, f.cfg, f.cand, 8443)
			if err == nil || !strings.Contains(err.Error(), "OUT_ACL_READBACK_FAILED") {
				t.Fatalf("bad guard = %v, want OUT_ACL_READBACK_FAILED", err)
			}
		})
	}
}

// TestNodeACLReadbackRejectsLateInjectedAccept is the fail-open regression: an
// accept appended after the sorted sources still re-renders to the same bytes
// it was parsed from, so a file-derived expectation would accept it. Anchoring
// on state.json must reject it instead.
func TestNodeACLReadbackRejectsLateInjectedAccept(t *testing.T) {
	f := newACLFixture(t)
	f.writeACL(t, []string{"203.0.113.7"})
	f.writeAppliedState(t, []string{"203.0.113.7"})

	// 240.0.0.0/32 sorts after 203.0.113.7, so appending it to the file keeps
	// the file a canonical render of a *different*, wider allowlist.
	base, err := node.CompileACL(f.cand, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(base),
		"    tcp dport 8443 drop",
		"    ip saddr 240.0.0.0/32 tcp dport 8443 accept\n    tcp dport 8443 drop", 1)
	if _, err := node.ParseACLAllowed(f.cand, []byte(tampered)); err != nil {
		t.Fatalf("tampered file is not even a canonical render: %v", err)
	}
	if err := os.WriteFile(f.aclPath, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}

	// The live table carries the injected source: the readback must fail.
	runner := &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32", "240.0.0.0/32"))}
	if err := verifyNodeACLReadback(context.Background(), runner, f.root, f.cfg, f.cand, 8443); err == nil ||
		!strings.Contains(err.Error(), "OUT_ACL_READBACK_FAILED") {
		t.Fatalf("late-injected accept accepted = %v, want OUT_ACL_READBACK_FAILED", err)
	}

	// The same file is also not LKG, and repair must replace it with the
	// default-deny guard rather than persist the tampering.
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("late-injected accept was accepted as LKG")
	}
	if err := installNodeDynamic(context.Background(), NodeApplyOptions{Root: f.root, Runner: &nftStubRunner{}},
		node.NewCandidateDocument(f.cand), mustCompileCandidate(t, f.cand), node.RoleOut, true); err != nil {
		t.Fatalf("dynamic install failed: %v", err)
	}
	replaced, err := os.ReadFile(f.aclPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := node.CompileACL(f.cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(replaced) != string(expected) {
		t.Fatalf("repair persisted the tampered ACL:\n%s", replaced)
	}
}

// TestNodeACLReadbackWithoutStateAssertsShapeOnly pins the degraded path: with
// no state.json there is no trusted authorization record, so only the guard
// shape and both drops are asserted and the accept set is deliberately not
// compared. An injected accept is therefore not evidence of a pass on its own —
// it just cannot be distinguished without a trusted anchor.
//
// The extra-accept case below is the discrimination test for that contract: a
// table whose accept set differs from any plausible constant must still pass the
// shape-only path. That is what makes "no set assertion happened here" a real
// claim rather than an untested assumption.
func TestNodeACLReadbackWithoutStateAssertsShapeOnly(t *testing.T) {
	f := newACLFixture(t)
	f.writeACL(t, []string{"203.0.113.7"})

	// Shape is complete, so the shape-only readback passes even though the
	// file carries an accept nobody recorded.
	runner := &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32"))}
	if err := verifyNodeACLReadback(context.Background(), runner, f.root, f.cfg, f.cand, 8443); err != nil {
		t.Fatalf("shape-only readback rejected a complete guard: %v", err)
	}
	// A different accept set also passes: with no recorded anchor the installer
	// cannot assert a set, and must not pretend to. The Hub's own readback task
	// (which carries allowed_sources) is what proves the set later.
	runner = &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32", "240.0.0.0/32"))}
	if err := verifyNodeACLReadback(context.Background(), runner, f.root, f.cfg, f.cand, 8443); err != nil {
		t.Fatalf("shape-only readback asserted an accept set it has no record for: %v", err)
	}
	// Shape is still required: a chain without the drops fails.
	runner = &nftStubRunner{output: []byte(`{"nftables":[` +
		`{"table":{"family":"inet","name":"meshmux_out"}},` +
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}]}`)}
	if err := verifyNodeACLReadback(context.Background(), runner, f.root, f.cfg, f.cand, 8443); err == nil ||
		!strings.Contains(err.Error(), "OUT_ACL_READBACK_FAILED") {
		t.Fatalf("shape-only readback accepted a guard without drops: %v", err)
	}
	// An unverifiable ACL is not LKG, so repair rewrites default deny rather
	// than trusting a file with no recorded authorization.
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("ACL without a recorded allowlist was accepted as LKG")
	}
}

// TestNodeRepairPreservesAuthorizedACL pins the repair contract: when state.json
// records exactly the allowlist the ACL file renders, the file is LKG and
// installNodeDynamic must not rewrite it to the empty default-deny render
// (which would revoke every authorized Line).
func TestNodeRepairPreservesAuthorizedACL(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	aclPath := rooted(f.root, node.ACLPath)
	authorized := []string{"203.0.113.7", "2001:db8::/32"}
	acl, err := node.CompileACL(f.candidate.Candidate(), authorized)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclPath, acl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
		t.Fatal(err)
	}
	writeNodeAppliedState(t, f.root, f.cfg, authorized)
	digest, ok := nodeValidLKG(f.root, f.cfg)
	if !ok {
		t.Fatal("authorized ACL is not accepted as LKG")
	}
	f.opts.Readback = func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
		return node.Readback{
			Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 7,
			ConfigSHA256: digest, LocalActive: true, OutDefaultDeny: true,
		}, nil
	}
	f.runner.calls = nil
	if _, err := f.install(t, true, ""); err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	current, err := os.ReadFile(aclPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(acl) {
		t.Fatalf("repair rewrote the authorized ACL:\n%s", current)
	}
}

// TestNodeInstallReplacesForeignACL pins the other direction: an ACL file that
// is not a canonical MeshMux render is replaced by the default-deny script, so
// a corrupted file cannot survive a repair as authorization.
func TestNodeInstallReplacesForeignACL(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	aclPath := rooted(f.root, node.ACLPath)
	if err := os.WriteFile(aclPath, []byte("flush ruleset\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
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
	expected, err := node.CompileACL(f.candidate.Candidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(expected) {
		t.Fatalf("foreign ACL survived repair:\n%s", current)
	}
}

// TestNodeFreshInstallStartsDefaultDeny pins that a first install never adopts
// an existing allowlist: nothing is authorized before the Hub binds a Line, so
// even a canonical ACL carrying sources is reset to default deny. (A real
// fresh install also refuses a stray managed file without a ledger; this calls
// the dynamic install step directly to pin the ACL decision itself.)
func TestNodeFreshInstallStartsDefaultDeny(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	dir := rooted(f.root, nodeAgentStateDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stale, err := node.CompileACL(f.candidate.Candidate(), []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	aclPath := rooted(f.root, node.ACLPath)
	if err := os.WriteFile(aclPath, stale, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installNodeDynamic(context.Background(), f.opts, f.candidate, mustCompileCandidate(t, f.candidate.Candidate()), node.RoleOut, false); err != nil {
		t.Fatalf("dynamic install failed: %v", err)
	}
	current, err := os.ReadFile(aclPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := node.CompileACL(f.candidate.Candidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(expected) {
		t.Fatalf("fresh install kept a pre-existing allowlist:\n%s", current)
	}
}

// TestNodeRepairRejectsLateInjectedAcceptInPreservePath pins the third anchor:
// installNodeDynamic's repair-preserve path must compare the file against the
// recorded applied allowlist, so a canonical-looking file with an appended
// accept is replaced by default deny instead of being preserved and re-applied.
func TestNodeRepairRejectsLateInjectedAcceptInPreservePath(t *testing.T) {
	f := newACLFixture(t)
	f.writeAppliedState(t, []string{"203.0.113.7"})
	base, err := node.CompileACL(f.cand, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(base),
		"    tcp dport 8443 drop",
		"    ip saddr 240.0.0.0/32 tcp dport 8443 accept\n    tcp dport 8443 drop", 1)
	if _, err := node.ParseACLAllowed(f.cand, []byte(tampered)); err != nil {
		t.Fatalf("tampered file is not a canonical render: %v", err)
	}
	if err := os.WriteFile(f.aclPath, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.aclPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := installNodeDynamic(context.Background(), NodeApplyOptions{Root: f.root, Runner: &nftStubRunner{}},
		node.NewCandidateDocument(f.cand), mustCompileCandidate(t, f.cand), node.RoleOut, true); err != nil {
		t.Fatalf("dynamic install failed: %v", err)
	}
	replaced, err := os.ReadFile(f.aclPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := node.CompileACL(f.cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(replaced) != string(expected) {
		t.Fatalf("preserve path kept the tampered ACL:\n%s", replaced)
	}
}

// TestNodeInstallAssertUsesObservedDefaultDeny pins that the installer's
// healthy verdict comes from observed_out_default_deny, not from the presence
// of a policy accept line.
func TestNodeInstallAssertUsesObservedDefaultDeny(t *testing.T) {
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleOut, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion,
		AgentSHA256:  strings.Repeat("b", 64), KernelSHA256: strings.Repeat("c", 64),
	}
	rb := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
		KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 1,
		ConfigSHA256: strings.Repeat("d", 64), LocalActive: true,
	}
	if err := verifyNodeInstall(context.Background(), cfg, nil, rb); err == nil ||
		!strings.Contains(err.Error(), "OUT_DEFAULT_DENY_MISSING") {
		t.Fatalf("missing default-deny evidence = %v", err)
	}
	rb.OutDefaultDeny = true
	if err := verifyNodeInstall(context.Background(), cfg, nil, rb); err != nil {
		t.Fatalf("observed default deny rejected: %v", err)
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

// writeNodeAppliedState records an applied allowlist in the fixture's Agent
// runtime state, the installer's only trusted authorization anchor.
func writeNodeAppliedState(t *testing.T, root string, cfg node.Config, allowed []string) {
	t.Helper()
	type state struct {
		Schema                 string    `json:"schema"`
		NodeID                 string    `json:"node_id"`
		Role                   node.Role `json:"role"`
		Revision               int64     `json:"revision"`
		LKGDigest              string    `json:"lkg_digest"`
		AllowedSources         []string  `json:"allowed_sources,omitempty"`
		AllowedSourcesRecorded bool      `json:"allowed_sources_recorded,omitempty"`
	}
	body, err := json.Marshal(state{
		Schema: "meshmux-node-state/v1", NodeID: cfg.NodeID, Role: cfg.Role,
		Revision: 7, LKGDigest: strings.Repeat("d", 64),
		AllowedSources: allowed, AllowedSourcesRecorded: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := rooted(root, nodeAgentStateDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
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
