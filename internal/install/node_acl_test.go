package install

import (
	"context"
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

// TestNodeACLReadbackRequiresExactObservedGuard pins the installer assert: the
// live table must carry both VLESS drops and exactly the accept set of the
// managed ACL file. A `policy accept` chain, an extra accept or a missing drop
// all fail, so an Out can never report installed without a real guard.
func TestNodeACLReadbackRequiresExactObservedGuard(t *testing.T) {
	root := t.TempDir()
	candidate := node.Candidate{
		NodeID: strings.Repeat("a", 32), Role: node.RoleOut, Revision: 1,
		VLESSPort: 8443, KernelVersion: node.KernelVersion,
	}
	acl, err := node.CompileACL(candidate, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	aclPath := rooted(root, node.ACLPath)
	if err := os.MkdirAll(rooted(root, nodeAgentStateDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclPath, acl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
		t.Fatal(err)
	}

	ok := &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32"))}
	if err := verifyNodeACLReadback(context.Background(), ok, root, candidate, 8443); err != nil {
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
			err := verifyNodeACLReadback(context.Background(), runner, root, candidate, 8443)
			if err == nil || !strings.Contains(err.Error(), "OUT_ACL_READBACK_FAILED") {
				t.Fatalf("bad guard = %v, want OUT_ACL_READBACK_FAILED", err)
			}
		})
	}

	// A missing or hand-edited managed file is never trusted as the
	// expectation.
	if err := os.WriteFile(aclPath, append(append([]byte{}, acl...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &nftStubRunner{output: []byte(aclJSONWithAccepts(8443, "203.0.113.7/32"))}
	if err := verifyNodeACLReadback(context.Background(), runner, root, candidate, 8443); err == nil {
		t.Fatal("hand-edited ACL was accepted as the expectation")
	}
}

// TestNodeRepairPreservesAuthorizedACL pins the repair contract: an ACL file
// that already carries a Hub-applied allowlist is the canonical render for the
// candidate, so it is LKG and installNodeDynamic must not rewrite it to the
// empty default-deny render (which would revoke every authorized Line).
func TestNodeRepairPreservesAuthorizedACL(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	aclPath := rooted(f.root, node.ACLPath)
	authorized, err := node.CompileACL(f.candidate.Candidate(), []string{"203.0.113.7", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclPath, authorized, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(aclPath, 0600); err != nil {
		t.Fatal(err)
	}
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
	if string(current) != string(authorized) {
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
	compiled, err := node.CompileCandidate(f.candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	if err := installNodeDynamic(context.Background(), f.opts, f.candidate, compiled, node.RoleOut, false); err != nil {
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
