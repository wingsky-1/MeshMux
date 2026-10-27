package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// aclTask builds one config task carrying the Hub-side allowlist.
func aclTask(t *testing.T, kind, operationID, key string, revision, configRevision int64, allowed []string) protocol.Task {
	t.Helper()
	params := map[string]any{"revision": configRevision}
	if allowed != nil {
		params["allowed_sources"] = allowed
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Task{
		Schema: protocol.Schema, Version: protocol.Version,
		OperationID: operationID, Revision: revision, IdempotencyKey: key,
		NodeID: strings.Repeat("a", 32), Kind: kind, Params: raw,
	}
}

// TestReadbackACLAllowlistIsExact pins that the live table must carry exactly
// the authorized sources: a missing accept denies a Line the Hub believes is
// admitted, an extra accept admits a source nobody authorized. Both are
// RULE_INVALID, never a silent pass.
func TestReadbackACLAllowlistIsExact(t *testing.T) {
	allowed := []string{"203.0.113.7", "2001:db8::/32"}
	base := validNFTRules(8443)
	withAccepts := append([]string{base[0], base[1]},
		nftAcceptRule("ip", "203.0.113.7/32", 8443),
		nftAcceptRule("ip6", "2001:db8::/32", 8443),
		base[2], base[3])
	runner := &runtimeTestRunner{nftRules: withAccepts}
	if err := VerifyOutACL(context.Background(), runner, 8443, allowed); err != nil {
		t.Fatalf("exact authorized set rejected: %v", err)
	}

	cases := []struct {
		name  string
		rules []string
	}{
		{
			name: "missing authorized accept",
			rules: []string{base[0], base[1],
				nftAcceptRule("ip", "203.0.113.7/32", 8443), base[2], base[3]},
		},
		{
			name: "extra unauthorized accept",
			rules: append([]string{base[0], base[1],
				nftAcceptRule("ip", "192.0.2.9/32", 8443)},
				withAccepts[2:]...),
		},
		{
			name: "accept after the drop",
			rules: []string{base[0], base[1],
				nftAcceptRule("ip", "203.0.113.7/32", 8443),
				base[2],
				nftAcceptRule("ip6", "2001:db8::/32", 8443),
				base[3]},
		},
		{
			name: "duplicate accept",
			rules: append([]string{base[0], base[1],
				nftAcceptRule("ip", "203.0.113.7/32", 8443)},
				withAccepts[2:]...),
		},
		{
			name: "accept for the wrong port",
			rules: []string{base[0], base[1],
				nftAcceptRule("ip", "203.0.113.7/32", 9999),
				nftAcceptRule("ip6", "2001:db8::/32", 8443), base[2], base[3]},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &runtimeTestRunner{nftRules: tc.rules}
			err := VerifyOutACL(context.Background(), runner, 8443, allowed)
			if err == nil || !strings.Contains(err.Error(), "OUT_ACL_RULE_INVALID") {
				t.Fatalf("mutated table = %v, want OUT_ACL_RULE_INVALID", err)
			}
		})
	}

	// A table with accepts but an empty expectation is the fail-closed case:
	// the Hub authorized nobody, so any accept is an unauthorized admission.
	runner = &runtimeTestRunner{nftRules: withAccepts}
	if err := VerifyOutACL(context.Background(), runner, 8443, nil); err == nil ||
		!strings.Contains(err.Error(), "OUT_ACL_RULE_INVALID") {
		t.Fatalf("accepts under an empty allowlist = %v, want OUT_ACL_RULE_INVALID", err)
	}
	// And the reverse: the empty default-deny render must not pass while the
	// Hub expects an authorized source.
	runner = &runtimeTestRunner{nftRules: validNFTRules(8443)}
	if err := VerifyOutACL(context.Background(), runner, 8443, allowed); err == nil ||
		!strings.Contains(err.Error(), "OUT_ACL_RULE_INVALID") {
		t.Fatalf("default-deny table under an allowlist = %v, want OUT_ACL_RULE_INVALID", err)
	}
	// The empty expectation against the empty render is the healthy state.
	if err := VerifyOutACL(context.Background(), runner, 8443, nil); err != nil {
		t.Fatalf("default-deny table rejected: %v", err)
	}
}

// TestReadbackACLAcceptsBothNFTPrefixSpellings pins the parser against the two
// shapes nft uses for one address match: a bare address string for a host
// prefix and a {"prefix":{...}} object. Real nft prints either depending on
// how the rule was written, so both must compare equal to the same prefix.
func TestReadbackACLAcceptsBothNFTPrefixSpellings(t *testing.T) {
	base := validNFTRules(8443)
	doc := func(right string) []byte {
		accept := `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[` +
			`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":` + right + `}},` +
			`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},` +
			`{"accept":null}]}}`
		return []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1], accept, base[2], base[3]}, ",") + `]}`)
	}
	for _, right := range []string{`"203.0.113.7"`, `{"prefix":{"addr":"203.0.113.7","len":32}}`} {
		if err := VerifyOutACLDocument(doc(right), 8443, []string{"203.0.113.7"}); err != nil {
			t.Fatalf("right=%s rejected: %v", right, err)
		}
	}
	// A host prefix must not be accepted for the other family.
	ip6 := `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"203.0.113.7"}},` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},` +
		`{"accept":null}]}}`
	wrongFamily := []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1], ip6, base[2], base[3]}, ",") + `]}`)
	if err := VerifyOutACLDocument(wrongFamily, 8443, []string{"203.0.113.7"}); err == nil {
		t.Fatal("v4 address under an ip6 match was accepted")
	}
}

// TestReadbackACLShapeOnlyWithoutState pins the degraded bootstrap path: with no
// runtime state there is no trusted record of an applied allowlist, so only the
// guard shape and both drops are asserted. The accept set is deliberately not
// compared, because the only remaining candidate expectation would be the ACL
// file itself.
func TestReadbackACLShapeOnlyWithoutState(t *testing.T) {
	base := validNFTRules(8443)
	shapeOnly := []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1], base[2], base[3]}, ",") + `]}`)
	if err := VerifyOutACLShapeDocument(shapeOnly, 8443); err != nil {
		t.Fatalf("default-deny guard rejected by shape check: %v", err)
	}
	// An accept the Hub never authorized is not distinguished here (there is
	// no anchor), but the shape must still be complete.
	withAccept := []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1],
		nftAcceptRule("ip", "240.0.0.0/32", 8443), base[2], base[3]}, ",") + `]}`)
	if err := VerifyOutACLShapeDocument(withAccept, 8443); err != nil {
		t.Fatalf("shape check rejected a complete guard: %v", err)
	}
	// Every shape violation still fails.
	for name, output := range map[string][]byte{
		"no drops": []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1]}, ",") + `]}`),
		"policy drop": []byte(`{"nftables":[` + strings.Join([]string{base[0],
			strings.Replace(base[1], `"policy":"accept"`, `"policy":"drop"`, 1), base[2], base[3]}, ",") + `]}`),
		"wrong prio": []byte(`{"nftables":[` + strings.Join([]string{base[0],
			strings.Replace(base[1], `"prio":-10`, `"prio":0`, 1), base[2], base[3]}, ",") + `]}`),
		"foreign table": []byte(`{"nftables":[` + strings.Join([]string{
			strings.Replace(base[0], `"meshmux_out"`, `"other"`, 1), base[1], base[2], base[3]}, ",") + `]}`),
		"accept after drop": []byte(`{"nftables":[` + strings.Join([]string{base[0], base[1], base[2],
			nftAcceptRule("ip", "203.0.113.7/32", 8443), base[3]}, ",") + `]}`),
	} {
		if err := VerifyOutACLShapeDocument(output, 8443); err == nil {
			t.Errorf("%s accepted by shape check", name)
		}
	}
}

// TestAppliedAllowedSourcesIsTheOnlyAnchor pins the accessor the installer uses:
// the recorded allowlist is returned only from a valid state file for this exact
// node, and a missing state is reported as "no record" rather than as an empty
// authorization.
func TestAppliedAllowedSourcesIsTheOnlyAnchor(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)

	// A freshly bootstrapped Out has state but no recorded authorization, so the
	// accessor reports "no record" instead of an empty allowlist. Treating it as
	// an empty applied set would permanently fail the node until the Hub
	// re-applied, and treating it as any set would trust nothing.
	applied, recorded, err := AppliedAllowedSources(root, cfg.NodeID, cfg.Role)
	if err != nil || recorded || len(applied) != 0 {
		t.Fatalf("bootstrap accessor = %v, %v, %v; want nil,false,nil", applied, recorded, err)
	}

	allowed := []string{"203.0.113.7", "2001:db8::/32"}
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9, allowed)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply = %+v", result)
	}
	applied, recorded, err = AppliedAllowedSources(root, cfg.NodeID, cfg.Role)
	if err != nil || !recorded || !sameACLSources(applied, allowed) {
		t.Fatalf("accessor after apply = %v, %v, %v", applied, recorded, err)
	}
	// An explicitly applied empty allowlist is a real record (default deny), not
	// "nothing recorded", so readbacks must assert it exactly.
	emptyApply := aclTask(t, protocol.KindConfigApply, strings.Repeat("7", 32), strings.Repeat("8", 32), 13, 9, []string{})
	if result := runtime.Execute(context.Background(), emptyApply); result.Status != "healthy" {
		t.Fatalf("empty-allowlist apply = %+v", result)
	}
	applied, recorded, err = AppliedAllowedSources(root, cfg.NodeID, cfg.Role)
	if err != nil || !recorded || len(applied) != 0 {
		t.Fatalf("accessor after empty apply = %v, %v, %v; want [],true,nil", applied, recorded, err)
	}

	// A different node never inherits this host's record.
	if _, recorded, err = AppliedAllowedSources(root, strings.Repeat("b", 32), cfg.Role); err == nil || recorded {
		t.Fatalf("accessor accepted a foreign node: %v %v", recorded, err)
	}
	// A missing state file is "no record", never an empty authorization.
	if err := os.Remove(rooted(root, RuntimeStatePath)); err != nil {
		t.Fatal(err)
	}
	applied, recorded, err = AppliedAllowedSources(root, cfg.NodeID, cfg.Role)
	if err != nil || recorded || len(applied) != 0 {
		t.Fatalf("missing-state accessor = %v, %v, %v; want nil,false,nil", applied, recorded, err)
	}
	// A malformed state is an error, not a downgrade.
	if err := os.WriteFile(rooted(root, RuntimeStatePath), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, recorded, err = AppliedAllowedSources(root, cfg.NodeID, cfg.Role); err == nil || recorded {
		t.Fatalf("malformed state accepted: %v %v", recorded, err)
	}
}

// TestReadbackBootstrapIgnoresTamperedACLFile is the fail-open regression for
// the state-loss path: a canonical-looking ACL file with a late injected accept
// must not become its own authorization, and the bootstrap readback must not
// claim an exact accept set it cannot know.
func TestReadbackBootstrapIgnoresTamperedACLFile(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	outCandidate := testCandidate(7).Candidate()
	outCandidate.Role = RoleOut
	base, err := CompileACL(outCandidate, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(base),
		"    tcp dport 8443 drop",
		"    ip saddr 240.0.0.0/32 tcp dport 8443 accept\n    tcp dport 8443 drop", 1)
	if _, err := ParseACLAllowed(outCandidate, []byte(tampered)); err != nil {
		t.Fatalf("tampered ACL is not even a canonical render: %v", err)
	}
	if err := os.WriteFile(rooted(root, ACLPath), []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	runner.nftRules = nftRulesFromScript(tampered, 8443)

	// No runtime state exists: the readback may only assert shape, so it
	// succeeds, but it must not record the injected source as authorized.
	readback, err := ReadbackLocal(context.Background(), cfg, root, runner)
	if err != nil {
		t.Fatalf("shape-only bootstrap rejected a complete guard: %v", err)
	}
	if !readback.OutDefaultDeny {
		t.Fatal("bootstrap readback lost the default-deny guard evidence")
	}
	applied, recorded, err := AppliedAllowedSources(root, cfg.NodeID, cfg.Role)
	if err != nil || recorded || len(applied) != 0 {
		t.Fatalf("bootstrap recorded an authorization from the file: %v %v %v", applied, recorded, err)
	}
}

// TestReadbackRejectsLateInjectedAcceptUnderRecordedState is the second half of
// the fail-open regression: once state.json records what the Hub authorized, the
// same late injected accept (240.0.0.0/32 sorts after 203.0.113.7) must fail the
// live readback instead of being accepted because the file re-renders cleanly.
func TestReadbackRejectsLateInjectedAcceptUnderRecordedState(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply = %+v", result)
	}
	// The live table now carries an accept nobody authorized.
	runner.unauthorizedAccept = "240.0.0.0/32"
	if _, err := ReadbackLocal(context.Background(), cfg, root, runner); err == nil ||
		!strings.Contains(err.Error(), "OUT_ACL_RULE_INVALID") {
		t.Fatalf("late-injected accept under recorded state = %v, want OUT_ACL_RULE_INVALID", err)
	}
	// A readback task with the same applied allowlist also fails. The fake
	// injection is one-shot, so it is re-armed for this second read.
	runner.unauthorizedAccept = "240.0.0.0/32"
	taskReadback := aclTask(t, protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("4", 32), 12, 9,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), taskReadback); result.ErrorCode != "OUT_ACL_RULE_INVALID" {
		t.Fatalf("tampered table readback task = %+v", result)
	}
	// A task naming a different allowlist fails as a source mismatch before the
	// table is even compared.
	runner.unauthorizedAccept = ""
	other := aclTask(t, protocol.KindConfigReadback, strings.Repeat("5", 32), strings.Repeat("6", 32), 13, 9,
		[]string{"198.51.100.0/24"})
	if result := runtime.Execute(context.Background(), other); result.ErrorCode != "OUT_ACL_SOURCE_MISMATCH" {
		t.Fatalf("mismatched readback task = %+v", result)
	}
}

// TestReadbackAfterStateLossIsShapeOnly pins that losing state.json on an
// authorized Out does not brick the node and does not launder the file into an
// authorization: the readback proves the guard shape, reports default-deny
// evidence, and records no allowlist until the Hub re-applies.
func TestReadbackAfterStateLossIsShapeOnly(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply = %+v", result)
	}
	// Simulate a lost state file while the applied table stays in place.
	if err := os.Remove(rooted(root, RuntimeStatePath)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadbackLocal(context.Background(), cfg, root, runner); err != nil {
		t.Fatalf("readback after state loss = %v; want shape-only pass", err)
	}
	if applied, recorded, err := AppliedAllowedSources(root, cfg.NodeID, cfg.Role); err != nil || recorded || len(applied) != 0 {
		t.Fatalf("state loss recorded an authorization: %v %v %v", applied, recorded, err)
	}
	// A tampered table with an extra accept is still not distinguished here, but
	// the next Hub readback task (which carries the Hub's own allowlist) fails on
	// the mismatch instead of silently accepting the injected source.
	runner.unauthorizedAccept = "240.0.0.0/32"
	readbackTask := aclTask(t, protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("4", 32), 12, 9,
		[]string{"203.0.113.7"})
	result := runtime.Execute(context.Background(), readbackTask)
	if result.Status == "healthy" {
		t.Fatalf("tampered table after state loss reported healthy: %+v", result)
	}
}

// TestReadbackACLRejectsInvalidExpectation pins that a bad Hub allowlist never
// reaches a comparison: it fails as ACL_SOURCE_INVALID instead of matching a
// table by accident.
func TestReadbackACLRejectsInvalidExpectation(t *testing.T) {
	runner := &runtimeTestRunner{nftRules: validNFTRules(8443)}
	err := VerifyOutACL(context.Background(), runner, 8443, []string{"0.0.0.0/0"})
	if err == nil || !strings.Contains(err.Error(), "ACL_SOURCE_INVALID") {
		t.Fatalf("zero-length expectation = %v, want ACL_SOURCE_INVALID", err)
	}
}

// TestApplyWithAllowlistRendersOrderedAcceptAndRecovers pins the whole apply
// path for an authorized Out: the applied script carries accept-before-drop,
// the readback proves it, and the LKG keeps the authorization. A readback that
// no longer matches rolls back to the last-known-good authorization.
func TestApplyWithAllowlistRendersOrderedAcceptAndRecovers(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	allowed := []string{"203.0.113.7", "2001:db8::/32"}
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9, allowed)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "healthy" {
		t.Fatalf("authorized apply = %+v", result)
	}
	if !strings.Contains(runner.aclApplied, "ip saddr 203.0.113.7/32 tcp dport 8443 accept") ||
		!strings.Contains(runner.aclApplied, "ip6 saddr 2001:db8::/32 tcp dport 8443 accept") {
		t.Fatalf("applied ACL lost the authorized sources:\n%s", runner.aclApplied)
	}
	if strings.Index(runner.aclApplied, "accept") > strings.Index(runner.aclApplied, "tcp dport 8443 drop") {
		t.Fatalf("applied ACL put an accept after the drop:\n%s", runner.aclApplied)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if !sameACLSources(state.AllowedSources, allowed) {
		t.Fatalf("LKG allowlist = %v, want %v", state.AllowedSources, allowed)
	}
	aclFile, err := os.ReadFile(rooted(root, ACLPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(aclFile) != runner.aclApplied {
		t.Fatal("applied ACL file differs from the script pushed to nft")
	}
	parsed, err := ParseACLAllowed(controller.candidate.Candidate(), aclFile)
	if err != nil || !sameACLSources(parsed, allowed) {
		t.Fatalf("applied ACL is not a canonical render: %v %v", parsed, err)
	}
}

// TestApplyReadbackRejectsUnauthorizedExtraAccept pins that a live table which
// admits an extra source fails the apply and rolls back, instead of reporting
// healthy on a table the Hub did not authorize.
func TestApplyReadbackRejectsUnauthorizedExtraAccept(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	// The fake data plane keeps an extra accept the Hub never authorized:
	// the readback must not trust the requested authorization. Clearing it
	// on the rollback apply lets the LKG prove itself again.
	runner.unauthorizedAccept = "192.0.2.9"
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("4", 32), 11, 9,
		[]string{"203.0.113.7"})
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "rolled_back" || !strings.Contains(result.ErrorCode, "OUT_ACL_RULE_INVALID") {
		t.Fatalf("unauthorized table apply = %+v", result)
	}
}

// TestTaskAllowedSourcesRejectsMalformed pins the params boundary: the Agent
// refuses a malformed allowlist instead of applying a different authorization.
func TestTaskAllowedSourcesRejectsMalformed(t *testing.T) {
	cases := []string{
		`{"revision":9,"allowed_sources":"203.0.113.7"}`,
		`{"revision":9,"allowed_sources":[1,2]}`,
		`{"revision":9,"allowed_sources":null}`,
		`{"revision":9,"allowed_sources":{"source":"203.0.113.7"}}`,
		`{"revision":9,"allowed_sources":["not-an-ip"]}`,
		`{"revision":9,"allowed_sources":["0.0.0.0/0"]}`,
		`{"revision":9,"allowed_sources":["203.0.113.7; reboot"]}`,
	}
	for _, params := range cases {
		task := protocol.Task{
			Schema: protocol.Schema, Version: protocol.Version,
			OperationID: strings.Repeat("1", 32), Revision: 1,
			IdempotencyKey: strings.Repeat("2", 32),
			NodeID:         strings.Repeat("a", 32), Kind: protocol.KindConfigApply,
			Params: []byte(params),
		}
		if _, _, err := taskAllowedSources(task); err == nil {
			t.Fatalf("malformed allowlist accepted: %s", params)
		}
	}
	task := protocol.Task{Params: []byte(`{"revision":9}`)}
	if allowed, present, err := taskAllowedSources(task); err != nil || present || len(allowed) != 0 {
		t.Fatalf("absent allowlist = %v, %v, %v", allowed, present, err)
	}
	task.Params = []byte(`{"revision":9,"allowed_sources":["203.0.113.7","2001:db8::/32"]}`)
	allowed, present, err := taskAllowedSources(task)
	if err != nil || !present || len(allowed) != 2 {
		t.Fatalf("valid allowlist = %v, %v, %v", allowed, present, err)
	}
}

// TestReadbackACLSourceMismatch pins that a readback task naming a different
// allowlist than the active revision fails instead of reporting healthy for a
// data plane that carries another authorization.
func TestReadbackACLSourceMismatch(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply = %+v", result)
	}
	readback := aclTask(t, protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("4", 32), 12, 9,
		[]string{"198.51.100.0/24"})
	result := runtime.Execute(context.Background(), readback)
	if result.ErrorCode != "OUT_ACL_SOURCE_MISMATCH" {
		t.Fatalf("mismatched readback = %+v", result)
	}
	// The matching readback, and one that carries no expectation, both pass.
	for i, allowed := range [][]string{{"203.0.113.7"}, nil} {
		readback := aclTask(t, protocol.KindConfigReadback,
			strings.Repeat(string(rune('5'+i)), 32), strings.Repeat(string(rune('6'+i)), 32), int64(13+i), 9, allowed)
		if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
			t.Fatalf("readback %d = %+v", i, result)
		}
	}
}

// TestApplyWithAllowlistRollsBackACLOnKernelFailure pins the LKG path for an
// authorized Out: when the kernel restart fails, the previous ACL (including
// its authorization) is restored, not the empty default-deny render.
func TestApplyWithAllowlistRollsBackACLOnKernelFailure(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(9)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	// Seed the LKG with one authorized source.
	seed := aclTask(t, protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), seed); result.Status != "healthy" {
		t.Fatalf("seed apply = %+v", result)
	}
	previousACL, err := os.ReadFile(rooted(root, ACLPath))
	if err != nil {
		t.Fatal(err)
	}
	// The next revision authorizes another source but fails at restart.
	runner.restartFail = true
	next := aclTask(t, protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("4", 32), 12, 9,
		[]string{"198.51.100.0/24"})
	result := runtime.Execute(context.Background(), next)
	if result.Status != "rolled_back" || result.ErrorCode != "SINGBOX_RESTART_FAILED" {
		t.Fatalf("failed apply = %+v", result)
	}
	restored, err := os.ReadFile(rooted(root, ACLPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, previousACL) {
		t.Fatalf("rollback lost the LKG authorization:\n%s\n---\n%s", restored, previousACL)
	}
	if !strings.Contains(string(restored), "ip saddr 203.0.113.7/32") {
		t.Fatalf("rollback dropped the authorized source:\n%s", restored)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if !sameACLSources(state.AllowedSources, []string{"203.0.113.7"}) {
		t.Fatalf("rollback state allowlist = %v", state.AllowedSources)
	}
}

// TestReadbackTransientACLSignals pins that ACL failures are deterministic:
// the installer must not retry a wrong table as if the kernel were slow.
func TestReadbackTransientACLSignals(t *testing.T) {
	for _, code := range []string{
		"OUT_ACL_UNAVAILABLE",
		"OUT_ACL_INVALID",
		"OUT_ACL_RULE_INVALID",
		"OUT_ACL_DEFAULT_DENY_INCOMPLETE",
		"OUT_ACL_INPUT_HOOK_INVALID",
		"OUT_ACL_FOREIGN_TABLE",
		"ACL_SOURCE_INVALID",
	} {
		if TransientReadback(errors.New(code)) {
			t.Errorf("%s must fail fast", code)
		}
	}
}
