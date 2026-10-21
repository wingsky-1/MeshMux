package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/protocol"
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
