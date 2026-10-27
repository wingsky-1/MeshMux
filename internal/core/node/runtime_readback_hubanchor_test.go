package node

import (
	"context"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// TestReadbackTaskUsesHubAllowlistWhenStateHasNoRecord pins the one reachable
// fail-open left after the C1 fix: when state.json carries no applied allowlist
// (a fresh bootstrap, or a lost state file), a config.readback task that arrives
// with the Hub's own allowed_sources must still be asserted exactly.
//
// Dropping that Hub parameter would degrade the readback to a shape-only check,
// and a table with an unauthorized accept (240.0.0.0/32 sorting after the
// authorized 203.0.113.7) would then report healthy. The Hub task parameter is an
// independent anchor — it comes from the Hub, never from the file or table under
// test — so shape degradation is only correct for a readback that carries no
// expectation at all.
func TestReadbackTaskUsesHubAllowlistWhenStateHasNoRecord(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(7)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)

	// No apply has happened yet: bootstrap recorded revision 7 and the LKG but
	// deliberately no authorization.
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.AllowedSourcesRecorded || len(state.AllowedSources) != 0 {
		t.Fatalf("bootstrap recorded an authorization: %+v", state.AllowedSources)
	}

	// The live table carries the Hub-authorized source plus an injected accept.
	outCandidate := testCandidate(7).Candidate()
	outCandidate.Role = RoleOut
	authorized, err := CompileACL(outCandidate, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(authorized),
		"    tcp dport 8443 drop",
		"    ip saddr 240.0.0.0/32 tcp dport 8443 accept\n    tcp dport 8443 drop", 1)
	runner.nftRules = nftRulesFromScript(tampered, 8443)

	// The Hub's readback task names the authorized set, so the injected accept
	// must fail the task instead of reporting healthy.
	task := aclTask(t, protocol.KindConfigReadback, strings.Repeat("1", 32), strings.Repeat("2", 32), 12, 7,
		[]string{"203.0.113.7"})
	result := runtime.Execute(context.Background(), task)
	if result.Status == "healthy" {
		t.Fatalf("state-without-record readback reported healthy for a table with an injected accept: %+v", result)
	}
	if result.ErrorCode != "OUT_ACL_RULE_INVALID" {
		t.Fatalf("state-without-record readback = %+v, want OUT_ACL_RULE_INVALID", result)
	}

	// The un-tampered table still passes the same task, so the fix does not turn
	// into a blanket failure of the bootstrap-then-readback sequence.
	runner.nftRules = nftRulesFromScript(string(authorized), 8443)
	ok := aclTask(t, protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("4", 32), 13, 7,
		[]string{"203.0.113.7"})
	if result := runtime.Execute(context.Background(), ok); result.Status != "healthy" {
		t.Fatalf("exact guard rejected under a Hub expectation: %+v", result)
	}

	// A task naming a different allowlist than the live table fails as a rule
	// mismatch (there is no recorded set to call it a Hub/Node disagreement).
	different := aclTask(t, protocol.KindConfigReadback, strings.Repeat("5", 32), strings.Repeat("6", 32), 14, 7,
		[]string{"198.51.100.0/24"})
	if result := runtime.Execute(context.Background(), different); result.Status == "healthy" {
		t.Fatalf("readback with a different Hub allowlist reported healthy: %+v", result)
	}
}

// TestReadbackTaskWithoutAnyExpectationIsShapeOnly pins that the degraded path is
// still available and still bounded: a readback task that carries no
// allowed_sources has no independent anchor, so it may only assert the guard
// shape — and it must not claim the accept set is authorized.
func TestReadbackTaskWithoutAnyExpectationIsShapeOnly(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role, cfg.VLESSPort = RoleOut, 8443
	runner.listenPort = 8443
	controller := &runtimeTestController{candidate: testCandidate(7)}
	controller.candidate.Role = RoleOut
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)

	outCandidate := testCandidate(7).Candidate()
	outCandidate.Role = RoleOut
	table, err := CompileACL(outCandidate, []string{"203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	runner.nftRules = nftRulesFromScript(string(table), 8443)
	task := aclTask(t, protocol.KindConfigReadback, strings.Repeat("1", 32), strings.Repeat("2", 32), 12, 7, nil)
	if result := runtime.Execute(context.Background(), task); result.Status != "healthy" {
		t.Fatalf("expectation-free readback rejected a complete guard: %+v", result)
	}
	// A shape violation still fails: the degraded path is not a free pass.
	runner.nftRules = validNFTRules(9999)
	if result := runtime.Execute(context.Background(),
		aclTask(t, protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("4", 32), 13, 7, nil)); result.Status == "healthy" {
		t.Fatalf("expectation-free readback accepted a guard for another port: %+v", result)
	}
}
