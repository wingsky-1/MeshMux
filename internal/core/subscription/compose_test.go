package subscription

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// composeFixture builds one Line with its own credential, so the composer can
// be exercised without a store.
func composeFixture(t *testing.T, nodeID, name string, sortOrder int) ComposeLine {
	t.Helper()
	line := exportFixture(t, nodeID, name, "line.example.invalid", 8443, sortOrder)
	credential := exportCredential(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nodeID, "")
	return ComposeLine{Line: line, Credential: credential}
}

// composePins is the version-locked artifact set of the composer tests. The
// URLs use example.invalid on purpose: `sing-box check` validates the document
// shape, never fetches the artifact.
func composePins() RuleSetPin {
	return RuleSetPin{
		Source:  "https://rulesets.example.invalid/2026-10-26.srs",
		Version: "20261026",
		SHA256:  strings.Repeat("a", 64),
	}
}

// composeRules is a small library selection covering the three actions and the
// two matcher families that need a pin.
func composeRules() []ComposeRule {
	pin := composePins()
	return []ComposeRule{
		{StableKey: "preset-direct-cn", Version: 1, Action: ActionDirect, Kind: MatcherGeoSite,
			Values: []string{"cn"}, Pins: map[string]RuleSetPin{"cn": pin}},
		{StableKey: "preset-proxy-ai", Version: 1, Action: ActionProxy, Kind: MatcherRuleSet,
			Values: []string{"ai"}, Pins: map[string]RuleSetPin{"ai": pin}},
		{StableKey: "preset-reject-ads", Version: 1, Action: ActionReject, Kind: MatcherDomainSuffix,
			Values: []string{"ads.example.invalid", "tracker.example.invalid"}},
	}
}

// TestComposeSubscriptionIsByteDeterministic pins the pure-function contract:
// the same selection produces byte-identical documents and one stable content
// id, so the artifact can be re-derived on every download.
func TestComposeSubscriptionIsByteDeterministic(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	out := []ComposeOut{{OutID: "22222222222222222222222222222222", DisplayName: "东京 Out", Server: "out.example.invalid", Port: 443, LinkKey: goldenLinkKey}}
	rules := composeRules()
	network := []ComposeNetwork{{DeviceID: "33333333333333333333333333333333", DisplayName: "iPad"}}

	first, firstDiagnostics := ComposeSubscription(lines, out, rules, network)
	second, secondDiagnostics := ComposeSubscription(lines, out, rules, network)
	if anyBlocking(firstDiagnostics) || anyBlocking(secondDiagnostics) {
		t.Fatalf("unexpected blocking diagnostics: %+v / %+v", firstDiagnostics, secondDiagnostics)
	}
	if first.ContentID == "" || first.ContentID != second.ContentID {
		t.Fatalf("content id = %q / %q, want one stable non-empty id", first.ContentID, second.ContentID)
	}
	if string(first.SingBox) != string(second.SingBox) {
		t.Fatal("sing-box document is not byte-identical")
	}
	if string(first.Mihomo) != string(second.Mihomo) {
		t.Fatal("mihomo document is not byte-identical")
	}
	// The Line publishes no route for a subscription any more: the Out is a
	// client-side hop, so the retired field stays empty.
	if len(first.LineRoutes) != 0 || len(second.LineRoutes) != 0 {
		t.Fatalf("line routes = %d / %d, want none", len(first.LineRoutes), len(second.LineRoutes))
	}
	if len(network) != 1 {
		t.Fatal("the network selection must not block the artifact")
	}
}

// TestComposeSubscriptionRendersOutIntoClientDocuments pins the client-chain
// contract: a selected Out becomes one egress in both client documents and the
// egress every proxy rule names, so the client hops Line -> Out itself and the
// Line publishes no route at all.
func TestComposeSubscriptionRendersOutIntoClientDocuments(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	out := []ComposeOut{{OutID: "22222222222222222222222222222222", DisplayName: "东京 Out", Server: "out.example.invalid", Port: 443, LinkKey: goldenLinkKey}}

	documents, diagnostics := ComposeSubscription(lines, out, composeRules(), nil)
	if anyBlocking(diagnostics) {
		t.Fatalf("unexpected blocking diagnostics: %+v", diagnostics)
	}
	if len(documents.LineRoutes) != 0 {
		t.Fatalf("line routes = %+v, want none (the Line no longer forwards)", documents.LineRoutes)
	}
	client := string(documents.SingBox)
	// The client document keeps the Line outbound and grows exactly one Out
	// egress that dials the Out endpoint with the link key.
	for _, required := range []string{
		`"tag": "香港 01 [11111111111111111111111111111111]"`,
		`"type": "shadowsocks"`, `"tag": "out"`, `"server": "out.example.invalid"`,
		`"method": "2022-blake3-aes-128-gcm"`, `"password": "` + goldenLinkKey + `"`,
		`"outbound": "out"`,
	} {
		if !strings.Contains(client, required) {
			t.Fatalf("sing-box document misses %q:\n%s", required, client)
		}
	}
	// The Out is the egress of the proxy rules only: the final egress stays the
	// Line selector, so unmatched traffic never silently leaves through the Out.
	if !strings.Contains(client, `"final": "meshmux-selector"`) {
		t.Fatalf("the final egress is not the Line selector:\n%s", client)
	}
	mihomo := string(documents.Mihomo)
	for _, required := range []string{
		`- name: "out"`, `type: "ss"`, `cipher: "2022-blake3-aes-128-gcm"`,
		`password: "` + goldenLinkKey + `"`, `- "RULE-SET,ai@20261026,out"`,
	} {
		if !strings.Contains(mihomo, required) {
			t.Fatalf("mihomo document misses %q:\n%s", required, mihomo)
		}
	}
	if !strings.Contains(mihomo, `- "MATCH,PROXY"`) {
		t.Fatalf("the mihomo final rule is not the Line group:\n%s", mihomo)
	}
}

// TestComposeSubscriptionRulesReachBothDocuments pins the dual-kernel rule
// rendering: the same library selection appears in the sing-box route and in
// the Mihomo rules, and both documents pass the real kernel check when the
// pinned binary is available.
func TestComposeSubscriptionRulesReachBothDocuments(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	out := []ComposeOut{{OutID: "22222222222222222222222222222222", DisplayName: "东京 Out", Server: "out.example.invalid", Port: 443, LinkKey: goldenLinkKey}}
	documents, diagnostics := ComposeSubscription(lines, out, composeRules(), nil)
	if anyBlocking(diagnostics) {
		t.Fatalf("unexpected blocking diagnostics: %+v", diagnostics)
	}
	singBox := string(documents.SingBox)
	for _, required := range []string{
		`"rule_set": [`, `"geosite-cn@20261026"`, `"ai@20261026"`,
		`"action": "reject"`, `"domain_suffix": [`, `"final": "meshmux-selector"`,
	} {
		if !strings.Contains(singBox, required) {
			t.Fatalf("sing-box document misses %q:\n%s", required, singBox)
		}
	}
	mihomo := string(documents.Mihomo)
	for _, required := range []string{
		`- "RULE-SET,geosite-cn@20261026,DIRECT"`,
		`- "RULE-SET,ai@20261026,out"`,
		`- "DOMAIN-SUFFIX,ads.example.invalid,REJECT"`,
		`rule-providers:`, `- "MATCH,PROXY"`,
	} {
		if !strings.Contains(mihomo, required) {
			t.Fatalf("mihomo document misses %q:\n%s", required, mihomo)
		}
	}

	binary := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if binary == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native compose check")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	dir := t.TempDir()
	clientPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(clientPath, documents.SingBox, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "check", "-c", clientPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box refused the composed client document: %v\n%s", err, output)
	}
}

// TestComposeSubscriptionRefusesUnpinnedRuleSet pins the version lock: a geo
// or ruleset rule without a pinned artifact is a blocking diagnostic and no
// document is emitted.
func TestComposeSubscriptionRefusesUnpinnedRuleSet(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	rules := []ComposeRule{{StableKey: "custom-ai", Version: 1, Action: ActionProxy, Kind: MatcherRuleSet, Values: []string{"ai"}}}
	documents, diagnostics := ComposeSubscription(lines, nil, rules, nil)
	if len(documents.SingBox) != 0 || len(documents.Mihomo) != 0 {
		t.Fatal("an unpinned ruleset produced a document")
	}
	if !hasBlocking(diagnostics, "COMPOSE_RULESET_UNPINNED") {
		t.Fatalf("diagnostics = %+v, want a blocking COMPOSE_RULESET_UNPINNED", diagnostics)
	}
}

// TestComposeSubscriptionRefusesSecondOut pins the 1.0 single-Out constraint
// at the composer boundary too, so no caller can assemble a multi-Out document.
func TestComposeSubscriptionRefusesSecondOut(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	outs := []ComposeOut{
		{OutID: "22222222222222222222222222222222", Server: "out-a.example.invalid", Port: 443, LinkKey: goldenLinkKey},
		{OutID: "33333333333333333333333333333333", Server: "out-b.example.invalid", Port: 443, LinkKey: goldenLinkKey},
	}
	documents, diagnostics := ComposeSubscription(lines, outs, nil, nil)
	if len(documents.SingBox) != 0 {
		t.Fatal("a second Out produced a document")
	}
	if !hasBlocking(diagnostics, "COMPOSE_OUT_LIMIT") {
		t.Fatalf("diagnostics = %+v, want a blocking COMPOSE_OUT_LIMIT", diagnostics)
	}
}

// TestComposeSubscriptionRemindsRecordedNetwork pins the 1.0 Out/Mesh boundary:
// a network selection is recorded and reported as a reminder, never executed
// by this composer.
func TestComposeSubscriptionRemindsRecordedNetwork(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	network := []ComposeNetwork{{DeviceID: "33333333333333333333333333333333", DisplayName: "iPad"}}
	documents, diagnostics := ComposeSubscription(lines, nil, nil, network)
	if len(documents.SingBox) == 0 && len(documents.Mihomo) == 0 {
		t.Fatal("a recorded network blocked the artifact")
	}
	if !hasReminder(diagnostics, "COMPOSE_NETWORK_RECORDED_ONLY") {
		t.Fatalf("diagnostics = %+v, want the recorded-only reminder", diagnostics)
	}
}

// TestComposeSubscriptionRejectsEmptySelection pins the input layer: no Line
// means nothing to assemble.
func TestComposeSubscriptionRejectsEmptySelection(t *testing.T) {
	documents, diagnostics := ComposeSubscription(nil, nil, nil, nil)
	if len(documents.SingBox) != 0 || len(documents.Mihomo) != 0 {
		t.Fatal("an empty selection produced a document")
	}
	if !hasBlocking(diagnostics, "COMPOSE_NO_LINES") {
		t.Fatalf("diagnostics = %+v, want a blocking COMPOSE_NO_LINES", diagnostics)
	}
}

// TestComposeSubscriptionDuplicateRuleIsBlocking pins the assembly-conflict
// layer: the same revision selected twice would shadow itself.
func TestComposeSubscriptionDuplicateRuleIsBlocking(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	rule := ComposeRule{StableKey: "preset-reject-ads", Version: 1, Action: ActionReject, Kind: MatcherDomainSuffix, Values: []string{"ads.example.invalid"}}
	documents, diagnostics := ComposeSubscription(lines, nil, []ComposeRule{rule, rule}, nil)
	if len(documents.SingBox) != 0 {
		t.Fatal("a duplicate rule produced a document")
	}
	if !hasBlocking(diagnostics, "COMPOSE_RULE_DUPLICATE") {
		t.Fatalf("diagnostics = %+v, want a blocking COMPOSE_RULE_DUPLICATE", diagnostics)
	}
}

// TestComposeSubscriptionRejectsOverlappingRules pins the conflict layer: two
// rules with different actions on the same target would shadow each other, so
// the earlier one silently wins in the kernel. The composer refuses instead.
func TestComposeSubscriptionRejectsOverlappingRules(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	rules := []ComposeRule{
		{StableKey: "a-direct", Version: 1, Action: ActionDirect, Kind: MatcherDomain, Values: []string{"dl.example.invalid"}},
		{StableKey: "b-proxy", Version: 1, Action: ActionProxy, Kind: MatcherDomainSuffix, Values: []string{"example.invalid"}},
	}
	documents, diagnostics := ComposeSubscription(lines, nil, rules, nil)
	if len(documents.SingBox) != 0 {
		t.Fatal("an overlapping rule set produced a document")
	}
	if !hasBlocking(diagnostics, "COMPOSE_RULE_CONFLICT") {
		t.Fatalf("diagnostics = %+v, want a blocking COMPOSE_RULE_CONFLICT", diagnostics)
	}
}

// TestComposeSelectionSnapshotIDIsContentAddressed pins the snapshot contract:
// only the selection and its versions are hashed, so a rename or a rendered
// byte change never alters the selection identity.
func TestComposeSelectionSnapshotIDIsContentAddressed(t *testing.T) {
	selection := Selection{
		SubscriberID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Version:      3,
		Lines:        []SelectionLine{{NodeID: "11111111111111111111111111111111", Position: 0, LineRevision: 4}},
		Out:          &SelectionOut{OutID: "22222222222222222222222222222222", Position: 0, OutRevision: 2},
		Rules:        []SelectionRule{{StableKey: "preset-direct-cn", Version: 1, Position: 0}},
		Networks:     []SelectionNetwork{{DeviceID: "33333333333333333333333333333333", Position: 0}},
	}
	if err := selection.Validate(); err != nil {
		t.Fatal(err)
	}
	first := selection.SnapshotID()
	second := selection.SnapshotID()
	if first == "" || first != second {
		t.Fatalf("snapshot id = %q / %q", first, second)
	}
	// The selection carries no rendered bytes: a byte change cannot be part of
	// the hash because the model has no such field.
	encoded, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "mixed-port") || strings.Contains(string(encoded), "outbounds") {
		t.Fatalf("the selection snapshot carries rendered bytes: %s", encoded)
	}
	changed := selection
	changed.Rules = []SelectionRule{{StableKey: "preset-direct-cn", Version: 2, Position: 0}}
	if changed.SnapshotID() == first {
		t.Fatal("a rule revision change did not change the snapshot id")
	}
	duplicate := selection
	duplicate.Lines = []SelectionLine{{NodeID: "11111111111111111111111111111111", Position: 0}, {NodeID: "44444444444444444444444444444444", Position: 0}}
	if err := duplicate.Validate(); err == nil {
		t.Fatal("a duplicate position was accepted")
	}
}

func anyBlocking(diagnostics []Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Level == DiagnosticBlocking {
			return true
		}
	}
	return false
}

func hasBlocking(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Level == DiagnosticBlocking {
			return true
		}
	}
	return false
}

func hasReminder(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Level == DiagnosticReminder {
			return true
		}
	}
	return false
}
