package subscription

import (
	"strings"
	"testing"
)

// The makers are direct entry points, not one dispatcher. Each test below pins
// the boundary that makes that safe: a target either renders its own material
// or refuses it, never silently drops it.

func TestBuildLineBlockAggregatesOneSelector(t *testing.T) {
	lines := []Line{
		goldenLine(goldenLineTwoNodeID, "东京 02", 2),
		goldenLine(goldenLineOneNodeID, "香港 01", 1),
	}
	credentials := []Credential{
		goldenCredential("dddddddddddddddddddddddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", goldenLineTwoNodeID),
		goldenCredential("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", goldenLineOneNodeID),
	}
	plan, err := buildExportPlan(lines, credentials)
	if err != nil {
		t.Fatal(err)
	}
	block := buildLineBlock(plan.Nodes)
	if len(block.Outbounds) != 2 {
		t.Fatalf("outbounds = %d, want 2", len(block.Outbounds))
	}
	if block.Outbounds[0].NodeID != goldenLineOneNodeID || block.Outbounds[1].NodeID != goldenLineTwoNodeID {
		t.Fatalf("outbound order = %q, %q; want SortOrder then NodeID", block.Outbounds[0].NodeID, block.Outbounds[1].NodeID)
	}
	if block.Selector.Default != block.Outbounds[0].Label {
		t.Fatalf("selector default = %q, want the first label %q", block.Selector.Default, block.Outbounds[0].Label)
	}
	if len(block.Selector.Outbounds) != 2 || block.Selector.Outbounds[0] != block.Outbounds[0].Label {
		t.Fatalf("selector outbounds = %v", block.Selector.Outbounds)
	}
	if !strings.Contains(block.Selector.Default, "["+goldenLineOneNodeID+"]") {
		t.Fatalf("label %q does not carry the stable node id", block.Selector.Default)
	}
}

func TestBuildLineBlockEmptyIsZero(t *testing.T) {
	block := buildLineBlock(nil)
	if len(block.Outbounds) != 0 || block.Selector.Default != "" || len(block.Selector.Outbounds) != 0 {
		t.Fatalf("empty block = %+v, want the zero value", block)
	}
}

func TestBuildClientRoutePlanMapsActions(t *testing.T) {
	rendered, diagnostics := renderComposeRules(composeRules())
	if hasBlockingDiagnostics(diagnostics) {
		t.Fatalf("rules blocked: %+v", diagnostics)
	}
	plan := buildClientRoutePlan(rendered)
	if plan.Final != composeEgressProxy {
		t.Fatalf("final = %q, want proxy", plan.Final)
	}
	seen := map[composeEgress]bool{}
	for _, rule := range plan.Rules {
		seen[rule.Egress] = true
	}
	for _, want := range []composeEgress{composeEgressDirect, composeEgressProxy, composeEgressReject} {
		if !seen[want] {
			t.Fatalf("client plan is missing the %q egress: %+v", want, plan.Rules)
		}
	}
	if len(plan.RuleSets) == 0 {
		t.Fatal("client plan declares no rule set")
	}
	for _, set := range plan.RuleSets {
		want := "domain"
		if strings.HasPrefix(set.Tag, "geoip-") {
			want = "ipcidr"
		}
		if set.Behavior != want {
			t.Fatalf("rule set %q behavior = %q, want %q", set.Tag, set.Behavior, want)
		}
	}
}

// TestBuildClientRoutePlanMapsProxyToOut pins the client-chain mapping: with a
// selected egress every proxy rule names the Out tag, so the client hops
// Line -> Out itself; the final egress stays the Line selector, so unmatched
// traffic is never silently sent through the Out.
func TestBuildClientRoutePlanMapsProxyToOut(t *testing.T) {
	rendered, diagnostics := renderComposeRules(composeRules())
	if hasBlockingDiagnostics(diagnostics) {
		t.Fatalf("rules blocked: %+v", diagnostics)
	}
	plan := buildClientRoutePlan(rendered)
	if plan.Final != composeEgressProxy {
		t.Fatalf("final = %q, want the Line selector", plan.Final)
	}
	line := goldenLine(goldenLineOneNodeID, "香港 01", 1)
	block := buildLineBlock([]exportNode{{Line: line, UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Label: line.DisplayName}})
	out := buildOutEgress(&ComposeOut{OutID: goldenOutID, Server: "out.example.invalid", Port: 443, LinkKey: goldenLinkKey})
	if out == nil {
		t.Fatal("a selected Out built no egress")
	}
	// Without an Out the proxy rules keep naming the selector; that is the
	// frozen direct-subscription shape.
	direct, err := makeStandardSingBoxDocument(composeRouterPlan{Lines: block.Outbounds, Selector: block.Selector, Route: plan})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(direct), `"outbound": "meshmux-selector"`) {
		t.Fatalf("a direct subscription lost its selector route:\n%s", direct)
	}
	if strings.Contains(string(direct), `"tag": "out"`) {
		t.Fatalf("a direct subscription grew an Out egress:\n%s", direct)
	}
	singBox, err := makeStandardSingBoxDocument(composeRouterPlan{
		Lines: block.Outbounds, Selector: block.Selector, Out: out, Route: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"outbound": "out"`, `"outbound": "direct"`, `"action": "reject"`, `"final": "meshmux-selector"`} {
		if !strings.Contains(string(singBox), want) {
			t.Fatalf("client document is missing %s:\n%s", want, singBox)
		}
	}
	if strings.Contains(string(singBox), `"outbound": "meshmux-selector"`) {
		t.Fatalf("a proxy rule still names the selector while an Out is selected:\n%s", singBox)
	}
	// Byte determinism of the whole document, not just of one fragment.
	again, err := makeStandardSingBoxDocument(composeRouterPlan{
		Lines: block.Outbounds, Selector: block.Selector, Out: out, Route: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(singBox) != string(again) {
		t.Fatal("the client document is not byte-deterministic")
	}
}

// TestMakersRefuseForeignMaterial pins that no target silently drops material it
// cannot express. A dispatcher that guessed the target from the plan shape would
// make these refusals unreachable.
func TestMakersRefuseForeignMaterial(t *testing.T) {
	line := goldenLine(goldenLineOneNodeID, "香港 01", 1)
	block := buildLineBlock([]exportNode{{Line: line, UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Label: line.DisplayName}})
	meshRoute := composeRoutePlan{
		Rules: []composeRouteRule{{
			Matcher: composeMatcher{Kind: MatcherIPCIDR, Values: []string{MeshTailnetIPv4Prefix}},
			Egress:  composeEgressEndpoint,
			Target:  exportMeshEndpointTag,
		}},
		Final: composeEgressProxy,
	}
	endpoint := composeEndpoint{Tag: exportMeshEndpointTag, ControlURL: "https://headscale.example.invalid", Hostname: "ipad-mesh"}

	cases := []struct {
		name string
		plan composeRouterPlan
		code string
	}{
		{"mihomo endpoint", composeRouterPlan{Lines: block.Outbounds, Selector: block.Selector, Route: meshRoute, Endpoints: []composeEndpoint{endpoint}}, CodeComposeMihomoUnsupported},
		{"standard endpoint", composeRouterPlan{Lines: block.Outbounds, Selector: block.Selector, Route: meshRoute}, "COMPOSE_ROUTE_RENDER_FAILED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.code == CodeComposeMihomoUnsupported {
				_, err = makeMihomoDocument(tc.plan)
			} else {
				_, err = makeStandardSingBoxDocument(tc.plan)
			}
			if err == nil || !strings.HasPrefix(err.Error(), tc.code) {
				t.Fatalf("error = %v, want %s", err, tc.code)
			}
		})
	}

	// The mesh maker refuses a standard client route instead of guessing.
	if _, err := makeMeshSingBoxDocument(composeRouterPlan{
		Lines: block.Outbounds, Selector: block.Selector,
		Route: composeRoutePlan{Rules: []composeRouteRule{{
			Matcher: composeMatcher{Kind: MatcherDomain, Values: []string{"ai.example.invalid"}},
			Egress:  composeEgressProxy,
		}}, Final: composeEgressProxy},
	}); err == nil || !strings.HasPrefix(err.Error(), "COMPOSE_ROUTE_RENDER_FAILED") {
		t.Fatalf("mesh maker accepted a client route: %v", err)
	}
}

func TestComposeSubscriptionRefusesOutWithoutProxyRule(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, goldenLineOneNodeID, "香港 01", 1)}
	outs := []ComposeOut{{OutID: goldenOutID, Server: "out.example.invalid", Port: 443, LinkKey: goldenLinkKey}}
	rules := []ComposeRule{{
		StableKey: "preset-direct-cn", Version: 1, Action: ActionDirect, Kind: MatcherGeoSite,
		Values: []string{"cn"}, Pins: map[string]RuleSetPin{"cn": composePins()},
	}}
	documents, diagnostics := ComposeSubscription(lines, outs, rules, nil)
	if len(documents.SingBox) != 0 || len(documents.Mihomo) != 0 {
		t.Fatal("an Out without a proxy rule produced an artifact")
	}
	if !hasBlockingCode(diagnostics, CodeComposeOutUnused) {
		t.Fatalf("diagnostics = %+v, want %s", diagnostics, CodeComposeOutUnused)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == CodeComposeOutRecorded {
			t.Fatal("a refused Out was still announced as recorded")
		}
	}
}

// TestContentIDIsTheApprovalCredential pins the artifact identity contract: the
// content id changes when any rendered byte changes and stays equal for an
// identical re-render, which is what a download compares against.
func TestContentIDIsTheApprovalCredential(t *testing.T) {
	lines, outs, rules, network := goldenSelection()
	first, diagnostics := ComposeSubscription(lines, outs, rules, network)
	if anyBlocking(diagnostics) {
		t.Fatalf("blocked: %+v", diagnostics)
	}
	second, _ := ComposeSubscription(lines, outs, rules, network)
	if first.ContentID != second.ContentID {
		t.Fatalf("content id = %q / %q, want one stable value", first.ContentID, second.ContentID)
	}
	renamed := append([]ComposeLine(nil), lines...)
	renamed[0].Line.DisplayName = "香港 01 改名"
	third, _ := ComposeSubscription(renamed, outs, rules, network)
	if third.ContentID == first.ContentID {
		t.Fatal("a renamed Line kept the approved content id")
	}
}
