package subscription

// The kernel-neutral composer IR. Validation and selection live in
// compose.go; the stages fill this plan and the makers in render.go turn it
// into bytes. No maker reads an Action, an exportNode or a kernel tag rule:
// actions are mapped exactly once here, and a new matcher or maker is an
// additive change to this file and the target maker only.
//
// Flow of one composition:
//
//	input (four wizard groups)
//	  -> buildComposeSelection: shape checks, ordering, rule overlap checks
//	     (deterministic, no I/O); a blocking finding stops here
//	  -> composeDocuments: stage 1 mesh material (sing-box only), stage 2 one
//	     Line selector block, stage 3 the client egress (Line selector + the
//	     selected Out) and the client route; then the target makers
//	  -> ComposeDocuments: two documents, SelectionID, ContentID (the approval
//	     credential)
//
// There is no server route stage: under client-chain egress the Line only
// serves its own inbound, and the Out is one more egress the client dials.
//
// Nothing here reads a clock, a database, the network or a random source; the
// same input always yields the same bytes.

import (
	"sort"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// composeEgress is the target-neutral egress of one routed rule. The three
// library egresses reuse the shared action spellings; the endpoint exists only
// here, because "the mesh endpoint" is a routing fact no rule library row can
// state. A proxy rule names the Out tag when the selection carries an Out and
// the Line selector otherwise; that is decided once, in buildClientRoutePlan.
//
// These names are IR identifiers, not kernel tags: a maker maps "reject" to the
// kernel's reject action and "endpoint" to its own endpoint tag, which is why
// the tag literals live in internal/core/node/protocol and not here.
type composeEgress string

const (
	composeEgressDirect   composeEgress = composeEgress(ir.ActionDirect)
	composeEgressProxy    composeEgress = composeEgress(ir.ActionProxy)
	composeEgressReject   composeEgress = composeEgress(ir.ActionReject)
	composeEgressEndpoint composeEgress = "endpoint"
)

// composeMatcher is one validated matcher in render order. Tags and Sources
// are aligned: Tags[i] is declared with Sources[i].
type composeMatcher struct {
	Kind    MatcherKind
	Values  []string
	Tags    []string
	Sources []string
}

// composeRouteRule couples one matcher to one egress. Target is only set for
// an endpoint egress (the mesh Tailscale tag).
type composeRouteRule struct {
	Matcher composeMatcher
	Egress  composeEgress
	Target  string
}

// composeRuleSet is one declared remote artifact. Behavior is derived from the
// tag prefix so both kernels agree on the rule-provider behavior.
type composeRuleSet struct {
	Tag      string
	Source   string
	Behavior string
}

// composeRoutePlan is the only route structure a maker consumes.
type composeRoutePlan struct {
	Rules    []composeRouteRule
	RuleSets []composeRuleSet
	Final    composeEgress
}

// composeLineOutbound is one VLESS outbound material of a selected Line.
type composeLineOutbound struct {
	NodeID     string
	Label      string
	Server     string
	Port       int
	UUID       string
	ServerName string
	PublicKey  string
	ShortID    string
}

// composeSelector is the single client select group over the selected Lines.
type composeSelector struct {
	Default   string
	Outbounds []string
}

// composeLineBlock is stage 2: all selected Lines and one selector.
type composeLineBlock struct {
	Outbounds []composeLineOutbound
	Selector  composeSelector
}

// composeOutEgress is stage 3: the selected egress the client dials itself.
// Kind is "" for a MeshMux Out node (the SS link) and ComposeOutHTTP for an
// external HTTP proxy. A nil *composeOutEgress means the subscription selects
// no egress, so every proxy rule names the Line selector.
type composeOutEgress struct {
	Kind     string
	Server   string
	Port     int
	LinkKey  string
	Username string
	Password string
}

// composeEndpoint is one mesh Tailscale endpoint material.
type composeEndpoint struct {
	Tag          string
	AuthKey      string
	ControlURL   string
	Hostname     string
	AcceptRoutes bool
	Ephemeral    bool
}

// composeMeshMaterial is stage 1: the sing-box-only mesh endpoint and rule.
type composeMeshMaterial struct {
	Endpoint composeEndpoint
	Rules    []composeRouteRule
}

// composeRouterPlan is the complete input of one maker.
type composeRouterPlan struct {
	Endpoints []composeEndpoint
	Lines     []composeLineOutbound
	Selector  composeSelector
	Out       *composeOutEgress
	Route     composeRoutePlan
}

// composeSelection is the validated, ordered input of the document stage.
type composeSelection struct {
	Lines    []ComposeLine
	Out      *ComposeOut
	Rules    []ComposeRule
	Rendered []composeRenderedRule
	Network  []ComposeNetwork
}

// buildLineBlock aggregates the paired Lines into VLESS material and one
// selector. The first Line in detection order (SortOrder, then NodeID) is the
// selector default; the order is the same in both client documents.
func buildLineBlock(nodes []exportNode) composeLineBlock {
	block := composeLineBlock{
		Outbounds: make([]composeLineOutbound, 0, len(nodes)),
		Selector:  composeSelector{Outbounds: make([]string, 0, len(nodes))},
	}
	for _, node := range nodes {
		block.Outbounds = append(block.Outbounds, composeLineOutbound{
			NodeID:     node.Line.NodeID,
			Label:      node.Label,
			Server:     node.Line.Server,
			Port:       node.Line.Port,
			UUID:       node.UUID,
			ServerName: node.Line.ServerName,
			PublicKey:  node.Line.PublicKey,
			ShortID:    node.Line.ShortID,
		})
		block.Selector.Outbounds = append(block.Selector.Outbounds, node.Label)
	}
	if len(block.Outbounds) > 0 {
		block.Selector.Default = block.Outbounds[0].Label
	}
	return block
}

// buildComposeRuleSets declares every referenced remote artifact exactly once
// in first-use order. Behavior is the fixed prefix rule shared by both kernels.
//
// A tag with no source declares nothing: a geo or rule-set identifier the
// operator configured without a pin is a bare tag the client kernel resolves on
// its own (or refuses), not a remote file this composer may fetch. Only a
// pinned artifact contributes a rule-set declaration.
func buildComposeRuleSets(rules []composeRenderedRule) []composeRuleSet {
	sets := make([]composeRuleSet, 0, len(rules))
	declared := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		for index, tag := range rule.tags {
			if index >= len(rule.sources) || rule.sources[index] == "" {
				continue
			}
			if _, exists := declared[tag]; exists {
				continue
			}
			declared[tag] = struct{}{}
			behavior := "domain"
			if kind, _, isGeo := ir.SplitGeoTag(tag); isGeo && kind == ir.MatcherGeoIP {
				behavior = "ipcidr"
			}
			sets = append(sets, composeRuleSet{Tag: tag, Source: rule.sources[index], Behavior: behavior})
		}
	}
	return sets
}

// buildComposeMatcher maps one validated rule to its IR matcher. It copies the
// slices so a later caller cannot mutate the validated selection.
func buildComposeMatcher(rule composeRenderedRule) composeMatcher {
	return composeMatcher{
		Kind:    rule.kind,
		Values:  append([]string(nil), rule.values...),
		Tags:    append([]string(nil), rule.tags...),
		Sources: append([]string(nil), rule.sources...),
	}
}

// buildClientRoutePlan is stage 4: library actions become the client egresses.
// A proxy rule points at the Out tag when the selection carries an egress and
// at the selector otherwise, direct at the explicit direct outbound and reject
// at the kernel's reject action. The final egress is always the selector: a
// subscription sends the traffic its rules do not match over the Line, and the
// Out is only ever reached through a proxy rule.
func buildClientRoutePlan(rules []composeRenderedRule) composeRoutePlan {
	plan := composeRoutePlan{
		Rules:    make([]composeRouteRule, 0, len(rules)),
		RuleSets: buildComposeRuleSets(rules),
		Final:    composeEgressProxy,
	}
	for _, rule := range rules {
		egress := composeEgressDirect
		switch rule.action {
		case ActionProxy:
			egress = composeEgressProxy
		case ActionReject:
			egress = composeEgressReject
		}
		plan.Rules = append(plan.Rules, composeRouteRule{Matcher: buildComposeMatcher(rule), Egress: egress})
	}
	return plan
}

// buildOutEgress is stage 3: the selected egress the client dials itself. A
// nil selection yields a nil egress, so a direct subscription keeps the frozen
// selector-only bytes. The credential shape is chosen by Kind: an Out node
// carries the SS link key, an external HTTP proxy its optional Basic pair.
func buildOutEgress(out *ComposeOut) *composeOutEgress {
	if out == nil {
		return nil
	}
	return &composeOutEgress{
		Kind:     out.Kind,
		Server:   out.Server,
		Port:     out.Port,
		LinkKey:  out.LinkKey,
		Username: out.Username,
		Password: out.Password,
	}
}

// buildMeshMaterial is stage 1: the mesh-only sing-box material. It never
// contributes a client document and never enters the mihomo maker.
func buildMeshMaterial(input MeshDeviceInput, model MeshConfigModel, purpose meshPurposeDocument) composeMeshMaterial {
	return composeMeshMaterial{
		Endpoint: composeEndpoint{
			Tag:          exportMeshEndpointTag,
			AuthKey:      input.AuthKey,
			ControlURL:   model.ControlURL,
			Hostname:     model.Hostname,
			AcceptRoutes: purpose.acceptRoutes,
			Ephemeral:    false,
		},
		Rules: []composeRouteRule{{
			Matcher: composeMatcher{Kind: MatcherIPCIDR, Values: append([]string(nil), model.TailnetPrefixes...)},
			Egress:  composeEgressEndpoint,
			Target:  exportMeshEndpointTag,
		}},
	}
}

// hasBlockingDiagnostics reports whether any finding refuses the artifact.
func hasBlockingDiagnostics(diagnostics []Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Level == DiagnosticBlocking {
			return true
		}
	}
	return false
}

// buildComposeSelection validates the four wizard groups and returns the
// ordered selection. The diagnostic order is part of the Web contract: every
// Line finding is followed by the Out finding, the rule findings, the
// Out-without-proxy finding, then the two reminders.
func buildComposeSelection(lines []ComposeLine, outs []ComposeOut, rules []ComposeRule, network []ComposeNetwork) (composeSelection, []Diagnostic) {
	diagnostics := make([]Diagnostic, 0, 8)
	block := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticBlocking, Code: code, Detail: detail})
	}
	remind := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticReminder, Code: code, Detail: detail})
	}

	if len(lines) == 0 {
		block(CodeComposeNoLines, "至少选择一条 Line")
		return composeSelection{}, diagnostics
	}
	selected := make([]ComposeLine, 0, len(lines))
	seenLines := make(map[string]struct{}, len(lines))
	for _, entry := range lines {
		if err := validateExportLine(entry.Line); err != nil {
			block(CodeComposeLineInvalid, "Line 传输参数不完整")
			continue
		}
		if _, duplicate := seenLines[entry.Line.NodeID]; duplicate {
			block(CodeComposeLineInvalid, "Line 被重复选择")
			continue
		}
		if err := entry.Credential.Validate(); err != nil {
			block(CodeComposeCredentialInvalid, "凭据不是规范记录")
			continue
		}
		if entry.Credential.NodeID != entry.Line.NodeID {
			block(CodeComposeCredentialInvalid, "凭据与 Line 不匹配")
			continue
		}
		seenLines[entry.Line.NodeID] = struct{}{}
		selected = append(selected, entry)
	}
	sortComposeLines(selected)

	if len(outs) > MaxOutsPerSubscription {
		block(CodeComposeOutLimit, "1.0 每个订阅最多选择 1 个 Out")
	}
	var out *ComposeOut
	if len(outs) == 1 {
		candidate := outs[0]
		if err := validateComposeOut(candidate); err != nil {
			block(CodeComposeOutInvalid, err.Error())
		} else {
			out = &candidate
		}
	}

	rendered, ruleDiagnostics := renderComposeRules(rules)
	diagnostics = append(diagnostics, ruleDiagnostics...)
	if out != nil && !hasBlockingDiagnostics(diagnostics) {
		proxyRules := 0
		for _, rule := range rendered {
			if rule.action == ActionProxy {
				proxyRules++
			}
		}
		if proxyRules == 0 {
			// An Out that no rule routes to would be an egress the client never
			// dials: the operator asked for a hop the document cannot express.
			// Refuse instead of silently shipping an unused credential.
			block(CodeComposeOutUnused, "已选择出口，但没有任何代理规则使用它；请为规则选择代理动作或取消出口")
		}
	}
	if hasBlockingDiagnostics(diagnostics) {
		return composeSelection{}, diagnostics
	}
	if out != nil {
		remind(CodeComposeOutRecorded, "出口选择已记录；出口凭据随客户端文档下发，客户端按代理规则直接连接出口")
	}
	if len(network) > 0 {
		remind(CodeComposeNetworkRecorded, "组网设备选择已记录；Mesh 子网路由执行待 1.1，本订阅不包含 Mesh 端点")
	}
	return composeSelection{Lines: selected, Out: out, Rules: rules, Rendered: rendered, Network: network}, diagnostics
}

// sortComposeLines orders the selection by SortOrder then NodeID. The helper is
// separate so the ordering rule has exactly one implementation.
func sortComposeLines(selected []ComposeLine) {
	sort.SliceStable(selected, func(i, j int) bool {
		left, right := selected[i].Line, selected[j].Line
		if left.SortOrder != right.SortOrder {
			return left.SortOrder < right.SortOrder
		}
		return left.NodeID < right.NodeID
	})
}

// composeDocuments renders the two client documents and both identities from
// one validated selection. The Line publishes no route: the Out lives in the
// client documents, so there is no fragment to render.
func composeDocuments(selection composeSelection) (ComposeDocuments, []Diagnostic) {
	diagnostics := make([]Diagnostic, 0, 2)
	block := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticBlocking, Code: code, Detail: detail})
	}

	baseLines := make([]Line, 0, len(selection.Lines))
	credentials := make([]Credential, 0, len(selection.Lines))
	for _, entry := range selection.Lines {
		baseLines = append(baseLines, entry.Line)
		credentials = append(credentials, entry.Credential)
	}
	plan, err := buildExportPlan(baseLines, credentials)
	if err != nil {
		// Selection validation already checked each Line and credential; only
		// the cross-credential subscriber check can still refuse here, and the
		// historical surface for it is the sing-box refusal.
		block(CodeComposeLineInvalid, "sing-box 客户端文档无法组装")
		return ComposeDocuments{}, diagnostics
	}
	blockLines := buildLineBlock(plan.Nodes)
	clientRoute := buildClientRoutePlan(selection.Rendered)
	outEgress := buildOutEgress(selection.Out)

	singBox, err := makeStandardSingBoxDocument(composeRouterPlan{
		Lines:    blockLines.Outbounds,
		Selector: blockLines.Selector,
		Out:      outEgress,
		Route:    clientRoute,
	})
	if err != nil {
		block(CodeComposeLineInvalid, "sing-box 客户端文档无法组装")
		return ComposeDocuments{}, diagnostics
	}
	mihomo, err := makeMihomoDocument(composeRouterPlan{
		Lines:    blockLines.Outbounds,
		Selector: blockLines.Selector,
		Out:      outEgress,
		Route:    clientRoute,
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), CodeComposeMihomoUnsupported) {
			block(CodeComposeMihomoUnsupported, "所选规则包含 Mihomo 无法表达的能力")
		} else {
			block(CodeComposeLineInvalid, "Mihomo 客户端文档无法组装")
		}
		return ComposeDocuments{}, diagnostics
	}

	// LineRoutes stays nil: the Line publishes no route for a subscription any
	// more (client-chain egress). The field is kept only for source
	// compatibility and is removed in a later v1 release.
	documents := ComposeDocuments{SingBox: singBox, Mihomo: mihomo}
	documents.SelectionID = composeSelectionID(baseLines, selection.Out, selection.Rules, selection.Network)
	documents.ContentID = composeContentID(documents)
	return documents, diagnostics
}
