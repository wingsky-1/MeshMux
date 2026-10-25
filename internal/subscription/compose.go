package subscription

// The subscription composer is the single renderer of one subscription's client
// documents and of the Line route fragments the subscription asks for. It is a
// pure function: no I/O, no clock, no database. The same selection always
// produces byte-identical documents and one stable content id, so a download
// can be re-derived and compared instead of being trusted from a cached copy.
//
// The composer owns its own small rule model instead of importing
// internal/compiler: compiler already imports this package (the mesh model), so
// the dependency would be a cycle. The two models share the same six matcher
// kinds and the same canonical value rules; compose_drift_test.go compares both
// so they cannot silently diverge.
//
// Composition never executes anything. A selected Out is recorded and rendered into
// the Line route fragment (the double-hop egress the Line publishes); it is a routing
// choice for the client document, not an authorization (Ruling R10: the Out allowlist
// is node membership, and a subscription edit never touches it). A selected mesh device
// is recorded only: the standard subscription never grows a Tailscale endpoint.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MaxOutsPerSubscription is the 1.0 single-Out constraint. The Out pool itself
// is unbounded; one subscription may select at most this many Out nodes, and
// the store enforces the same bound with a table constraint.
const MaxOutsPerSubscription = 1

// DiagnosticLevel separates a reminder from a blocking finding. A reminder is
// rendered with "!" and never blocks a save or a download; a blocking finding
// is rendered with "✖" and refuses the artifact.
type DiagnosticLevel string

const (
	DiagnosticReminder DiagnosticLevel = "reminder"
	DiagnosticBlocking DiagnosticLevel = "blocking"
)

// Stable composer codes. Only the code is stable; Detail is operator text.
const (
	CodeComposeNoLines           = "COMPOSE_NO_LINES"
	CodeComposeLineInvalid       = "COMPOSE_LINE_INVALID"
	CodeComposeCredentialInvalid = "COMPOSE_CREDENTIAL_INVALID"
	CodeComposeOutLimit          = "COMPOSE_OUT_LIMIT"
	CodeComposeOutInvalid        = "COMPOSE_OUT_INVALID"
	CodeComposeOutUnused         = "COMPOSE_OUT_WITHOUT_PROXY_RULE"
	CodeComposeRuleInvalid       = "COMPOSE_RULE_INVALID"
	CodeComposeRuleDuplicate     = "COMPOSE_RULE_DUPLICATE"
	CodeComposeRuleConflict      = "COMPOSE_RULE_CONFLICT"
	CodeComposeRulesetUnpinned   = "COMPOSE_RULESET_UNPINNED"
	CodeComposeMihomoUnsupported = "COMPOSE_MIHOMO_UNSUPPORTED"
	CodeComposeNetworkRecorded   = "COMPOSE_NETWORK_RECORDED_ONLY"
	CodeComposeOutRecorded       = "COMPOSE_OUT_RECORDED_PENDING"
)

// Action is the library egress of one selected rule. It mirrors the rule
// library: direct, proxy or reject. There is no Out action here; the Out is
// selected once per subscription, never per rule.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionReject Action = "reject"
)

// MatcherKind is the single matcher family of one rule. It mirrors the six
// kinds the rule library stocks.
type MatcherKind string

const (
	MatcherDomain       MatcherKind = "domain"
	MatcherDomainSuffix MatcherKind = "domain_suffix"
	MatcherIPCIDR       MatcherKind = "ipcidr"
	MatcherGeoSite      MatcherKind = "geosite"
	MatcherGeoIP        MatcherKind = "geoip"
	MatcherRuleSet      MatcherKind = "ruleset"
)

// RuleSetPin is the version lock of one external rule-set artifact. It mirrors
// route.RulesetPin (HTTPS source, immutable version, lowercase SHA-256); the
// composer re-implements the check because it cannot import internal/route
// without a cycle. compose_drift_test.go keeps the two in step.
type RuleSetPin struct {
	Source  string
	Version string
	SHA256  string
}

// Validate rejects a mutable or malformed artifact pin before any document is
// rendered, so a client configuration can never name an unpinned file.
func (p RuleSetPin) Validate() error {
	invalid := func(reason string) error {
		return errors.New(CodeComposeRulesetUnpinned + ": " + reason)
	}
	if p.Source == "" || len(p.Source) > 512 || strings.TrimSpace(p.Source) != p.Source {
		return invalid("the source must be one exact URL")
	}
	parsed, err := url.Parse(p.Source)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || strings.ContainsAny(p.Source, " \t\r\n") {
		return invalid("the source must be one exact public HTTPS URL without credentials, query or fragment")
	}
	if addr, addrErr := netip.ParseAddr(parsed.Hostname()); addrErr == nil {
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
			return invalid("the source must not be a loopback, private or unspecified literal address")
		}
	}
	if host := parsed.Hostname(); host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return invalid("the source must be a public rule-set host")
	}
	if !composePinVersionPattern.MatchString(p.Version) || composeMutableVersions[strings.ToLower(p.Version)] {
		return invalid("the version must be one immutable label")
	}
	if len(p.SHA256) != 64 {
		return invalid("the digest must be 64 lowercase hex characters")
	}
	for index := 0; index < len(p.SHA256); index++ {
		if !isLowerHex(p.SHA256[index]) {
			return invalid("the digest must be 64 lowercase hex characters")
		}
	}
	return nil
}

var (
	composePinVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$`)
	composeMutableVersions   = map[string]bool{
		"latest": true, "head": true, "main": true, "master": true,
		"stable": true, "dev": true, "nightly": true,
	}
	composeTagPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	composeDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Diagnostic is one composer finding. Detail never carries a credential, a
// token, a URL with a query or a document byte.
type Diagnostic struct {
	Level  DiagnosticLevel
	Code   string
	Detail string
}

// ComposeLine is one selected Line together with the credential that belongs to
// it. The pair is validated as a whole: a credential of another Line or another
// Subscriber would publish somebody else's identity.
type ComposeLine struct {
	Line       Line
	Credential Credential
}

// ComposeOutHTTP marks one egress slot entry whose endpoint is an external
// HTTP proxy (Ruling R11) instead of a MeshMux Out node. The composer only
// needs the fact: the proxy credentials never enter a client document, they
// stay in the Line candidate's private egress.
const ComposeOutHTTP = "http"

// ComposeOut is one selected egress: an Out node or an external HTTP proxy.
// The 1.0 slot always holds at most one entry; Kind distinguishes the two
// shapes for the UI, the selection identity and validation. It carries no
// credential: the Line presents the Hub-issued link credential on its own
// candidate path, never in a subscription document.
type ComposeOut struct {
	OutID       string
	DisplayName string
	Server      string
	Port        int
	// Kind is "" (or "out") for a MeshMux Out node and ComposeOutHTTP for an
	// external HTTP proxy.
	Kind string
}

// ComposeRule is one pinned library revision in the subscription's order.
// Pins is keyed by the geo code or the remote rule-set tag the rule names.
type ComposeRule struct {
	StableKey string
	Version   int
	Action    Action
	Kind      MatcherKind
	Values    []string
	Pins      map[string]RuleSetPin
}

// ComposeNetwork is one selected mesh device. It is recorded and displayed; the
// standard subscription never executes a mesh path.
type ComposeNetwork struct {
	DeviceID    string
	DisplayName string
}

// LineRoute is the server route fragment one selected Line has to publish for
// this subscription. It names the Out tag; the Out body and its authorization
// stay on the existing Out path.
type LineRoute struct {
	NodeID   string
	Fragment []byte
}

// ComposeDocuments is the assembled artifact: the two client documents, the
// per-Line route fragments, the selection identity and the content id.
type ComposeDocuments struct {
	SingBox     []byte
	Mihomo      []byte
	LineRoutes  []LineRoute
	SelectionID string
	ContentID   string
}

// ComposeSubscription assembles one subscription from its recorded selection.
//
// The four inputs are the four wizard groups. A blocking diagnostic always
// produces no document: the caller can never publish half an artifact.
func ComposeSubscription(lines []ComposeLine, outs []ComposeOut, rules []ComposeRule, network []ComposeNetwork) (ComposeDocuments, []Diagnostic) {
	diagnostics := make([]Diagnostic, 0, 8)
	block := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticBlocking, Code: code, Detail: detail})
	}
	remind := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticReminder, Code: code, Detail: detail})
	}
	hasBlocking := func() bool {
		for _, diagnostic := range diagnostics {
			if diagnostic.Level == DiagnosticBlocking {
				return true
			}
		}
		return false
	}

	if len(lines) == 0 {
		block(CodeComposeNoLines, "至少选择一条 Line")
		return ComposeDocuments{}, diagnostics
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
	sort.SliceStable(selected, func(i, j int) bool {
		left, right := selected[i].Line, selected[j].Line
		if left.SortOrder != right.SortOrder {
			return left.SortOrder < right.SortOrder
		}
		return left.NodeID < right.NodeID
	})

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
	if out != nil && !hasBlocking() {
		proxyRules := 0
		for _, rule := range rendered {
			if rule.action == ActionProxy {
				proxyRules++
			}
		}
		if proxyRules == 0 {
			// An Out that no rule selects would render a Line route that never
			// uses it: the operator asked for a double hop the document cannot
			// express. Refuse instead of silently keeping the Line egress.
			block(CodeComposeOutUnused, "已选择出口，但没有任何代理规则使用它；请为规则选择代理动作或取消出口")
		}
	}
	if hasBlocking() {
		return ComposeDocuments{}, diagnostics
	}
	if out != nil {
		remind(CodeComposeOutRecorded, "出口选择已记录；Line 路由片段按所选出口渲染并通过内核门禁")
	}
	if len(network) > 0 {
		remind(CodeComposeNetworkRecorded, "组网设备选择已记录；Mesh 子网路由执行待 1.1，本订阅不包含 Mesh 端点")
	}

	baseLines := make([]Line, 0, len(selected))
	credentials := make([]Credential, 0, len(selected))
	for _, entry := range selected {
		baseLines = append(baseLines, entry.Line)
		credentials = append(credentials, entry.Credential)
	}
	singBox, err := exportSingBoxWithRules(baseLines, credentials, rendered)
	if err != nil {
		block(CodeComposeLineInvalid, "sing-box 客户端文档无法组装")
		return ComposeDocuments{}, diagnostics
	}
	mihomo, err := exportMihomoWithRules(baseLines, credentials, rendered)
	if err != nil {
		if strings.HasPrefix(err.Error(), CodeComposeMihomoUnsupported) {
			block(CodeComposeMihomoUnsupported, "所选规则包含 Mihomo 无法表达的能力")
		} else {
			block(CodeComposeLineInvalid, "Mihomo 客户端文档无法组装")
		}
		return ComposeDocuments{}, diagnostics
	}

	documents := ComposeDocuments{SingBox: singBox, Mihomo: mihomo, LineRoutes: []LineRoute{}}
	if out != nil {
		fragment, err := renderLineRoute(rendered)
		if err != nil {
			block(CodeComposeRuleInvalid, "Line 路由片段无法渲染")
			return ComposeDocuments{}, diagnostics
		}
		for _, entry := range selected {
			documents.LineRoutes = append(documents.LineRoutes, LineRoute{NodeID: entry.Line.NodeID, Fragment: fragment})
		}
	}
	documents.SelectionID = composeSelectionID(baseLines, out, rules, network)
	documents.ContentID = composeContentID(documents)
	return documents, diagnostics
}

// validateComposeOut checks the operator-visible half of one egress. The
// endpoint is required: an egress without a configured dial address would
// render a route that names an egress nobody can reach. The kind is either the
// MeshMux Out ("out" or empty) or an external HTTP proxy ("http").
func validateComposeOut(out ComposeOut) error {
	if err := ValidateID(out.OutID); err != nil {
		return errors.New(CodeComposeOutInvalid + ": out_id must be 32 lowercase hex characters")
	}
	switch out.Kind {
	case "", "out", ComposeOutHTTP:
	default:
		return errors.New(CodeComposeOutInvalid + ": the egress kind must be out or http")
	}
	if out.Server == "" || !validHost(out.Server) {
		return errors.New(CodeComposeOutInvalid + ": the out endpoint must be one hostname or IP address")
	}
	if out.Port < 1 || out.Port > 65535 {
		return errors.New(CodeComposeOutInvalid + ": the out port must be 1-65535")
	}
	return nil
}

// composeRenderedRule is one validated rule ready for rendering. tags and
// sources are aligned: tag[i] is declared with sources[i].
type composeRenderedRule struct {
	action  Action
	kind    MatcherKind
	values  []string
	tags    []string
	sources []string
}

// renderComposeRules validates the rule selection and returns the renderable
// order. It reports the duplicate, conflict, invalid-value and unpinned cases
// as blocking findings.
func renderComposeRules(rules []ComposeRule) ([]composeRenderedRule, []Diagnostic) {
	diagnostics := []Diagnostic{}
	block := func(code, detail string) {
		diagnostics = append(diagnostics, Diagnostic{Level: DiagnosticBlocking, Code: code, Detail: detail})
	}
	seen := make(map[string]struct{}, len(rules))
	rendered := make([]composeRenderedRule, 0, len(rules))
	for _, rule := range rules {
		identity := rule.StableKey + " v" + strconv.Itoa(rule.Version)
		if _, duplicate := seen[identity]; duplicate {
			block(CodeComposeRuleDuplicate, "规则 "+identity+" 被重复选择")
			continue
		}
		seen[identity] = struct{}{}
		if rule.Version <= 0 {
			block(CodeComposeRuleInvalid, "规则 "+rule.StableKey+" 缺少有效版本")
			continue
		}
		switch rule.Action {
		case ActionDirect, ActionProxy, ActionReject:
		default:
			block(CodeComposeRuleInvalid, "规则 "+identity+" 的动作不是直连/代理/拒绝")
			continue
		}
		values, tags, sources, err := composeRuleTargets(rule)
		if err != nil {
			if strings.HasPrefix(err.Error(), CodeComposeRulesetUnpinned) {
				block(CodeComposeRulesetUnpinned, "规则 "+identity+"："+strings.TrimPrefix(err.Error(), CodeComposeRulesetUnpinned+": "))
			} else {
				block(CodeComposeRuleInvalid, "规则 "+identity+"："+err.Error())
			}
			continue
		}
		rendered = append(rendered, composeRenderedRule{action: rule.Action, kind: rule.Kind, values: values, tags: tags, sources: sources})
	}
	for i := range rendered {
		for j := i + 1; j < len(rendered); j++ {
			if reason := composeRulesOverlap(rendered[i], rendered[j]); reason != "" {
				block(CodeComposeRuleConflict, reason)
			}
		}
	}
	return rendered, diagnostics
}

// composeRuleTargets validates one matcher family and returns its canonical
// values plus the rendered rule-set tags and their pinned sources.
func composeRuleTargets(rule ComposeRule) ([]string, []string, []string, error) {
	if len(rule.Values) == 0 || len(rule.Values) > 64 {
		return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": a rule needs 1-64 matcher values")
	}
	values := make([]string, 0, len(rule.Values))
	tags := make([]string, 0, len(rule.Values))
	sources := make([]string, 0, len(rule.Values))
	seen := make(map[string]struct{}, len(rule.Values))
	for _, raw := range rule.Values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": matcher values must not be blank")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": matcher value " + value + " repeats")
		}
		seen[value] = struct{}{}
		switch rule.Kind {
		case MatcherDomain, MatcherDomainSuffix:
			if !composeDomainPattern.MatchString(value) {
				return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": a domain must be a canonical lowercase DNS name")
			}
		case MatcherIPCIDR:
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Masked() != prefix {
				return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": every ip_cidr matcher must be a canonical network")
			}
		case MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
			if !composeTagPattern.MatchString(value) {
				return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": geo and rule-set identifiers must be lowercase")
			}
			pin, ok := rule.Pins[value]
			if !ok {
				return nil, nil, nil, errors.New(CodeComposeRulesetUnpinned + ": " + value + " 没有版本锁定的规则集")
			}
			if err := pin.Validate(); err != nil {
				return nil, nil, nil, err
			}
			tag := value + "@" + pin.Version
			switch rule.Kind {
			case MatcherGeoSite:
				tag = "geosite-" + tag
			case MatcherGeoIP:
				tag = "geoip-" + tag
			}
			tags = append(tags, tag)
			sources = append(sources, pin.Source)
		default:
			return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": unknown matcher kind")
		}
		values = append(values, value)
	}
	return values, tags, sources, nil
}

// composeRulesOverlap reports why two rules collide, or "" when disjoint. The
// sampling mirrors the library conflict check: a domain covered by a suffix and
// an IP covered by a wider prefix are both caught, so a later rule can never be
// silently shadowed by an earlier one.
func composeRulesOverlap(a, b composeRenderedRule) string {
	for _, probe := range composeSamples(b) {
		if composeMatches(a, probe) {
			return "规则 " + string(b.kind) + " " + probe + " 被前一条规则覆盖，顺序会静默改变语义"
		}
	}
	for _, probe := range composeSamples(a) {
		if composeMatches(b, probe) {
			return "规则 " + string(a.kind) + " " + probe + " 被后一条规则覆盖，顺序会静默改变语义"
		}
	}
	return ""
}

func composeSamples(rule composeRenderedRule) []string {
	out := make([]string, 0, len(rule.values))
	for _, value := range rule.values {
		switch rule.kind {
		case MatcherDomainSuffix:
			out = append(out, "x."+value)
		case MatcherIPCIDR:
			if prefix, err := netip.ParsePrefix(value); err == nil {
				out = append(out, prefix.Addr().String())
			}
		default:
			out = append(out, value)
		}
	}
	return out
}

func composeMatches(rule composeRenderedRule, probe string) bool {
	for _, value := range rule.values {
		switch rule.kind {
		case MatcherDomain:
			if probe == value {
				return true
			}
		case MatcherDomainSuffix:
			if probe == value || strings.HasSuffix(probe, "."+value) {
				return true
			}
		case MatcherIPCIDR:
			addr, err := netip.ParseAddr(probe)
			if err != nil {
				continue
			}
			if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(addr) {
				return true
			}
		default:
			if probe == value {
				return true
			}
		}
	}
	return false
}

// renderLineRoute renders the server route fragment one selected Line has to
// publish. Direct rules stay on the Line, proxy rules take the Out tag and
// reject rules take the explicit block tag. The final egress stays the Line, so
// an Out never becomes the default path of a subscription that only selects it
// for named rules.
func renderLineRoute(rules []composeRenderedRule) ([]byte, error) {
	rendered := make([]map[string]any, 0, len(rules))
	declared := make(map[string]struct{}, len(rules))
	sets := make([]singBoxClientRuleSet, 0, len(rules))
	for _, rule := range rules {
		outbound := exportSingBoxDirectTag
		switch rule.action {
		case ActionProxy:
			outbound = singBoxOutTag
		case ActionReject:
			outbound = singBoxBlockTag
		}
		entry := map[string]any{"outbound": outbound}
		switch rule.kind {
		case MatcherDomain:
			entry["domain"] = rule.values
		case MatcherDomainSuffix:
			entry["domain_suffix"] = rule.values
		case MatcherIPCIDR:
			entry["ip_cidr"] = rule.values
		default:
			entry["rule_set"] = append([]string(nil), rule.tags...)
			for index, tag := range rule.tags {
				if _, exists := declared[tag]; exists {
					continue
				}
				declared[tag] = struct{}{}
				sets = append(sets, singBoxClientRuleSet{
					Type: "remote", Tag: tag, Format: "binary", URL: rule.sources[index],
				})
			}
		}
		rendered = append(rendered, entry)
	}
	body, err := json.MarshalIndent(struct {
		Rules   []map[string]any       `json:"rules"`
		RuleSet []singBoxClientRuleSet `json:"rule_set,omitempty"`
		Final   string                 `json:"final"`
	}{Rules: rendered, RuleSet: sets, Final: exportSingBoxDirectTag}, "", "  ")
	if err != nil {
		return nil, errors.New("COMPOSE_ROUTE_RENDER_FAILED")
	}
	return append(body, '\n'), nil
}

// composeSelectionID hashes only the selection: the ordered Line identities,
// the Out, the pinned rule revisions and the recorded devices. A rename or a
// rendered byte change never alters it, so it can key the snapshot.
func composeSelectionID(lines []Line, out *ComposeOut, rules []ComposeRule, network []ComposeNetwork) string {
	var builder strings.Builder
	builder.WriteString("meshmux-subscription-selection/1\n")
	for _, line := range lines {
		builder.WriteString("line\t" + line.NodeID + "\t" + strconv.Itoa(line.SortOrder) + "\n")
	}
	if out != nil {
		builder.WriteString("out\t" + out.OutID + "\t" + out.Kind + "\n")
	}
	for _, rule := range rules {
		builder.WriteString("rule\t" + rule.StableKey + "\t" + strconv.Itoa(rule.Version) + "\n")
	}
	for _, device := range network {
		builder.WriteString("network\t" + device.DeviceID + "\n")
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// composeContentID hashes the rendered artifact, so a download can prove it is
// serving exactly the bytes that were composed from the current selection. The
// snapshot identity is deliberately not part of it: two snapshots of the same
// choice must produce the same artifact id, otherwise every re-save would look
// like drift.
func composeContentID(documents ComposeDocuments) string {
	var builder strings.Builder
	builder.WriteString("meshmux-subscription-artifact/1\n")
	builder.WriteString(composeDigest(documents.SingBox) + "\n")
	builder.WriteString(composeDigest(documents.Mihomo) + "\n")
	for _, route := range documents.LineRoutes {
		builder.WriteString("route\t" + route.NodeID + "\t" + composeDigest(route.Fragment) + "\n")
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func composeDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
