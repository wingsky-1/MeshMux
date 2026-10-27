package subscription

// The subscription composer is the single renderer of one subscription's client
// documents. It is a pure function: no I/O, no clock, no database. The same
// selection always produces byte-identical documents and one stable content id,
// so a download can be re-derived and compared instead of being trusted from a
// cached copy.
//
// The composer and the policy generators share one vocabulary from
// internal/core/subscription/ir (six matcher kinds, three actions, the pin and
// CIDR predicates). The IR package is the subscription layer's own definition,
// so the composer imports downward only and policy imports it without a cycle:
// there is
// no second copy left to drift.
//
// Composition never executes anything and publishes no server route. The
// selected Out is rendered into both client documents as one egress the client
// dials itself (client-chain egress): the Line only ever serves its own VLESS
// inbound, and every proxy rule in the document names the Out tag, so a client
// hops Line -> Out without the Line forwarding anything. A selected mesh device
// is recorded only: the standard subscription never grows a Tailscale endpoint.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
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
// selected once per subscription, never per rule. The vocabulary lives in the
// subscription IR so the library and the composer share one spelling.
type Action = ir.Action

const (
	ActionDirect = ir.ActionDirect
	ActionProxy  = ir.ActionProxy
	ActionReject = ir.ActionReject
)

// MatcherKind is the single matcher family of one rule. It mirrors the six
// kinds the rule library stocks and is shared through the IR package.
type MatcherKind = ir.MatcherKind

const (
	MatcherDomain       = ir.MatcherDomain
	MatcherDomainSuffix = ir.MatcherDomainSuffix
	MatcherIPCIDR       = ir.MatcherIPCIDR
	MatcherGeoSite      = ir.MatcherGeoSite
	MatcherGeoIP        = ir.MatcherGeoIP
	MatcherRuleSet      = ir.MatcherRuleSet
)

// RuleSetPin is the version lock of one external rule-set artifact. The shape
// and the shared predicates live in the subscription IR; policy's identically
// shaped RulesetPin maps the same detail to its own stable code, so the two
// gates cannot drift.
type RuleSetPin struct {
	Source  string
	Version string
	SHA256  string
}

// Validate rejects a mutable or malformed artifact pin before any document is
// rendered, so a client configuration can never name an unpinned file.
func (p RuleSetPin) Validate() error {
	if detail := ir.PinDetail(p.Source, p.Version, p.SHA256); detail != "" {
		return errors.New(CodeComposeRulesetUnpinned + ": " + detail)
	}
	return nil
}

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
// HTTP proxy (Ruling R11) instead of a MeshMux Out node. The composer renders
// it as a client-side `http` outbound, so the client dials the proxy itself.
// The value is the node wire contract's; this is a re-export, not a second
// source.
const ComposeOutHTTP = protocol.OutEgressHTTP

// ComposeOut is one selected egress: an Out node or an external HTTP proxy.
// The 1.0 slot always holds at most one entry; Kind distinguishes the two
// shapes for the UI, the selection identity and validation.
//
// Under client-chain egress the composer renders this material into both client
// documents, so the subscriber's client dials the egress itself and the Line
// only serves its own VLESS inbound. LinkKey (SS Out) and Username/Password
// (external HTTP proxy) are therefore part of the artifact: they are bearer
// secrets of the same class as the per-Line VLESS UUID, protected by the
// subscription bearer URL and never logged.
type ComposeOut struct {
	OutID       string
	DisplayName string
	Server      string
	Port        int
	// Kind is "" (or "out") for a MeshMux Out node and ComposeOutHTTP for an
	// external HTTP proxy.
	Kind string
	// LinkKey is the Hub-issued Shadowsocks link key of an Out node: the
	// password half of the pinned 2022-blake3-aes-128-gcm link. It is empty
	// for an HTTP proxy.
	LinkKey string
	// Username and Password are the optional Basic credentials of an external
	// HTTP proxy. Both are empty for an Out node.
	Username string
	Password string
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

// LineRoute is the server route fragment one selected Line had to publish for
// this subscription.
//
// Deprecated: retired by client-chain egress (docs/superpowers/plans/
// 2026-10-27-client-chain-egress.md). The Line no longer forwards: the selected
// Out is rendered into the client documents themselves, so the composer emits
// no server route and ComposeDocuments.LineRoutes stays empty. The type and the
// field are kept only so existing callers keep compiling; both are removed in a
// later v1 release.
type LineRoute struct {
	NodeID   string
	Fragment []byte
}

// ComposeDocuments is the assembled artifact: the two client documents, the
// selection identity and the content id.
type ComposeDocuments struct {
	SingBox []byte
	Mihomo  []byte
	// LineRoutes is always empty.
	//
	// Deprecated: retired by client-chain egress; the Line publishes no route
	// for a subscription any more. Kept so callers compile; removed later.
	LineRoutes  []LineRoute
	SelectionID string
	ContentID   string
}

// ComposeSubscription assembles one subscription from its recorded selection.
//
// Input: the four wizard groups (Lines with their credentials, at most one Out,
// the pinned rule revisions, the recorded mesh devices).
// Validation: every Line/credential pair, the single-Out bound, the rule pins
// and overlaps, and the "an Out nobody routes to" case are checked before any
// byte exists; each refusal is one blocking Diagnostic with a stable code.
// Assembly: buildComposeSelection returns the ordered selection, then
// composeDocuments builds the plan and runs the two client makers.
// Effect: none — this function writes nothing and reads nothing.
// Return: the two client documents, the selection identity and the ContentID
// that an approval is recorded against. A blocking diagnostic always yields zero
// documents, so a caller can never publish half an artifact.
func ComposeSubscription(lines []ComposeLine, outs []ComposeOut, rules []ComposeRule, network []ComposeNetwork) (ComposeDocuments, []Diagnostic) {
	selection, diagnostics := buildComposeSelection(lines, outs, rules, network)
	if hasBlockingDiagnostics(diagnostics) {
		return ComposeDocuments{}, diagnostics
	}
	documents, documentDiagnostics := composeDocuments(selection)
	return documents, append(diagnostics, documentDiagnostics...)
}

// validateComposeOut checks the dial half of one egress. The endpoint is
// required: an egress without a configured dial address would render a client
// outbound nobody can reach. The kind is either the MeshMux Out ("out" or
// empty) or an external HTTP proxy ("http"), and each kind carries exactly its
// own credential shape.
func validateComposeOut(out ComposeOut) error {
	if err := ValidateID(out.OutID); err != nil {
		return errors.New(CodeComposeOutInvalid + ": out_id must be 32 lowercase hex characters")
	}
	switch out.Kind {
	case "", protocol.OutboundOutTag, ComposeOutHTTP:
	default:
		return errors.New(CodeComposeOutInvalid + ": the egress kind must be out or http")
	}
	if out.Server == "" || !validHost(out.Server) {
		return errors.New(CodeComposeOutInvalid + ": the out endpoint must be one hostname or IP address")
	}
	if out.Port < 1 || out.Port > 65535 {
		return errors.New(CodeComposeOutInvalid + ": the out port must be 1-65535")
	}
	if out.Kind == ComposeOutHTTP {
		// An HTTP proxy carries Basic credentials, never a link key; the two
		// shapes never mix, so a value of the other shape is refused instead of
		// silently dropped from the document.
		if out.LinkKey != "" {
			return errors.New(CodeComposeOutInvalid + ": an http proxy carries no link key")
		}
		if out.Username == "" && out.Password != "" {
			return errors.New(CodeComposeOutInvalid + ": an http password requires a username")
		}
		return validateProxyCredential(out.Username, out.Password)
	}
	if out.Username != "" || out.Password != "" {
		return errors.New(CodeComposeOutInvalid + ": an out node carries no proxy credentials")
	}
	if !protocol.ValidOutLinkKey(out.LinkKey) {
		return errors.New(CodeComposeOutInvalid + ": the out link key must be 16 random bytes in base64-std")
	}
	return nil
}

// validateProxyCredential bounds the optional Basic pair of an external HTTP
// proxy. An empty value is legal (no auth or an empty password); a password
// without a username is refused by the caller. The shape is the wire
// contract's, so a credential the Hub accepts is one the client can render.
func validateProxyCredential(username, password string) error {
	if !protocol.ValidProxyCredential(username) || !protocol.ValidProxyCredential(password) {
		return errors.New(CodeComposeOutInvalid + ": http proxy credentials must be valid UTF-8 up to 256 bytes without control characters")
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
	if len(rule.Values) == 0 || len(rule.Values) > ir.MaxRuleValues {
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
			if !ir.ValidDomain(value) {
				return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": a domain must be a canonical lowercase DNS name")
			}
		case MatcherIPCIDR:
			if _, err := ir.CanonicalPrefix(value); err != nil {
				return nil, nil, nil, errors.New(CodeComposeRuleInvalid + ": every ip_cidr matcher must be a canonical network")
			}
		case MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
			if !ir.ValidTag(value) {
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
				tag = ir.GeoSiteTag(tag)
			case MatcherGeoIP:
				tag = ir.GeoIPTag(tag)
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
//
// Only the two client documents enter the digest: the retired LineRoutes field
// is always empty, and hashing it would keep a dead shape in the approval
// identity.
func composeContentID(documents ComposeDocuments) string {
	var builder strings.Builder
	builder.WriteString("meshmux-subscription-artifact/1\n")
	builder.WriteString(composeDigest(documents.SingBox) + "\n")
	builder.WriteString(composeDigest(documents.Mihomo) + "\n")
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func composeDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
