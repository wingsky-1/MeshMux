package policy

// Policy intent and the format-independent rule model. One rule has exactly one
// matcher kind so sing-box (AND within a rule) and Mihomo (one line) express the
// same OR semantics; nothing here knows either document syntax.

import (
	"errors"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// Stable policy refusals; only the code leaves the package.
const (
	CodePolicyInvalid     = "POLICY_INVALID"
	CodePolicyConflict    = "POLICY_CONFLICT"
	CodePolicyNodeUnknown = "POLICY_NODE_UNKNOWN"
	CodeRulesetUnpinned   = "RULESET_UNPINNED"
)

// CompilerAction is the format-independent egress of one rule. It is a wider
// vocabulary than the library's three actions: the server layer adds the Out
// hop and the client layer adds the mesh endpoint. The two shared spellings are
// taken from the library action so the two layers cannot disagree about
// "direct" and "proxy".
type CompilerAction string

const (
	CompilerActionDirect    CompilerAction = CompilerAction(ir.ActionDirect)
	CompilerActionProxy     CompilerAction = CompilerAction(ir.ActionProxy)
	CompilerActionOut       CompilerAction = CompilerAction(protocol.OutboundOutTag)
	CompilerActionTailscale CompilerAction = "tailscale"
)

func (a CompilerAction) validClient() bool {
	return a == CompilerActionDirect || a == CompilerActionProxy || a == CompilerActionTailscale
}
func (a CompilerAction) validServer() bool {
	return a == CompilerActionDirect || a == CompilerActionOut
}

// DNSResolver is the resolver class a matched flow must use: domestic traffic
// resolves domestically, every other egress through an encrypted resolver on
// that same egress, so resolution never splits from access.
type DNSResolver string

const (
	DNSDomestic  DNSResolver = "domestic"
	DNSEncrypted DNSResolver = "encrypted"
)

func resolverFor(action CompilerAction) DNSResolver {
	if action == CompilerActionDirect {
		return DNSDomestic
	}
	return DNSEncrypted
}

// NormalizeSSID lowercases a Wi-Fi name and removes whitespace. The predicate
// itself lives in the subscription IR so both layers normalize identically.
func NormalizeSSID(raw string) string { return ir.NormalizeSSID(raw) }

// Match is one matcher kind; Geo and remote identifiers need a pin. DNS is an
// annotation, not a matcher kind: it names the resolver the rule's egress uses.
type Match struct {
	Domains        []string
	DomainSuffixes []string
	IPCIDRs        []string
	GeoSite        []string
	GeoIP          []string
	RuleSets       []string
	SSIDs          []string
	DNS            DNSResolver
}

// Validate accepts exactly one matcher kind and canonical values, so an invalid
// domain or CIDR is refused before a generator sees it.
func (m Match) Validate() error {
	kinds := 0
	for _, values := range [][]string{m.Domains, m.DomainSuffixes, m.IPCIDRs, m.GeoSite, m.GeoIP, m.RuleSets, m.SSIDs} {
		if len(values) > 0 {
			kinds++
		}
	}
	if kinds != 1 {
		return errors.New(CodePolicyInvalid + ": each rule must use exactly one matcher kind")
	}
	for _, domain := range append(append([]string{}, m.Domains...), m.DomainSuffixes...) {
		if !ir.ValidDomain(domain) {
			return errors.New(CodePolicyInvalid + ": a domain must be a canonical lowercase DNS name")
		}
	}
	for _, raw := range m.IPCIDRs {
		if _, err := ir.CanonicalPrefix(raw); err != nil {
			return errors.New(CodePolicyInvalid + ": every IP matcher must be a canonical CIDR network")
		}
	}
	for _, tag := range append(append(append([]string{}, m.GeoSite...), m.GeoIP...), m.RuleSets...) {
		if !ir.ValidTag(tag) {
			return errors.New(CodePolicyInvalid + ": geo and ruleset identifiers must be lowercase")
		}
	}
	for _, raw := range m.SSIDs {
		if raw != NormalizeSSID(raw) || !ir.ValidSSID(raw) {
			return errors.New(CodePolicyInvalid + ": an SSID must be lowercase, without whitespace, and use letters, digits, dot, underscore, plus or hyphen")
		}
	}
	if m.DNS != "" && m.DNS != DNSDomestic && m.DNS != DNSEncrypted {
		return errors.New(CodePolicyInvalid + ": the DNS annotation must be domestic or encrypted")
	}
	return nil
}

// CompilerRule couples one matcher to one action. Priorities must be strictly ascending
// so input order is rendered order and duplicates are a conflict.
type CompilerRule struct {
	Priority int
	Match    Match
	Action   CompilerAction
}

// ClientPolicy is client intent plus the read-only non-secret mesh view; it
// carries no credential or Token. The view is the subscription IR shape, not
// the subscription package, so the merged compiler does not depend upward on
// the composer.
type ClientPolicy struct {
	Default CompilerAction
	Rules   []CompilerRule
	Mesh    ir.MeshView
}

// Validate checks the intent and refuses overlaps the save path must not merge.
func (p ClientPolicy) Validate() error {
	if !p.Default.validClient() {
		return errors.New(CodePolicyInvalid + ": the client default must be direct, proxy or tailscale")
	}
	if err := validateRules(p.Rules, CompilerAction.validClient); err != nil {
		return err
	}
	return checkClientConflicts(p.Rules)
}

// MeshClientPolicy derives the 10a mesh intent: tailnet prefixes to Tailscale,
// everything else through the proxy selector. The caller must name a Line label
// present in the model; an absent label is refused, never guessed. The model is
// copied and only read.
func MeshClientPolicy(model ir.MeshView, proxyLine string) (ClientPolicy, error) {
	// Anti-corruption: the mesh view arrives from another module, so its shape
	// is checked here instead of being trusted. A malformed prefix, label or
	// identity is refused before it can reach a rule.
	if err := model.Validate(); err != nil {
		return ClientPolicy{}, errors.New(CodePolicyInvalid + ": the mesh view is not a canonical projection")
	}
	known := false
	for _, label := range model.LineLabels {
		if label == proxyLine {
			known = true
		}
	}
	if !known {
		return ClientPolicy{}, errors.New(CodePolicyNodeUnknown + ": the policy must name a Line label present in the mesh model")
	}
	policy := ClientPolicy{
		Default: CompilerActionProxy,
		Mesh:    cloneModel(model),
		Rules: []CompilerRule{{
			Priority: 1000,
			Match:    Match{IPCIDRs: append([]string(nil), model.TailnetPrefixes...)},
			Action:   CompilerActionTailscale,
		}},
	}
	return policy, policy.Validate()
}

// cloneModel copies the two slices so a caller cannot mutate the read-only
// view through the policy value it received.
func cloneModel(model ir.MeshView) ir.MeshView {
	model.TailnetPrefixes = append([]string(nil), model.TailnetPrefixes...)
	model.LineLabels = append([]string(nil), model.LineLabels...)
	return model
}

// ServerPolicy is server intent: Line direct by default, with only named rules
// allowed to choose the single optional Out.
type ServerPolicy struct {
	Default        CompilerAction
	Rules          []CompilerRule
	OutConfigured  bool
	OutAvailable   bool
	FallbackToLine bool
	OperationID    string
}

// Validate checks the server intent.
func (p ServerPolicy) Validate() error {
	if !p.Default.validServer() {
		return errors.New(CodePolicyInvalid + ": the server default must be direct or out")
	}
	return validateRules(p.Rules, CompilerAction.validServer)
}

// ResolveServerPolicy applies the Out contract before rendering: an unavailable
// Out never becomes direct silently. Only an explicit opt-in with an operation
// id may fall back, and the fallback rewrites Out actions to direct.
func ResolveServerPolicy(policy ServerPolicy) (ServerPolicy, error) {
	if err := policy.Validate(); err != nil {
		return policy, err
	}
	needsOut := policy.Default == CompilerActionOut
	for _, rule := range policy.Rules {
		needsOut = needsOut || rule.Action == CompilerActionOut
	}
	if !needsOut {
		return policy, nil
	}
	if !policy.OutConfigured {
		return policy, errors.New("OUT_BINDING_INVALID: the policy needs an Out but none is configured")
	}
	if policy.OutAvailable {
		return policy, nil
	}
	if !policy.FallbackToLine {
		return policy, &BlockedError{Code: CodeOutOfflineFailClosed, Detail: "OUT_OFFLINE"}
	}
	if policy.OperationID == "" {
		return policy, errors.New(CodeOutFallbackUnaudited + ": the explicit line fallback needs an operation id so the deviation can be audited")
	}
	resolved := policy
	resolved.Rules = append([]CompilerRule(nil), policy.Rules...)
	if resolved.Default == CompilerActionOut {
		resolved.Default = CompilerActionDirect
	}
	for index := range resolved.Rules {
		if resolved.Rules[index].Action == CompilerActionOut {
			resolved.Rules[index].Action = CompilerActionDirect
		}
	}
	return resolved, nil
}

func validateRules(rules []CompilerRule, allowed func(CompilerAction) bool) error {
	for index, rule := range rules {
		if rule.Priority <= 0 {
			return errors.New(CodePolicyInvalid + ": every rule needs a positive priority")
		}
		if index > 0 && rule.Priority <= rules[index-1].Priority {
			return errors.New(CodePolicyConflict + ": rule priorities must be strictly ascending and unique")
		}
		if !allowed(rule.Action) {
			return errors.New(CodePolicyInvalid + ": the rule action is not valid for this policy")
		}
		if rule.Match.DNS != "" && rule.Match.DNS != resolverFor(rule.Action) {
			return errors.New(CodePolicyConflict + ": the DNS annotation disagrees with the rule egress; resolution must use the same path as access")
		}
		if err := rule.Match.Validate(); err != nil {
			return err
		}
	}
	return nil
}
