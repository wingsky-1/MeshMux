package compiler

// Policy intent and the format-independent rule model. One rule has exactly one
// matcher kind so sing-box (AND within a rule) and Mihomo (one line) express the
// same OR semantics; nothing here knows either document syntax.

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode"

	"github.com/wingsky-1/MeshMux/internal/route"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// Stable compiler refusals; only the code leaves the package.
const (
	CodePolicyInvalid     = "POLICY_INVALID"
	CodePolicyConflict    = "POLICY_CONFLICT"
	CodePolicyNodeUnknown = "POLICY_NODE_UNKNOWN"
	CodeRulesetUnpinned   = "RULESET_UNPINNED"
)

// Action is the format-independent egress of one rule.
type Action string

const (
	ActionDirect    Action = "direct"
	ActionProxy     Action = "proxy"
	ActionOut       Action = "out"
	ActionTailscale Action = "tailscale"
)

func (a Action) validClient() bool {
	return a == ActionDirect || a == ActionProxy || a == ActionTailscale
}
func (a Action) validServer() bool { return a == ActionDirect || a == ActionOut }

// DNSResolver is the resolver class a matched flow must use: domestic traffic
// resolves domestically, every other egress through an encrypted resolver on
// that same egress, so resolution never splits from access.
type DNSResolver string

const (
	DNSDomestic  DNSResolver = "domestic"
	DNSEncrypted DNSResolver = "encrypted"
)

func resolverFor(action Action) DNSResolver {
	if action == ActionDirect {
		return DNSDomestic
	}
	return DNSEncrypted
}

var (
	domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	tagPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	ssidPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,30}[a-z0-9])?$`)
)

// NormalizeSSID lowercases a Wi-Fi name and removes whitespace.
func NormalizeSSID(raw string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, raw)
}

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
		if !domainPattern.MatchString(domain) {
			return errors.New(CodePolicyInvalid + ": a domain must be a canonical lowercase DNS name")
		}
	}
	for _, raw := range m.IPCIDRs {
		if prefix, err := netip.ParsePrefix(raw); err != nil || prefix.Masked() != prefix {
			return errors.New(CodePolicyInvalid + ": every IP matcher must be a canonical CIDR network")
		}
	}
	for _, tag := range append(append(append([]string{}, m.GeoSite...), m.GeoIP...), m.RuleSets...) {
		if !tagPattern.MatchString(tag) {
			return errors.New(CodePolicyInvalid + ": geo and ruleset identifiers must be lowercase")
		}
	}
	for _, raw := range m.SSIDs {
		if raw != NormalizeSSID(raw) || !ssidPattern.MatchString(raw) {
			return errors.New(CodePolicyInvalid + ": an SSID must be lowercase, without whitespace, and use letters, digits, dot, underscore, plus or hyphen")
		}
	}
	if m.DNS != "" && m.DNS != DNSDomestic && m.DNS != DNSEncrypted {
		return errors.New(CodePolicyInvalid + ": the DNS annotation must be domestic or encrypted")
	}
	return nil
}

// Rule couples one matcher to one action. Priorities must be strictly ascending
// so input order is rendered order and duplicates are a conflict.
type Rule struct {
	Priority int
	Match    Match
	Action   Action
}

// ClientPolicy is client intent plus the read-only non-secret mesh view; it
// carries no credential or Token.
type ClientPolicy struct {
	Default Action
	Rules   []Rule
	Mesh    subscription.MeshConfigModel
}

// Validate checks the intent and refuses overlaps the save path must not merge.
func (p ClientPolicy) Validate() error {
	if !p.Default.validClient() {
		return errors.New(CodePolicyInvalid + ": the client default must be direct, proxy or tailscale")
	}
	if err := validateRules(p.Rules, Action.validClient); err != nil {
		return err
	}
	return checkClientConflicts(p.Rules)
}

// MeshClientPolicy derives the 10a mesh intent: tailnet prefixes to Tailscale,
// everything else through the proxy selector. The caller must name a Line label
// present in the model; an absent label is refused, never guessed. The model is
// copied and only read.
func MeshClientPolicy(model subscription.MeshConfigModel, proxyLine string) (ClientPolicy, error) {
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
		Default: ActionProxy,
		Mesh:    cloneModel(model),
		Rules: []Rule{{
			Priority: 1000,
			Match:    Match{IPCIDRs: append([]string(nil), model.TailnetPrefixes...)},
			Action:   ActionTailscale,
		}},
	}
	return policy, policy.Validate()
}

func cloneModel(model subscription.MeshConfigModel) subscription.MeshConfigModel {
	model.TailnetPrefixes = append([]string(nil), model.TailnetPrefixes...)
	model.LineLabels = append([]string(nil), model.LineLabels...)
	return model
}

// ServerPolicy is server intent: Line direct by default, with only named rules
// allowed to choose the single optional Out.
type ServerPolicy struct {
	Default        Action
	Rules          []Rule
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
	return validateRules(p.Rules, Action.validServer)
}

// ResolveServerPolicy applies the Out contract before rendering: an unavailable
// Out never becomes direct silently. Only an explicit opt-in with an operation
// id may fall back, and the fallback rewrites Out actions to direct.
func ResolveServerPolicy(policy ServerPolicy) (ServerPolicy, error) {
	if err := policy.Validate(); err != nil {
		return policy, err
	}
	needsOut := policy.Default == ActionOut
	for _, rule := range policy.Rules {
		needsOut = needsOut || rule.Action == ActionOut
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
		return policy, &route.BlockedError{Code: route.CodeOutOfflineFailClosed, Detail: "OUT_OFFLINE"}
	}
	if policy.OperationID == "" {
		return policy, errors.New(route.CodeOutFallbackUnaudited + ": the explicit line fallback needs an operation id so the deviation can be audited")
	}
	resolved := policy
	resolved.Rules = append([]Rule(nil), policy.Rules...)
	if resolved.Default == ActionOut {
		resolved.Default = ActionDirect
	}
	for index := range resolved.Rules {
		if resolved.Rules[index].Action == ActionOut {
			resolved.Rules[index].Action = ActionDirect
		}
	}
	return resolved, nil
}

func validateRules(rules []Rule, allowed func(Action) bool) error {
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
