package policy

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/compiler"
)

// Stable rule-library refusal codes. Only the code (before ": ") is stable;
// the detail after it names the offending rule or subscriber for the operator.
const (
	CodePresetImmutable = "RULE_PRESET_IMMUTABLE"
	CodeReferenced      = "RULE_REFERENCED_BY_SUBSCRIPTIONS"
	CodeNotFound        = "RULE_NOT_FOUND"
	CodeInvalid         = "RULE_INVALID"
	CodeConflict        = "RULE_CONFLICT"
)

// Action is the library egress of one rule. The library carries only these
// three: direct access, proxied access, or an explicit reject. There is no
// Out or Tailscale action here; those are chosen by the subscription composer
// (Task 4), never stored on a library row.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionReject Action = "reject"
)

// MatcherKind is the single matcher family of one rule. Exactly six are
// stocked; compiler.Match.SSIDs stays usable for other layers but is never a
// library kind (ADR-0008 §5).
type MatcherKind string

const (
	MatcherDomain       MatcherKind = "domain"
	MatcherDomainSuffix MatcherKind = "domain_suffix"
	MatcherIPCIDR       MatcherKind = "ipcidr"
	MatcherGeoSite      MatcherKind = "geosite"
	MatcherGeoIP        MatcherKind = "geoip"
	MatcherRuleSet      MatcherKind = "ruleset"
)

// Origin marks whether a row came from the versioned preset bundle or from an
// operator. Preset rows are immutable; custom rows grow by revision.
type Origin string

const (
	OriginPreset Origin = "preset"
	OriginCustom Origin = "custom"
)

// presetKeyPrefix reserves the stable_key namespace of the seed bundle. Any
// write touching it is refused with RULE_PRESET_IMMUTABLE, so a custom rule
// can never squat a preset identity and a future bundle can never collide
// with a custom key.
const presetKeyPrefix = "preset-"

var stableKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// IsPresetKey reports whether a stable_key lives in the preset namespace.
func IsPresetKey(key string) bool { return strings.HasPrefix(key, presetKeyPrefix) }

// Rule is one immutable library row: identity is (StableKey, Version). A
// match/action change never edits a row; it inserts a new version under the
// same key, so subscriptions pinned to an old revision keep their bytes.
type Rule struct {
	StableKey string
	Version   int
	Name      string
	Action    Action
	Kind      MatcherKind
	Values    []string
	Origin    Origin
	CreatedAt int64
	UpdatedAt int64
}

// Validate enforces the library contract: a slug key, a guarded display name,
// one of the three actions, one of the six matcher kinds, and canonical
// matcher values under compiler semantics. The preset- namespace reservation
// is a write-path guard (Create/Revise and ValidateRuleSet), not a Validate
// rule, so seeded preset rows validate like any other row.
func (r Rule) Validate() error {
	if !stableKeyPattern.MatchString(r.StableKey) {
		return errors.New(CodeInvalid + ": stable_key must be 1-64 lowercase letters, digits or hyphens")
	}
	if err := validateRuleName(r.Name); err != nil {
		return err
	}
	switch r.Action {
	case ActionDirect, ActionProxy, ActionReject:
	default:
		return errors.New(CodeInvalid + ": action must be direct, proxy or reject")
	}
	switch r.Kind {
	case MatcherDomain, MatcherDomainSuffix, MatcherIPCIDR, MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
	default:
		return errors.New(CodeInvalid + ": matcher kind must be one of domain, domain_suffix, ipcidr, geosite, geoip, ruleset")
	}
	if len(r.Values) == 0 || len(r.Values) > 64 {
		return errors.New(CodeInvalid + ": a rule needs 1-64 matcher values")
	}
	seen := map[string]bool{}
	values := make([]string, 0, len(r.Values))
	for _, raw := range r.Values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return errors.New(CodeInvalid + ": matcher values must not be blank")
		}
		if seen[value] {
			return errors.New(CodeInvalid + ": matcher values must not repeat " + value)
		}
		seen[value] = true
		values = append(values, value)
	}
	if err := r.ToCompilerMatchWith(values).Validate(); err != nil {
		return errors.New(CodeInvalid + ": " + ruleInvalidDetail(err))
	}
	return nil
}

func validateRuleName(name string) error {
	if name == "" || len([]rune(name)) > 80 {
		return errors.New(CodeInvalid + ": name must be 1-80 characters")
	}
	for _, marker := range []string{"key", "secret", "token", "uuid", "private", "password"} {
		if strings.Contains(strings.ToLower(name), marker) {
			return errors.New(CodeInvalid + ": the name must not describe credentials or keys")
		}
	}
	return nil
}

func ruleInvalidDetail(err error) string {
	if detail, _, found := strings.Cut(err.Error(), ": "); found {
		return detail
	}
	return err.Error()
}

// ToCompilerMatchWith maps one rule onto the shared matcher model for value
// validation. The action is deliberately not mapped: reject has no compiler
// counterpart, and the composer (Task 4) owns the action translation.
func (r Rule) ToCompilerMatchWith(values []string) compiler.Match {
	switch r.Kind {
	case MatcherDomain:
		return compiler.Match{Domains: values}
	case MatcherDomainSuffix:
		return compiler.Match{DomainSuffixes: values}
	case MatcherIPCIDR:
		return compiler.Match{IPCIDRs: values}
	case MatcherGeoSite:
		return compiler.Match{GeoSite: values}
	case MatcherGeoIP:
		return compiler.Match{GeoIP: values}
	default:
		return compiler.Match{RuleSets: values}
	}
}

// ToCompilerMatch maps the stored values onto the shared matcher model.
func (r Rule) ToCompilerMatch() compiler.Match {
	return r.ToCompilerMatchWith(append([]string(nil), r.Values...))
}

// ValidateRuleSet refuses a library set that would silently shadow itself:
// two rules whose matchers can hit the same target with different actions, or
// the same matcher repeated under one action. Disjoint rules always pass.
func ValidateRuleSet(rules []Rule) error {
	for _, r := range rules {
		if IsPresetKey(r.StableKey) {
			return errors.New(CodePresetImmutable + ": stable_key " + r.StableKey + " is reserved for the seed bundle")
		}
		if err := r.Validate(); err != nil {
			return err
		}
	}
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			if reason := rulesOverlap(rules[i], rules[j]); reason != "" {
				return errors.New(CodeConflict + ": rules " + rules[i].StableKey + " and " + rules[j].StableKey + " " + reason)
			}
		}
	}
	return nil
}

// rulesOverlap reports why two matchers collide, or "" when disjoint.
// Samples are concrete probes in the style of the compiler conflict check so
// cross-kind shadowing (a domain covered by a suffix) is caught too.
func rulesOverlap(a, b Rule) string {
	for _, probe := range matchSamples(b.Kind, b.Values) {
		if matchProbe(a.Kind, a.Values, probe) {
			if a.Action == b.Action {
				return "repeat the same match (" + probe + ")"
			}
			return "overlap on " + probe + "; the earlier rule would shadow the later one"
		}
	}
	for _, probe := range matchSamples(a.Kind, a.Values) {
		if matchProbe(b.Kind, b.Values, probe) {
			if a.Action == b.Action {
				return "repeat the same match (" + probe + ")"
			}
			return "overlap on " + probe + "; the earlier rule would shadow the later one"
		}
	}
	return ""
}

func matchSamples(kind MatcherKind, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		switch kind {
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

func matchProbe(kind MatcherKind, values []string, probe string) bool {
	for _, value := range values {
		switch kind {
		case MatcherDomain:
			if probe == value {
				return true
			}
		case MatcherDomainSuffix:
			if probe == value || strings.HasSuffix(probe, "."+value) {
				return true
			}
		case MatcherIPCIDR:
			if addr, err := netip.ParseAddr(probe); err == nil {
				if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(addr) {
					return true
				}
			}
		default:
			if probe == value {
				return true
			}
		}
	}
	return false
}
