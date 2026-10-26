package policy

// Geo and remote rulesets reuse the version lock of ruleset_pin.go: an exact
// HTTPS source, an immutable version label and a lowercase SHA-256. A policy
// that names geosite-*, geoip-* or a remote tag is refused unless that tag has
// a pin; an artifact is only usable when its bytes are non-empty, at most
// 8 MiB and match the pinned digest. A failure is RULESET_PIN_INVALID or
// RULESET_FETCH_FAILED and the caller refuses publication; there is no silent
// "use the built-in geo database" fallback.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// MaxRulesetBytes bounds one Geo or remote artifact. It is the single size
// limit for both the byte verifier here and the retained downloader in
// ruleset_pin.go, so a pinned artifact cannot become a memory lever on the Hub.
const MaxRulesetBytes = 8 << 20

// RuleSetPins are the pinned artifacts a generator may reference. The maps are
// keyed by the policy identifier (for example "cn" or "ai"), not by a URL.
type RuleSetPins struct {
	GeoSite map[string]RulesetPin
	GeoIP   map[string]RulesetPin
	Remote  map[string]RulesetPin
}

// Validate checks every supplied pin and proves each reference in rules has a
// pin. Unreferenced pins are still validated: a malformed pin in the input is a
// configuration defect even when no rule currently uses it.
func (p RuleSetPins) Validate(rules []CompilerRule) error {
	for _, pins := range []map[string]RulesetPin{p.GeoSite, p.GeoIP, p.Remote} {
		for tag, pin := range pins {
			if !ir.ValidTag(tag) {
				return errors.New(CodeRulesetUnpinned + ": a ruleset tag must be a lowercase identifier")
			}
			if err := pin.Validate(); err != nil {
				return err
			}
		}
	}
	for _, rule := range rules {
		for _, code := range rule.Match.GeoSite {
			if _, ok := p.GeoSite[code]; !ok {
				return errors.New(CodeRulesetUnpinned + ": " + ir.GeoSiteTag(code) + " has no version-locked pin")
			}
		}
		for _, code := range rule.Match.GeoIP {
			if _, ok := p.GeoIP[code]; !ok {
				return errors.New(CodeRulesetUnpinned + ": " + ir.GeoIPTag(code) + " has no version-locked pin")
			}
		}
		for _, tag := range rule.Match.RuleSets {
			if _, ok := p.Remote[tag]; !ok {
				return errors.New(CodeRulesetUnpinned + ": ruleset " + tag + " has no version-locked pin")
			}
		}
	}
	return nil
}

// VerifyRuleset is the only path from downloaded bytes to a generator input.
// It returns the payload unchanged only when the pin is valid, the artifact is
// non-empty, within MaxRulesetBytes and matches its SHA-256. Every failure is
// the stable RULESET_FETCH_FAILED code and carries no URL or body.
func VerifyRuleset(pin RulesetPin, payload []byte) ([]byte, error) {
	if err := pin.Validate(); err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned ruleset is empty")
	}
	if len(payload) > MaxRulesetBytes {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned ruleset exceeds the size bound")
	}
	sum := sha256.Sum256(payload)
	expected, err := hex.DecodeString(pin.SHA256)
	if err != nil || subtle.ConstantTimeCompare(sum[:], expected) != 1 {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned ruleset does not match its digest")
	}
	return payload, nil
}
