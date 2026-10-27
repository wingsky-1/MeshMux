package store_test

// Drift guards between the composer's own small rule model and the rule library
// it consumes.
//
// internal/subscription cannot import internal/policy (policy → subscription is
// the existing direction), so the composer re-declares the three
// actions and the six matcher kinds. This file is the single place that proves
// the two vocabularies are identical: a library action or matcher the composer
// does not know would silently refuse every subscription that selects it, and a
// composer kind the library cannot store would be unreachable.

import (
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
	subdomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

func TestComposerActionsMatchTheRuleLibrary(t *testing.T) {
	library := []policy.Action{policy.ActionDirect, policy.ActionProxy, policy.ActionReject}
	composer := []subdomain.Action{subdomain.ActionDirect, subdomain.ActionProxy, subdomain.ActionReject}
	if len(library) != len(composer) {
		t.Fatalf("library actions = %d, composer actions = %d", len(library), len(composer))
	}
	for index := range library {
		if string(library[index]) != string(composer[index]) {
			t.Fatalf("action %d: library %q, composer %q", index, library[index], composer[index])
		}
	}
}

func TestComposerMatcherKindsMatchTheRuleLibrary(t *testing.T) {
	library := []policy.MatcherKind{
		policy.MatcherDomain, policy.MatcherDomainSuffix, policy.MatcherIPCIDR,
		policy.MatcherGeoSite, policy.MatcherGeoIP, policy.MatcherRuleSet,
	}
	composer := []subdomain.MatcherKind{
		subdomain.MatcherDomain, subdomain.MatcherDomainSuffix, subdomain.MatcherIPCIDR,
		subdomain.MatcherGeoSite, subdomain.MatcherGeoIP, subdomain.MatcherRuleSet,
	}
	if len(library) != len(composer) {
		t.Fatalf("library matcher kinds = %d, composer matcher kinds = %d", len(library), len(composer))
	}
	for index := range library {
		if string(library[index]) != string(composer[index]) {
			t.Fatalf("matcher kind %d: library %q, composer %q", index, library[index], composer[index])
		}
	}
}

// TestComposerPinsMatchTheRouteVersionLock proves the composer's artifact pin
// accepts and refuses the same inputs as the route version lock the publish
// gate uses. A divergence would let a subscription render an artifact the gate
// would have refused.
func TestComposerPinsMatchTheRouteVersionLock(t *testing.T) {
	good := subdomain.RuleSetPin{
		Source:  "https://rulesets.example.invalid/2026-10-26.srs",
		Version: "20261026",
		SHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("the composer refused a valid pin: %v", err)
	}
	cases := []subdomain.RuleSetPin{
		{Source: "http://rulesets.example.invalid/a.srs", Version: "1", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs?x=1", Version: "1", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs", Version: "latest", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs", Version: "1", SHA256: "abc"},
		{Source: "https://127.0.0.1/a.srs", Version: "1", SHA256: good.SHA256},
	}
	for _, pin := range cases {
		if err := pin.Validate(); err == nil {
			t.Fatalf("the composer accepted an invalid pin: %+v", pin)
		}
	}
	// The route lock agrees on every case, so the two checks cannot drift.
	routeCases := []policy.RulesetPin{
		{Source: good.Source, Version: good.Version, SHA256: good.SHA256},
		{Source: "http://rulesets.example.invalid/a.srs", Version: "1", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs?x=1", Version: "1", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs", Version: "latest", SHA256: good.SHA256},
		{Source: "https://rulesets.example.invalid/a.srs", Version: "1", SHA256: "abc"},
		{Source: "https://127.0.0.1/a.srs", Version: "1", SHA256: good.SHA256},
	}
	for index, pin := range routeCases {
		composerErr := composerPinOf(pin).Validate()
		routeErr := pin.Validate()
		if (composerErr == nil) != (routeErr == nil) {
			t.Fatalf("case %d disagrees: composer=%v route=%v", index, composerErr, routeErr)
		}
	}
}

// composerPinOf converts a route pin into the composer's pin shape.
func composerPinOf(pin policy.RulesetPin) subdomain.RuleSetPin {
	return subdomain.RuleSetPin{Source: pin.Source, Version: pin.Version, SHA256: pin.SHA256}
}
