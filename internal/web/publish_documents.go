package web

// Client document wrappers for the publish gate.
//
// compiler.RenderSingBox and compiler.RenderMihomo emit routing fragments, not
// complete client documents: the fragment has no outbounds/proxy-groups and no
// rule-provider definitions. A kernel cannot validate a fragment on its own
// (sing-box refuses a route that names an unknown outbound, and Mihomo refuses
// a RULE-SET without a provider), so the gate wraps the fragment into the
// minimal document shape that exercises exactly the same route semantics.
//
// The wrapper is policy-neutral by construction: it never names an endpoint, a
// credential or a Line. It only declares the selector, the Tailscale endpoint
// tag and the pinned rule-provider definitions the fragment references.

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/compiler"
)

// assembleSingBoxClient wraps a rendered client route fragment into the native
// sing-box document shape.
func assembleSingBoxClient(fragment []byte) ([]byte, error) {
	var rendered map[string]json.RawMessage
	if err := json.Unmarshal(fragment, &rendered); err != nil {
		return nil, errors.New("RENDER_SINGBOX_FAILED: the client fragment is not JSON")
	}
	route, ok := rendered["route"]
	if !ok || len(bytes.TrimSpace(route)) == 0 {
		return nil, errors.New("RENDER_SINGBOX_FAILED: the client fragment has no route")
	}
	document := map[string]any{
		"log": map[string]any{"disabled": true},
		"outbounds": []map[string]any{
			{"type": "direct", "tag": "direct"},
			{"type": "selector", "tag": "meshmux-selector", "outbounds": []string{"direct"}},
		},
		"route": json.RawMessage(route),
	}
	if bytes.Contains(fragment, []byte(`"meshmux-ts"`)) {
		document["endpoints"] = []map[string]any{{"type": "tailscale", "tag": "meshmux-ts"}}
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, errors.New("RENDER_SINGBOX_FAILED: the client document was not encoded")
	}
	return append(body, '\n'), nil
}

// assembleMihomoClient wraps a rendered Mihomo rules fragment into the native
// Mihomo document shape.
//
// Two details matter for the gate to prove anything:
//
//   - every rule-provider the fragment references must be declared, or Mihomo
//     refuses the document for an unknown rule set;
//   - a pinned HTTP ruleset is declared with its exact pinned URL, so the gate
//     validates the same version-locked artifact the runtime will fetch.
//
// The proxy groups are neutral placeholders: the exporter's group names, with
// DIRECT as the only member. No endpoint or credential appears here.
func assembleMihomoClient(fragment []byte, pins compiler.RuleSetPins, rules []compiler.Rule) ([]byte, error) {
	body := strings.TrimSpace(string(fragment))
	if body == "" || !strings.HasPrefix(body, "rules:") {
		return nil, errors.New("RENDER_MIHOMO_FAILED: the client fragment is not a rules document")
	}
	providers, err := mihomoRuleProviders(pins, rules)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	out.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n")
	out.WriteString("proxy-groups:\n")
	out.WriteString("  - name: PROXY\n    type: select\n    proxies:\n      - DIRECT\n")
	out.WriteString("  - name: OUT\n    type: select\n    proxies:\n      - DIRECT\n")
	if len(providers) > 0 {
		out.WriteString(providers)
	}
	out.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		out.WriteString("\n")
	}
	return []byte(out.String()), nil
}

// mihomoRuleProviders declares the rule sets the fragment references. The tags
// are the same target-neutral tags compiler.ruleSetTags emits, and the URL is
// the pinned artifact URL, so the gate validates a declared version rather than
// an inline guess.
func mihomoRuleProviders(pins compiler.RuleSetPins, rules []compiler.Rule) (string, error) {
	tags := map[string]struct{}{}
	for _, rule := range rules {
		for _, code := range rule.Match.GeoSite {
			tags["geosite-"+code] = struct{}{}
		}
		for _, code := range rule.Match.GeoIP {
			tags["geoip-"+code] = struct{}{}
		}
		for _, tag := range rule.Match.RuleSets {
			tags[tag] = struct{}{}
		}
	}
	if len(tags) == 0 {
		return "", nil
	}
	ordered := make([]string, 0, len(tags))
	for tag := range tags {
		ordered = append(ordered, tag)
	}
	sort.Strings(ordered)
	var out strings.Builder
	out.WriteString("rule-providers:\n")
	for _, tag := range ordered {
		pin, ok := ruleSetPinFor(pins, tag)
		if !ok {
			return "", errors.New(compiler.CodeRulesetUnpinned + ": " + tag + " has no version-locked pin")
		}
		behavior := "domain"
		if strings.HasPrefix(tag, "geoip-") {
			behavior = "ipcidr"
		}
		out.WriteString("  " + tag + ":\n")
		out.WriteString("    type: http\n")
		out.WriteString("    behavior: " + behavior + "\n")
		out.WriteString("    url: " + pin.Source + "\n")
		out.WriteString("    path: ./ruleset/" + tag + ".yaml\n")
		out.WriteString("    interval: 86400\n")
	}
	return out.String(), nil
}

// ruleSetPinFor resolves the pin of one rendered tag. GeoSite and GeoIP tags
// are prefixed by the renderer; remote tags are used verbatim.
func ruleSetPinFor(pins compiler.RuleSetPins, tag string) (compiler.RulesetPin, bool) {
	if code, ok := strings.CutPrefix(tag, "geosite-"); ok {
		pin, found := pins.GeoSite[code]
		return pin, found
	}
	if code, ok := strings.CutPrefix(tag, "geoip-"); ok {
		pin, found := pins.GeoIP[code]
		return pin, found
	}
	pin, found := pins.Remote[tag]
	return pin, found
}
