package subscription

// The makers are the only code that knows a document syntax. Each target is a
// direct entry point — standard sing-box, mesh sing-box, Mihomo — and none is
// selected by a flag or a field count: a caller asks for the document it needs,
// so an accidental mesh material can never be silently rendered as a standard
// subscription (or dropped by a dispatcher).
//
// Every maker reads the same composeRouterPlan IR. No maker reads an Action, a
// Line record or a kernel tag rule: those were mapped exactly once in
// compose_plan.go.
//
// Extension points are additive only. A new matcher is one new case in the IR
// matcher and the makers that can express it (the others keep refusing it); a
// new kernel version is a new maker beside these, and an existing maker's bytes
// never change because a version was added. Every new egress tag belongs in
// internal/core/node/protocol, never as a literal here.

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// makeStandardSingBoxDocument renders one standard sing-box 1.14.3 client
// document. The route egresses are proxy (selector), direct and reject only; an
// Out, endpoint or block egress belongs to another producer and is refused
// rather than dropped.
func makeStandardSingBoxDocument(plan composeRouterPlan) ([]byte, error) {
	config := singBoxClientConfig{
		Log: singBoxClientLog{Level: "info", Timestamp: true},
		DNS: singBoxClientDNS{Servers: []singBoxClientDNSServer{{
			Type: "local",
			Tag:  exportSingBoxDNSTag,
		}}},
		Inbounds: []singBoxClientInbound{{
			Type:       "mixed",
			Tag:        exportSingBoxInboundTag,
			Listen:     exportListenAddress,
			ListenPort: exportClientPort,
		}},
		Route: singBoxClientRoute{
			DefaultDomainResolver: exportSingBoxDNSTag,
			Final:                 exportSingBoxSelectorTag,
		},
	}
	config.Outbounds = composeClientOutbounds(plan.Lines, plan.Selector)
	if len(plan.Route.Rules) > 0 {
		rendered, err := composeStandardRouteRules(plan.Route.Rules)
		if err != nil {
			return nil, err
		}
		config.Route.Rules = rendered
		config.Route.RuleSet = composeSingBoxRuleSets(plan.Route.RuleSets)
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("EXPORT_RENDER_FAILED")
	}
	return append(encoded, '\n'), nil
}

// composeClientOutbounds builds the VLESS outbounds plus the single selector
// and the explicit direct outbound. The order is the selected Line order, and
// the selector default is its first entry.
func composeClientOutbounds(lines []composeLineOutbound, selector composeSelector) []singBoxClientOutbound {
	outbounds := make([]singBoxClientOutbound, 0, len(lines)+2)
	for _, line := range lines {
		outbounds = append(outbounds, singBoxClientOutbound{
			Type:       "vless",
			Tag:        line.Label,
			Server:     line.Server,
			ServerPort: line.Port,
			UUID:       line.UUID,
			Flow:       exportVLESSFlow,
			Network:    exportNetwork,
			TLS: &singBoxClientTLS{
				Enabled:    true,
				ServerName: line.ServerName,
				UTLS: &singBoxClientUTLS{
					Enabled:     true,
					Fingerprint: exportUTFingerprint,
				},
				Reality: &singBoxClientReality{
					Enabled:   true,
					PublicKey: line.PublicKey,
					ShortID:   line.ShortID,
				},
			},
		})
	}
	outbounds = append(outbounds, singBoxClientOutbound{
		Type:      "selector",
		Tag:       exportSingBoxSelectorTag,
		Outbounds: append([]string(nil), selector.Outbounds...),
		Default:   selector.Default,
	})
	return append(outbounds, singBoxClientOutbound{
		Type: "direct",
		Tag:  exportSingBoxDirectTag,
	})
}

// composeStandardRouteRules maps the IR rules onto the sing-box client route
// keys. Reject is a rule action in sing-box 1.14.3, not a block outbound.
func composeStandardRouteRules(rules []composeRouteRule) ([]map[string]any, error) {
	rendered := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		entry := map[string]any{}
		switch rule.Egress {
		case composeEgressReject:
			entry["action"] = "reject"
		case composeEgressProxy:
			entry["outbound"] = exportSingBoxSelectorTag
		case composeEgressDirect:
			entry["outbound"] = exportSingBoxDirectTag
		default:
			return nil, errors.New("COMPOSE_ROUTE_RENDER_FAILED: the standard client cannot express this egress")
		}
		if err := attachComposeMatcher(entry, rule.Matcher); err != nil {
			return nil, err
		}
		rendered = append(rendered, entry)
	}
	return rendered, nil
}

// attachComposeMatcher writes the six matcher kinds onto a route entry. A new
// matcher is an additive case here and in the matching maker.
func attachComposeMatcher(entry map[string]any, matcher composeMatcher) error {
	switch matcher.Kind {
	case MatcherDomain:
		entry["domain"] = matcher.Values
	case MatcherDomainSuffix:
		entry["domain_suffix"] = matcher.Values
	case MatcherIPCIDR:
		entry["ip_cidr"] = matcher.Values
	case MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
		entry["rule_set"] = append([]string(nil), matcher.Tags...)
	default:
		return errors.New("COMPOSE_ROUTE_RENDER_FAILED: unknown matcher kind")
	}
	return nil
}

// composeSingBoxRuleSets declares the shared rule sets in the plan's first-use
// order. A nil plan yields an empty block that omitempty keeps out of the JSON.
func composeSingBoxRuleSets(sets []composeRuleSet) []singBoxClientRuleSet {
	rendered := make([]singBoxClientRuleSet, 0, len(sets))
	for _, set := range sets {
		rendered = append(rendered, singBoxClientRuleSet{
			Type: "remote", Tag: set.Tag, Format: protocol.RuleSetFormatBinary, URL: set.Source,
		})
	}
	return rendered
}

// makeLineRouteFragment renders the server route fragment one selected Line has
// to publish. Direct rules stay on the Line, proxy rules take the Out tag and
// reject rules take the explicit block tag. The final egress stays the Line.
func makeLineRouteFragment(plan composeRoutePlan) ([]byte, error) {
	rendered := make([]map[string]any, 0, len(plan.Rules))
	for _, rule := range plan.Rules {
		outbound := exportSingBoxDirectTag
		switch rule.Egress {
		case composeEgressDirect:
			outbound = exportSingBoxDirectTag
		case composeEgressLineOut:
			outbound = singBoxOutTag
		case composeEgressBlock:
			outbound = singBoxBlockTag
		default:
			return nil, errors.New("COMPOSE_ROUTE_RENDER_FAILED")
		}
		entry := map[string]any{"outbound": outbound}
		if err := attachComposeMatcher(entry, rule.Matcher); err != nil {
			return nil, err
		}
		rendered = append(rendered, entry)
	}
	body, err := json.MarshalIndent(struct {
		Rules   []map[string]any       `json:"rules"`
		RuleSet []singBoxClientRuleSet `json:"rule_set,omitempty"`
		Final   string                 `json:"final"`
	}{Rules: rendered, RuleSet: composeSingBoxRuleSets(plan.RuleSets), Final: exportSingBoxDirectTag}, "", "  ")
	if err != nil {
		return nil, errors.New("COMPOSE_ROUTE_RENDER_FAILED")
	}
	return append(body, '\n'), nil
}

// makeMeshSingBoxDocument renders one device-scoped sing-box document. It is
// the only maker that carries an endpoint; the standard maker and the Mihomo
// maker refuse endpoint material instead of silently dropping it.
func makeMeshSingBoxDocument(plan composeRouterPlan) ([]byte, error) {
	endpoints := make([]meshClientEndpoint, 0, len(plan.Endpoints))
	for _, endpoint := range plan.Endpoints {
		endpoints = append(endpoints, meshClientEndpoint{
			Type:         "tailscale",
			Tag:          endpoint.Tag,
			AuthKey:      endpoint.AuthKey,
			ControlURL:   endpoint.ControlURL,
			Hostname:     endpoint.Hostname,
			AcceptRoutes: endpoint.AcceptRoutes,
			Ephemeral:    endpoint.Ephemeral,
		})
	}
	rules := make([]meshClientRouteRule, 0, len(plan.Route.Rules))
	for _, rule := range plan.Route.Rules {
		if rule.Matcher.Kind != MatcherIPCIDR || rule.Egress != composeEgressEndpoint {
			return nil, errors.New("COMPOSE_ROUTE_RENDER_FAILED: the mesh document only routes CIDRs to its endpoint")
		}
		rules = append(rules, meshClientRouteRule{
			IPCIDR:   append([]string(nil), rule.Matcher.Values...),
			Outbound: rule.Target,
		})
	}
	config := meshClientConfig{
		Log: singBoxClientLog{Level: "info", Timestamp: true},
		DNS: singBoxClientDNS{Servers: []singBoxClientDNSServer{{
			Type: "local",
			Tag:  exportSingBoxDNSTag,
		}}},
		Inbounds: []singBoxClientInbound{{
			Type:       "mixed",
			Tag:        exportSingBoxInboundTag,
			Listen:     exportListenAddress,
			ListenPort: exportClientPort,
		}},
		Endpoints: endpoints,
		Outbounds: composeClientOutbounds(plan.Lines, plan.Selector),
		Route: meshClientRoute{
			DefaultDomainResolver: exportSingBoxDNSTag,
			Rules:                 rules,
			Final:                 exportSingBoxSelectorTag,
		},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("EXPORT_RENDER_FAILED")
	}
	return append(encoded, '\n'), nil
}

// mihomoClientDocument is the filled Mihomo document. Writing is a separate
// step so no writer contains a routing decision.
type mihomoClientDocument struct {
	MixedPort     int
	AllowLAN      bool
	BindAddress   string
	Mode          string
	LogLevel      string
	GroupName     string
	Proxies       []mihomoProxy
	RuleProviders []mihomoRuleProvider
	Rules         []string
	Final         string
}

type mihomoProxy struct {
	Name       string
	Server     string
	Port       int
	UUID       string
	Flow       string
	ServerName string
	PublicKey  string
	ShortID    string
}

type mihomoRuleProvider struct {
	Tag      string
	Behavior string
	URL      string
	Path     string
	Interval int
}

// makeMihomoDocument renders one Mihomo client document. It refuses endpoint,
// line-out and block egresses: Mihomo has no Tailscale endpoint and no double
// hop, so rendering them as a different action would change the selection
// silently.
func makeMihomoDocument(plan composeRouterPlan) ([]byte, error) {
	if plan.Route.Final != composeEgressProxy {
		return nil, errors.New(CodeComposeMihomoUnsupported + ": the Mihomo client has no endpoint final egress")
	}
	document := mihomoClientDocument{
		MixedPort:   exportClientPort,
		AllowLAN:    false,
		BindAddress: exportListenAddress,
		Mode:        "rule",
		LogLevel:    "info",
		GroupName:   exportMihomoGroupName,
		Proxies:     make([]mihomoProxy, 0, len(plan.Lines)),
		Final:       "MATCH," + exportMihomoGroupName,
	}
	for _, line := range plan.Lines {
		document.Proxies = append(document.Proxies, mihomoProxy{
			Name:       line.Label,
			Server:     line.Server,
			Port:       line.Port,
			UUID:       line.UUID,
			Flow:       exportVLESSFlow,
			ServerName: line.ServerName,
			PublicKey:  line.PublicKey,
			ShortID:    line.ShortID,
		})
	}
	document.RuleProviders = composeMihomoRuleProviders(plan.Route.RuleSets)
	lines, err := composeMihomoRuleLines(plan.Route.Rules)
	if err != nil {
		return nil, err
	}
	document.Rules = lines
	return writeMihomoClientDocument(document), nil
}

// mihomoProviderIntervalSeconds is the rule-provider refresh interval of a
// generated document. It is fixed because a shorter interval would let a client
// re-fetch a pinned artifact far more often than the pin was published for.
const mihomoProviderIntervalSeconds = 86400

// composeMihomoRuleProviders sorts providers by tag, which is the historical
// byte order, and derives the behavior from the shared rule-set plan.
func composeMihomoRuleProviders(sets []composeRuleSet) []mihomoRuleProvider {
	providers := make([]mihomoRuleProvider, 0, len(sets))
	for _, set := range sets {
		providers = append(providers, mihomoRuleProvider{
			Tag:      set.Tag,
			Behavior: set.Behavior,
			URL:      set.Source,
			Path:     "./ruleset/" + set.Tag + ".yaml",
			Interval: mihomoProviderIntervalSeconds,
		})
	}
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].Tag < providers[j].Tag })
	return providers
}

// composeMihomoRuleLines renders the IR rules as Mihomo rule lines. The action
// mapping is the fixed DIRECT/PROXY/REJECT trio.
func composeMihomoRuleLines(rules []composeRouteRule) ([]string, error) {
	lines := make([]string, 0, len(rules)+1)
	for _, rule := range rules {
		action := protocol.MihomoDirect
		switch rule.Egress {
		case composeEgressDirect:
			action = protocol.MihomoDirect
		case composeEgressProxy:
			action = exportMihomoGroupName
		case composeEgressReject:
			action = protocol.MihomoReject
		default:
			return nil, errors.New(CodeComposeMihomoUnsupported + ": the Mihomo client cannot express this egress")
		}
		switch rule.Matcher.Kind {
		case MatcherDomain:
			for _, value := range rule.Matcher.Values {
				lines = append(lines, "DOMAIN,"+value+","+action)
			}
		case MatcherDomainSuffix:
			for _, value := range rule.Matcher.Values {
				lines = append(lines, "DOMAIN-SUFFIX,"+value+","+action)
			}
		case MatcherIPCIDR:
			for _, value := range rule.Matcher.Values {
				kind := "IP-CIDR"
				if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is6() {
					kind = "IP-CIDR6"
				}
				lines = append(lines, kind+","+value+","+action+",no-resolve")
			}
		case MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
			for _, tag := range rule.Matcher.Tags {
				lines = append(lines, "RULE-SET,"+tag+","+action)
			}
		default:
			return nil, errors.New(CodeComposeMihomoUnsupported + ": the Mihomo client cannot express this matcher")
		}
	}
	return lines, nil
}

// writeMihomoClientDocument serializes a filled document in the fixed historical
// order. It contains no matcher or action branch.
func writeMihomoClientDocument(document mihomoClientDocument) []byte {
	builder := &yamlBuilder{}
	builder.integer(0, "mixed-port", document.MixedPort)
	builder.boolean(0, "allow-lan", document.AllowLAN)
	builder.scalar(0, "bind-address", document.BindAddress)
	builder.scalar(0, "mode", document.Mode)
	builder.scalar(0, "log-level", document.LogLevel)
	builder.key(0, "proxies")
	for _, proxy := range document.Proxies {
		builder.beginItem(1)
		builder.itemScalar(1, "name", proxy.Name)
		builder.itemScalar(1, "type", "vless")
		builder.itemScalar(1, "server", proxy.Server)
		builder.itemInteger(1, "port", proxy.Port)
		builder.itemScalar(1, "uuid", proxy.UUID)
		builder.itemScalar(1, "flow", proxy.Flow)
		builder.itemBoolean(1, "tls", true)
		builder.itemScalar(1, "servername", proxy.ServerName)
		builder.itemScalar(1, "client-fingerprint", exportUTFingerprint)
		builder.itemKey(1, "reality-opts")
		builder.itemScalar(2, "public-key", proxy.PublicKey)
		builder.itemScalar(2, "short-id", proxy.ShortID)
		builder.itemScalar(1, "network", exportNetwork)
		builder.itemBoolean(1, "udp", exportUDP)
	}
	builder.key(0, "proxy-groups")
	builder.beginItem(1)
	builder.itemScalar(1, "name", document.GroupName)
	builder.itemScalar(1, "type", "select")
	builder.itemKey(1, "proxies")
	for _, proxy := range document.Proxies {
		builder.listItem(2, proxy.Name)
	}
	if len(document.RuleProviders) > 0 {
		builder.line(0, "rule-providers:")
		for _, provider := range document.RuleProviders {
			builder.line(0, "  "+provider.Tag+":")
			builder.line(0, "    type: http")
			builder.line(0, "    behavior: "+provider.Behavior)
			builder.line(0, "    url: "+yamlQuote(provider.URL))
			builder.line(0, "    path: "+provider.Path)
			builder.line(0, "    interval: "+strconv.Itoa(provider.Interval))
		}
	}
	builder.key(0, "rules")
	for _, rule := range document.Rules {
		builder.listItem(1, rule)
	}
	builder.listItem(1, document.Final)
	return builder.bytes()
}
