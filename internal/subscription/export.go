package subscription

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The exporter targets exactly one client transport profile: VLESS over
// REALITY with the xtls-rprx-vision flow, plain TCP and a Chrome uTLS
// fingerprint. It never emits TUN, Mesh, mobile auto-VPN or Out node
// references, and it never emits the Line private key, the REALITY handshake
// configuration or a subscription bearer token.
//
// sing-box 1.14.3 has no outbound display-name field: an outbound carries a
// "tag" and nothing else that a client renders. The tag is therefore the client
// label "<display name> [<full node id>]", and the selector references and
// default use the same label. The display name stays visible after a rename,
// while the full stable Line NodeID remains encoded in the tag. The Mihomo
// proxy name uses the same label.
//
// A tag is display metadata, not the client identity. A rename changes only
// this label; the Line NodeID, the credential UUID, the REALITY public key and
// the server stay unchanged, so a refreshed subscription presents a new name
// without reusing or rotating an identity.
const (
	// exportListenAddress is the loopback address the client inbound binds
	// to. The exported configuration never listens on a public interface.
	exportListenAddress = "127.0.0.1"
	// exportClientPort is the loopback mixed proxy port used by desktop
	// clients that import this subscription.
	exportClientPort = 1080
	// exportSingBoxSelectorTag is the stable tag of the sing-box selector
	// outbound. It never changes with a rename or a reorder.
	exportSingBoxSelectorTag = "meshmux-selector"
	// exportSingBoxDirectTag is the explicit direct outbound tag. It exists
	// so the configuration never depends on an implicit default and never
	// references an Out node.
	exportSingBoxDirectTag = "direct"
	// singBoxOutTag and singBoxBlockTag are the Line-route egress tags the
	// composer renders. They match the node renderer's server tags, so a route
	// fragment produced here is publishable as a Line candidate unchanged.
	singBoxOutTag   = "out"
	singBoxBlockTag = "block"
	// exportSingBoxInboundTag is the tag of the loopback mixed inbound.
	exportSingBoxInboundTag = "mixed-in"
	// exportSingBoxDNSTag is the tag of the local DNS transport used to
	// resolve Line host names.
	exportSingBoxDNSTag = "local"
	// exportMihomoGroupName is the stable name of the Mihomo select group.
	exportMihomoGroupName = "PROXY"
	// exportVLESSFlow is the only VLESS sub-protocol exported.
	exportVLESSFlow = "xtls-rprx-vision"
	// exportUTFingerprint is the only uTLS fingerprint exported.
	exportUTFingerprint = "chrome"
	// exportNetwork is the only transport network exported. The Vision flow
	// carries TCP destinations only.
	exportNetwork = "tcp"
	// exportUDP is false because the Vision flow rejects UDP destinations on
	// the server side, so a client that offers UDP would fail its handshake.
	// The Mihomo "udp" flag therefore matches the sing-box "network" value.
	exportUDP = false
)

// exportNode is one selected Line together with the credential that belongs
// to it and the label used in client-facing lists.
type exportNode struct {
	Line  Line
	UUID  string
	Label string
}

// exportPlan is the validated, deterministically ordered export input.
type exportPlan struct {
	Nodes []exportNode
}

// ExportSingBox renders a standard sing-box 1.14.3 client configuration for
// the selected Lines and their own credentials.
//
// The result is deterministic: the same Lines and credentials always produce
// byte-identical output, and the Line order follows SortOrder then NodeID.
// Every Line must have exactly one credential in the set; a missing or extra
// credential is rejected so that no other subscriber identity can leak into
// a published subscription. All credentials must belong to one Subscriber, so
// one document can never mix two subscriber identities.
func ExportSingBox(lines []Line, credentials []Credential) ([]byte, error) {
	return exportSingBoxWithRules(lines, credentials, nil)
}

// exportSingBoxWithRules is ExportSingBox plus the subscription's rule
// selection. A nil rule set renders exactly the historical bytes: no route
// rules and no rule_set block, so a subscription without rules is unchanged.
func exportSingBoxWithRules(lines []Line, credentials []Credential, rules []composeRenderedRule) ([]byte, error) {
	plan, err := buildExportPlan(lines, credentials)
	if err != nil {
		return nil, err
	}
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
	config.Outbounds = clientProxyOutbounds(plan)
	if len(rules) > 0 {
		rendered, sets := clientRuleSelection(rules)
		config.Route.Rules = rendered
		config.Route.RuleSet = sets
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("EXPORT_RENDER_FAILED")
	}
	return append(encoded, '\n'), nil
}

// clientProxyOutbounds renders the proxy outbounds shared by every sing-box
// client document: one VLESS/REALITY outbound per selected Line, the selector
// that holds exactly those outbounds, and the explicit direct outbound.
//
// The selector default is the first selected Line. The selector keeps the
// chosen Lines only, so a client can never fall back to an unknown or
// unauthorized node. The document shape is platform independent: a desktop
// client, iOS and Android differ only in how they import this same document,
// never in the outbound model, so the Mesh endpoint is added by the caller and
// never by this helper.
func clientProxyOutbounds(plan *exportPlan) []singBoxClientOutbound {
	outbounds := make([]singBoxClientOutbound, 0, len(plan.Nodes)+2)
	selector := singBoxClientOutbound{
		Type: "selector",
		Tag:  exportSingBoxSelectorTag,
	}
	for _, node := range plan.Nodes {
		outbounds = append(outbounds, singBoxClientOutbound{
			Type:       "vless",
			Tag:        node.Label,
			Server:     node.Line.Server,
			ServerPort: node.Line.Port,
			UUID:       node.UUID,
			Flow:       exportVLESSFlow,
			Network:    exportNetwork,
			TLS: &singBoxClientTLS{
				Enabled:    true,
				ServerName: node.Line.ServerName,
				UTLS: &singBoxClientUTLS{
					Enabled:     true,
					Fingerprint: exportUTFingerprint,
				},
				Reality: &singBoxClientReality{
					Enabled:   true,
					PublicKey: node.Line.PublicKey,
					ShortID:   node.Line.ShortID,
				},
			},
		})
		selector.Outbounds = append(selector.Outbounds, node.Label)
	}
	selector.Default = plan.Nodes[0].Label
	outbounds = append(outbounds, selector)
	return append(outbounds, singBoxClientOutbound{
		Type: "direct",
		Tag:  exportSingBoxDirectTag,
	})
}

// ExportMihomo renders a standard Mihomo client configuration for the
// selected Lines and their own credentials.
//
// The result is deterministic: the same Lines and credentials always produce
// byte-identical output, and the Line order follows SortOrder then NodeID.
// Every Line must have exactly one credential in the set; a missing or extra
// credential is rejected so that no other subscriber identity can leak into
// a published subscription. All credentials must belong to one Subscriber, so
// one document can never mix two subscriber identities.
func ExportMihomo(lines []Line, credentials []Credential) ([]byte, error) {
	return exportMihomoWithRules(lines, credentials, nil)
}

// exportMihomoWithRules is ExportMihomo plus the subscription's rule
// selection. A nil rule set renders exactly the historical bytes.
//
// A rule the Mihomo client cannot express (an SSID matcher, a Tailscale
// endpoint action) is refused with CodeComposeMihomoUnsupported instead of
// emitting a document that silently drops it.
func exportMihomoWithRules(lines []Line, credentials []Credential, rules []composeRenderedRule) ([]byte, error) {
	plan, err := buildExportPlan(lines, credentials)
	if err != nil {
		return nil, err
	}
	document := &yamlBuilder{}
	document.integer(0, "mixed-port", exportClientPort)
	document.boolean(0, "allow-lan", false)
	document.scalar(0, "bind-address", exportListenAddress)
	document.scalar(0, "mode", "rule")
	document.scalar(0, "log-level", "info")
	document.key(0, "proxies")
	for _, node := range plan.Nodes {
		document.beginItem(1)
		document.itemScalar(1, "name", node.Label)
		document.itemScalar(1, "type", "vless")
		document.itemScalar(1, "server", node.Line.Server)
		document.itemInteger(1, "port", node.Line.Port)
		document.itemScalar(1, "uuid", node.UUID)
		document.itemScalar(1, "flow", exportVLESSFlow)
		document.itemBoolean(1, "tls", true)
		document.itemScalar(1, "servername", node.Line.ServerName)
		document.itemScalar(1, "client-fingerprint", exportUTFingerprint)
		document.itemKey(1, "reality-opts")
		document.itemScalar(2, "public-key", node.Line.PublicKey)
		document.itemScalar(2, "short-id", node.Line.ShortID)
		document.itemScalar(1, "network", exportNetwork)
		document.itemBoolean(1, "udp", exportUDP)
	}
	document.key(0, "proxy-groups")
	document.beginItem(1)
	document.itemScalar(1, "name", exportMihomoGroupName)
	document.itemScalar(1, "type", "select")
	document.itemKey(1, "proxies")
	for _, node := range plan.Nodes {
		document.listItem(2, node.Label)
	}
	providers, err := mihomoClientRuleProviders(rules)
	if err != nil {
		return nil, err
	}
	if providers != "" {
		document.buf.WriteString(providers)
	}
	document.key(0, "rules")
	lines_, err := mihomoClientRuleLines(rules)
	if err != nil {
		return nil, err
	}
	for _, line := range lines_ {
		document.listItem(1, line)
	}
	document.listItem(1, "MATCH,"+exportMihomoGroupName)
	return document.bytes(), nil
}

// clientRuleSelection renders the shared rule order for the sing-box client
// document: the same matcher-to-key mapping and the same rule_set tags the Line
// route uses, so client and server can never disagree about a rule.
func clientRuleSelection(rules []composeRenderedRule) ([]map[string]any, []singBoxClientRuleSet) {
	rendered := make([]map[string]any, 0, len(rules))
	declared := make(map[string]struct{}, len(rules))
	sets := make([]singBoxClientRuleSet, 0, len(rules))
	for _, rule := range rules {
		entry := map[string]any{}
		switch rule.action {
		case ActionReject:
			// sing-box 1.14.3 expresses a refusal as a rule action, not as a
			// block outbound, so the reject rule carries "action": "reject" and
			// no outbound at all.
			entry["action"] = "reject"
		case ActionProxy:
			entry["outbound"] = exportSingBoxSelectorTag
		default:
			entry["outbound"] = exportSingBoxDirectTag
		}
		attachClientMatcher(entry, rule)
		rendered = append(rendered, entry)
		// Every referenced rule set must be declared, including one a reject
		// rule names: an undeclared tag makes the kernel refuse the document.
		for index, tag := range rule.tags {
			if _, exists := declared[tag]; exists {
				continue
			}
			declared[tag] = struct{}{}
			sets = append(sets, singBoxClientRuleSet{Type: "remote", Tag: tag, Format: "binary", URL: rule.sources[index]})
		}
	}
	return rendered, sets
}

// attachClientMatcher writes the matcher keys of one rule into a route entry.
func attachClientMatcher(entry map[string]any, rule composeRenderedRule) {
	switch rule.kind {
	case MatcherDomain:
		entry["domain"] = rule.values
	case MatcherDomainSuffix:
		entry["domain_suffix"] = rule.values
	case MatcherIPCIDR:
		entry["ip_cidr"] = rule.values
	default:
		entry["rule_set"] = append([]string(nil), rule.tags...)
	}
}

// mihomoClientRuleProviders declares every remote artifact the rules reference.
// The tag carries the pinned version, so a client never fetches a mutable
// channel.
func mihomoClientRuleProviders(rules []composeRenderedRule) (string, error) {
	type provider struct {
		tag  string
		url  string
		kind string
	}
	ordered := make([]provider, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		for index, tag := range rule.tags {
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			kind := "domain"
			if strings.HasPrefix(tag, "geoip-") {
				kind = "ipcidr"
			}
			ordered = append(ordered, provider{tag: tag, url: rule.sources[index], kind: kind})
		}
	}
	if len(ordered) == 0 {
		return "", nil
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].tag < ordered[j].tag })
	var out strings.Builder
	out.WriteString("rule-providers:\n")
	for _, entry := range ordered {
		out.WriteString("  " + entry.tag + ":\n")
		out.WriteString("    type: http\n")
		out.WriteString("    behavior: " + entry.kind + "\n")
		out.WriteString("    url: " + yamlQuote(entry.url) + "\n")
		out.WriteString("    path: ./ruleset/" + entry.tag + ".yaml\n")
		out.WriteString("    interval: 86400\n")
	}
	return out.String(), nil
}

// mihomoClientRuleLines renders the rule order as Mihomo rule lines. The action
// mapping is the fixed DIRECT/PROXY/REJECT trio; an Out action is not part of
// the library, so it never reaches this function.
func mihomoClientRuleLines(rules []composeRenderedRule) ([]string, error) {
	lines := make([]string, 0, len(rules)+1)
	for _, rule := range rules {
		action := "DIRECT"
		switch rule.action {
		case ActionProxy:
			action = exportMihomoGroupName
		case ActionReject:
			action = "REJECT"
		}
		switch rule.kind {
		case MatcherDomain:
			for _, value := range rule.values {
				lines = append(lines, "DOMAIN,"+value+","+action)
			}
		case MatcherDomainSuffix:
			for _, value := range rule.values {
				lines = append(lines, "DOMAIN-SUFFIX,"+value+","+action)
			}
		case MatcherIPCIDR:
			for _, value := range rule.values {
				kind := "IP-CIDR"
				if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is6() {
					kind = "IP-CIDR6"
				}
				lines = append(lines, kind+","+value+","+action+",no-resolve")
			}
		case MatcherGeoSite, MatcherGeoIP, MatcherRuleSet:
			for _, tag := range rule.tags {
				lines = append(lines, "RULE-SET,"+tag+","+action)
			}
		default:
			return nil, errors.New(CodeComposeMihomoUnsupported + ": the Mihomo client cannot express this matcher")
		}
	}
	return lines, nil
}

// buildExportPlan validates the public Line fields, pairs every Line with
// exactly one credential and orders the result deterministically.
func buildExportPlan(lines []Line, credentials []Credential) (*exportPlan, error) {
	if len(lines) == 0 {
		return nil, errors.New("EXPORT_NO_LINES: select at least one Line")
	}
	selected := make(map[string]Line, len(lines))
	for _, line := range lines {
		if err := validateExportLine(line); err != nil {
			return nil, err
		}
		if _, exists := selected[line.NodeID]; exists {
			return nil, errors.New("EXPORT_DUPLICATE_LINE: the same Line was selected twice")
		}
		selected[line.NodeID] = line
	}
	pairs := make(map[string]string, len(lines))
	subscriberID := ""
	for _, credential := range credentials {
		// A credential must be a complete, canonical record. A missing
		// subscriber identity would publish a document that belongs to
		// nobody, so the whole record is validated before it is paired
		// with a Line.
		if err := credential.Validate(); err != nil {
			return nil, errors.New("EXPORT_CREDENTIAL_INVALID: credential is not a canonical record")
		}
		if _, exists := selected[credential.NodeID]; !exists {
			return nil, errors.New("EXPORT_CREDENTIAL_UNSELECTED: credential references a Line that is not selected")
		}
		if _, exists := pairs[credential.NodeID]; exists {
			return nil, errors.New("EXPORT_CREDENTIAL_DUPLICATE: a Line has more than one credential")
		}
		// One subscription document carries one subscriber only. Mixing
		// credentials of two subscribers would publish an identity that
		// belongs to somebody else.
		if subscriberID != "" && credential.SubscriberID != subscriberID {
			return nil, errors.New("EXPORT_CREDENTIAL_SUBSCRIBER_MISMATCH: credentials belong to more than one Subscriber")
		}
		subscriberID = credential.SubscriberID
		pairs[credential.NodeID] = credential.UUID
	}
	labels := exportLabels(lines)
	plan := &exportPlan{Nodes: make([]exportNode, 0, len(lines))}
	for _, line := range lines {
		uuid, exists := pairs[line.NodeID]
		if !exists {
			return nil, errors.New("EXPORT_CREDENTIAL_MISSING: a selected Line has no credential")
		}
		plan.Nodes = append(plan.Nodes, exportNode{
			Line:  line,
			UUID:  uuid,
			Label: labels[line.NodeID],
		})
	}
	sort.SliceStable(plan.Nodes, func(i, j int) bool {
		left, right := plan.Nodes[i].Line, plan.Nodes[j].Line
		if left.SortOrder != right.SortOrder {
			return left.SortOrder < right.SortOrder
		}
		return left.NodeID < right.NodeID
	})
	return plan, nil
}

// validateExportLine checks only the public fields a client receives. The
// Line private key is never required and never exported, so a downloaded
// public fixture can be exported without a server secret.
func validateExportLine(line Line) error {
	if err := ValidateID(line.NodeID); err != nil {
		return errors.New("EXPORT_LINE_INVALID: Line identity is not canonical")
	}
	if err := ValidateDisplayName(line.DisplayName); err != nil {
		return errors.New("EXPORT_LINE_INVALID: Line display name is not a printable label")
	}
	if !validHost(line.Server) {
		return errors.New("EXPORT_LINE_INVALID: Line server is not one hostname or IP address")
	}
	if line.Port < 1 || line.Port > 65535 {
		return errors.New("EXPORT_LINE_INVALID: Line port is out of range")
	}
	if line.SortOrder < 0 {
		return errors.New("EXPORT_LINE_INVALID: Line sort order is negative")
	}
	if !validHost(line.ServerName) {
		return errors.New("EXPORT_LINE_INVALID: Line server name is not one hostname or IP address")
	}
	if _, err := parseRealityKey(line.PublicKey); err != nil {
		return errors.New("EXPORT_LINE_INVALID: Line REALITY public key is not canonical")
	}
	if err := ValidateShortID(line.ShortID); err != nil {
		return errors.New("EXPORT_LINE_INVALID: Line REALITY short ID is not canonical")
	}
	if line.PrivateKey != "" {
		if err := validateRealityKeyPair(line.PrivateKey, line.PublicKey); err != nil {
			return errors.New("EXPORT_LINE_INVALID: Line REALITY key pair does not match")
		}
	}
	return nil
}

// exportLabels builds one client label per Line. The label always carries the
// stable Line identity, so two Lines that share a display name stay
// distinguishable and a rename never changes the identity part. The sing-box
// outbound tag and the Mihomo proxy name both use this label.
func exportLabels(lines []Line) map[string]string {
	labels := make(map[string]string, len(lines))
	for _, line := range lines {
		labels[line.NodeID] = line.DisplayName + " [" + line.NodeID + "]"
	}
	return labels
}

// singBoxClientConfig is the exported sing-box client document. The field
// order is fixed by the struct layout so the output is byte-deterministic.
type singBoxClientConfig struct {
	Log       singBoxClientLog        `json:"log"`
	DNS       singBoxClientDNS        `json:"dns"`
	Inbounds  []singBoxClientInbound  `json:"inbounds"`
	Outbounds []singBoxClientOutbound `json:"outbounds"`
	Route     singBoxClientRoute      `json:"route"`
}

type singBoxClientLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type singBoxClientDNS struct {
	Servers []singBoxClientDNSServer `json:"servers"`
}

type singBoxClientDNSServer struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type singBoxClientInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type singBoxClientOutbound struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag"`
	Server     string            `json:"server,omitempty"`
	ServerPort int               `json:"server_port,omitempty"`
	UUID       string            `json:"uuid,omitempty"`
	Flow       string            `json:"flow,omitempty"`
	Network    string            `json:"network,omitempty"`
	TLS        *singBoxClientTLS `json:"tls,omitempty"`
	Outbounds  []string          `json:"outbounds,omitempty"`
	Default    string            `json:"default,omitempty"`
}

type singBoxClientTLS struct {
	Enabled    bool                  `json:"enabled"`
	ServerName string                `json:"server_name"`
	UTLS       *singBoxClientUTLS    `json:"utls"`
	Reality    *singBoxClientReality `json:"reality"`
}

type singBoxClientUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type singBoxClientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type singBoxClientRoute struct {
	Rules                 []map[string]any       `json:"rules,omitempty"`
	RuleSet               []singBoxClientRuleSet `json:"rule_set,omitempty"`
	DefaultDomainResolver string                 `json:"default_domain_resolver"`
	Final                 string                 `json:"final"`
}

// singBoxClientRuleSet is one declared remote artifact a client route
// references. The URL is the pinned source, so the client fetches exactly the
// version the composer validated.
type singBoxClientRuleSet struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Format string `json:"format"`
	URL    string `json:"url"`
}

// yamlBuilder renders a deterministic YAML document for a fixed set of
// controlled keys. Every string value is emitted as a JSON double-quoted
// scalar: JSON string syntax is a subset of the YAML double-quoted scalar
// syntax, so one escaping rule covers quotes, backslashes, control
// characters and non-ASCII text without adding a YAML dependency.
type yamlBuilder struct {
	buf bytes.Buffer
	// itemIndent is the indent of the list item currently being written.
	itemIndent int
	// itemFirst marks that the next item key still has to carry the "- "
	// marker.
	itemFirst bool
}

func (b *yamlBuilder) line(indent int, text string) {
	b.buf.WriteString(strings.Repeat("  ", indent))
	b.buf.WriteString(text)
	b.buf.WriteByte('\n')
}

func (b *yamlBuilder) scalar(indent int, key, value string) {
	b.line(indent, key+": "+yamlQuote(value))
}

func (b *yamlBuilder) integer(indent int, key string, value int) {
	b.line(indent, key+": "+strconv.Itoa(value))
}

func (b *yamlBuilder) boolean(indent int, key string, value bool) {
	b.line(indent, key+": "+strconv.FormatBool(value))
}

func (b *yamlBuilder) key(indent int, key string) {
	b.line(indent, key+":")
}

func (b *yamlBuilder) listItem(indent int, value string) {
	b.line(indent, "- "+yamlQuote(value))
}

// beginItem starts a mapping list item. The first key written afterwards is
// placed on the "- " marker line; the remaining keys are aligned under it.
func (b *yamlBuilder) beginItem(indent int) {
	b.itemIndent = indent
	b.itemFirst = true
}

// itemScalar writes one mapping key of the current list item.
func (b *yamlBuilder) itemScalar(indent int, key, value string) {
	b.itemLine(indent, key+": "+yamlQuote(value))
}

// itemInteger writes one integer mapping key of the current list item.
func (b *yamlBuilder) itemInteger(indent int, key string, value int) {
	b.itemLine(indent, key+": "+strconv.Itoa(value))
}

// itemBoolean writes one boolean mapping key of the current list item.
func (b *yamlBuilder) itemBoolean(indent int, key string, value bool) {
	b.itemLine(indent, key+": "+strconv.FormatBool(value))
}

// itemKey writes one nested mapping key of the current list item.
func (b *yamlBuilder) itemKey(indent int, key string) {
	b.itemLine(indent, key+":")
}

// itemLine writes one line of the current list item. The first line carries
// the "- " marker, the following lines are indented one step further so all
// keys of the item line up.
func (b *yamlBuilder) itemLine(indent int, text string) {
	if b.itemFirst {
		b.itemFirst = false
		b.line(indent, "- "+text)
		return
	}
	b.line(indent+1, text)
}

func (b *yamlBuilder) bytes() []byte {
	return b.buf.Bytes()
}

// yamlQuote renders one YAML double-quoted scalar.
func yamlQuote(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(encoded)
}
