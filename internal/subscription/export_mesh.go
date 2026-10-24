package subscription

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// Mesh export is the device-scoped companion of the standard subscription
// export. It renders one sing-box 1.14.3 client document that carries the
// proxy outbounds of one Subscriber and one Tailscale endpoint for one mesh
// device. It deliberately does not alter ExportSingBox: a standard
// subscription still never contains a Mesh endpoint, a TUN inbound or a
// Headscale credential.
//
// The top-level document contains exactly the client-side pieces of 9c:
//
//	log, dns, mixed inbound, the proxy outbounds, one tailscale endpoint and a
//	route whose first (and only) rule sends the two tailnet prefixes to the
//	endpoint. Everything else uses the selector over the proxy Lines, so a
//	tailnet destination can never be sent through a proxy Line.
//
// The auth key is a one-shot Headscale pre-auth key. It is part of the input
// only, never a field of MeshConfigModel, never persisted by this package and
// never logged. The renderer is pure: the caller mints the key, renders once,
// and keeps the result no-store.

const (
	// MeshTailnetIPv4Prefix and MeshTailnetIPv6Prefix are the ranges the Hub
	// Headscale control plane allocates. internal/mesh owns the same values for
	// route validation; the subscription package cannot import it because
	// internal/mesh imports this package. A web-level drift test compares both
	// constants.
	MeshTailnetIPv4Prefix = "100.64.0.0/10"
	MeshTailnetIPv6Prefix = "fd7a:115c:a1e0::/48"

	// exportMeshEndpointTag is the stable tag of the Tailscale endpoint. The
	// route rule references exactly this tag, so the endpoint and the rule
	// cannot drift apart.
	exportMeshEndpointTag = "meshmux-ts"
)

// Stable export refusals. They are the diagnostic contract shared with the Web
// layer: only the code is logged.
const (
	// CodeMeshControlURLUnavailable: no Headscale control URL was configured.
	// The exporter never falls back to the public Tailscale SaaS control plane:
	// a MeshMux device must join the tailnet the Hub actually manages.
	CodeMeshControlURLUnavailable = "EXPORT_MESH_CONTROL_URL_UNAVAILABLE"
	// CodeMeshControlURLInvalid: the configured control URL is not one exact
	// HTTPS origin without a path, credentials, query or fragment.
	CodeMeshControlURLInvalid = "EXPORT_MESH_CONTROL_URL_INVALID"
	// CodeMeshAuthKeyInvalid: the one-shot Headscale pre-auth key is empty or
	// not a single safe token.
	CodeMeshAuthKeyInvalid = "EXPORT_MESH_AUTH_KEY_INVALID"
	// CodeMeshHostnameInvalid: the device hostname is not a canonical
	// lower-case DNS label accepted by the Tailscale endpoint.
	CodeMeshHostnameInvalid = "EXPORT_MESH_HOSTNAME_INVALID"
	// CodeMeshLineInTailnet: a literal Line address belongs to the tailnet
	// range. The first route rule would send that address to the Tailscale
	// endpoint instead of the Line, so the document is refused rather than
	// rendered into a loop.
	CodeMeshLineInTailnet = "EXPORT_MESH_LINE_IN_TAILNET"
	// CodeMeshPolicyInvalid: a policy-supplied tailnet prefix is not one
	// canonical CIDR network.
	CodeMeshPolicyInvalid = "EXPORT_MESH_POLICY_INVALID"
)

// MeshPolicy is the client-side routing policy of one mesh configuration. Its
// zero value is the 9c policy: the two built-in tailnet ranges are routed to
// the Tailscale endpoint and every other destination uses the proxy selector.
// The override fields exist so a later slice can supply the same ranges from
// the control plane without changing the exporter contract; they never enable
// TUN, LAN or SSID routing.
type MeshPolicy struct {
	TailnetIPv4 string
	TailnetIPv6 string
}

// MeshDeviceInput is the complete input of one device-scoped export. Lines and
// Credentials are the same public records a standard subscription download
// resolves, so one exporter validates both documents with the same plan.
type MeshDeviceInput struct {
	// DeviceID/DisplayName are audit labels only. They never appear as a
	// client identity and are not part of the rendered document.
	DeviceID    string
	DisplayName string
	// Hostname is the MeshMux-assigned Headscale node name.
	Hostname string
	// NodeName is accepted as an alias for Hostname so callers can pass the
	// stored device field directly. Hostname wins when both are set.
	NodeName string
	// ControlURL is the exact Headscale HTTPS origin.
	ControlURL string
	// HeadscaleOrigin is accepted as an alias for ControlURL.
	HeadscaleOrigin string
	// AuthKey is the one-shot Headscale pre-auth key. It is secret input and
	// deliberately absent from MeshConfigModel.
	AuthKey string
	// PreAuthKey is accepted as an alias for AuthKey.
	PreAuthKey  string
	Lines       []Line
	Credentials []Credential
	// Policy defaults to the zero-value 9c policy.
	Policy MeshPolicy
}

// normalized resolves the accepted field aliases without ever mutating the
// caller's value.
func (input MeshDeviceInput) normalized() MeshDeviceInput {
	if input.Hostname == "" {
		input.Hostname = input.NodeName
	}
	if input.ControlURL == "" {
		input.ControlURL = input.HeadscaleOrigin
	}
	if input.AuthKey == "" {
		input.AuthKey = input.PreAuthKey
	}
	return input
}

// MeshConfigModel is the non-secret projection of a mesh client document. It
// is built before any key is minted ("view first") and carries no auth key,
// enrollment secret, credential UUID, Line private key or subscription token.
// A reflection test pins this property so a later field cannot silently turn
// the page model into a secret carrier.
type MeshConfigModel struct {
	DeviceID        string
	DisplayName     string
	Hostname        string
	ControlURL      string
	TailnetPrefixes []string
	LineLabels      []string
}

// NewMeshConfigModel validates the non-secret half of a mesh export and
// returns the view model. It performs no I/O and mints nothing; the Web layer
// calls it before CreatePreAuthKey, so an invalid subscriber, Line set or
// control URL fails with zero Headscale key creations.
func NewMeshConfigModel(input MeshDeviceInput, policies ...MeshPolicy) (MeshConfigModel, error) {
	input = input.normalized()
	policy := meshPolicyFor(input, policies)
	prefixes, err := meshPolicyPrefixes(policy)
	if err != nil {
		return MeshConfigModel{}, err
	}
	if err := validateMeshControlURL(input.ControlURL); err != nil {
		return MeshConfigModel{}, err
	}
	if err := validateMeshHostname(input.Hostname); err != nil {
		return MeshConfigModel{}, err
	}
	plan, err := buildExportPlan(input.Lines, input.Credentials)
	if err != nil {
		return MeshConfigModel{}, err
	}
	if err := validateMeshLineAddresses(plan, prefixes); err != nil {
		return MeshConfigModel{}, err
	}
	labels := make([]string, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		labels = append(labels, node.Label)
	}
	return MeshConfigModel{
		DeviceID:        input.DeviceID,
		DisplayName:     input.DisplayName,
		Hostname:        input.Hostname,
		ControlURL:      input.ControlURL,
		TailnetPrefixes: prefixes,
		LineLabels:      labels,
	}, nil
}

// ExportMeshDevice renders one deterministic sing-box 1.14.3 client document
// for one proxy+mesh device. The output is byte-identical for the same input.
//
// The optional policy argument is accepted so a caller can supply the tailnet
// ranges explicitly; omitting it uses the zero-value 9c policy (and
// MeshDeviceInput.Policy when that is set).
func ExportMeshDevice(input MeshDeviceInput, policies ...MeshPolicy) ([]byte, error) {
	input = input.normalized()
	model, err := NewMeshConfigModel(input, policies...)
	if err != nil {
		return nil, err
	}
	if err := validateMeshAuthKey(input.AuthKey); err != nil {
		return nil, err
	}
	plan, err := buildExportPlan(input.Lines, input.Credentials)
	if err != nil {
		return nil, err
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
		Endpoints: []meshClientEndpoint{{
			Type:         "tailscale",
			Tag:          exportMeshEndpointTag,
			AuthKey:      input.AuthKey,
			ControlURL:   model.ControlURL,
			Hostname:     model.Hostname,
			AcceptRoutes: false,
			Ephemeral:    false,
		}},
		Route: meshClientRoute{
			DefaultDomainResolver: exportSingBoxDNSTag,
			Rules: []meshClientRouteRule{{
				IPCIDR:   model.TailnetPrefixes,
				Outbound: exportMeshEndpointTag,
			}},
			Final: exportSingBoxSelectorTag,
		},
	}
	selector := singBoxClientOutbound{
		Type: "selector",
		Tag:  exportSingBoxSelectorTag,
	}
	for _, node := range plan.Nodes {
		config.Outbounds = append(config.Outbounds, singBoxClientOutbound{
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
	config.Outbounds = append(config.Outbounds, selector)
	config.Outbounds = append(config.Outbounds, singBoxClientOutbound{
		Type: "direct",
		Tag:  exportSingBoxDirectTag,
	})
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("EXPORT_RENDER_FAILED")
	}
	return append(encoded, '\n'), nil
}

// meshPolicyFor resolves the optional positional policy and the embedded one.
// A zero-value embedded policy is always the 9c default.
func meshPolicyFor(input MeshDeviceInput, policies []MeshPolicy) MeshPolicy {
	policy := input.Policy
	if len(policies) > 0 {
		policy = policies[len(policies)-1]
	}
	return policy
}

// meshPolicyPrefixes returns the two routed prefixes in a stable order. It
// rejects an override that is not one canonical network prefix, so the route
// rule never carries a host route or a malformed CIDR.
func meshPolicyPrefixes(policy MeshPolicy) ([]string, error) {
	v4 := policy.TailnetIPv4
	if v4 == "" {
		v4 = MeshTailnetIPv4Prefix
	}
	v6 := policy.TailnetIPv6
	if v6 == "" {
		v6 = MeshTailnetIPv6Prefix
	}
	v4Prefix, err := canonicalMeshPrefix(v4)
	if err != nil {
		return nil, errors.New(CodeMeshPolicyInvalid + ": the IPv4 tailnet prefix is not canonical")
	}
	v6Prefix, err := canonicalMeshPrefix(v6)
	if err != nil {
		return nil, errors.New(CodeMeshPolicyInvalid + ": the IPv6 tailnet prefix is not canonical")
	}
	return []string{v4Prefix.String(), v6Prefix.String()}, nil
}

func canonicalMeshPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Masked() != prefix {
		return netip.Prefix{}, errors.New("not a canonical CIDR network")
	}
	return prefix, nil
}

// validateMeshControlURL accepts one exact HTTPS origin. An empty value is
// refused: falling back to controlplane.tailscale.com would silently enroll
// the device into a tailnet the Hub does not manage.
func validateMeshControlURL(raw string) error {
	if raw == "" {
		return errors.New(CodeMeshControlURLUnavailable + ": configure the Headscale origin")
	}
	if raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t\r\n") {
		return errors.New(CodeMeshControlURLInvalid + ": the control URL must be one exact origin")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return errors.New(CodeMeshControlURLInvalid + ": the control URL must be one exact HTTPS origin without a path")
	}
	return nil
}

// validateMeshAuthKey checks the one-shot key shape without interpreting it.
// The key is never echoed in an error.
func validateMeshAuthKey(key string) error {
	if key == "" || len(key) > 512 || strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t\r\n") {
		return errors.New(CodeMeshAuthKeyInvalid + ": a one-shot Headscale pre-auth key is required")
	}
	return nil
}

// validateMeshHostname accepts the canonical label MeshMux assigns as the
// Headscale node name. The Tailscale endpoint uses it as its hostname.
func validateMeshHostname(hostname string) error {
	if len(hostname) == 0 || len(hostname) > 63 {
		return errors.New(CodeMeshHostnameInvalid + ": the hostname must be 1-63 characters")
	}
	if hostname[0] == '-' || hostname[len(hostname)-1] == '-' {
		return errors.New(CodeMeshHostnameInvalid + ": the hostname must not start or end with a hyphen")
	}
	for _, r := range hostname {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return errors.New(CodeMeshHostnameInvalid + ": the hostname must be a lowercase DNS label")
	}
	return nil
}

// validateMeshLineAddresses refuses a literal Line address inside the tailnet
// range. A hostname is not resolved here; DNS answers are outside this pure
// renderer, but a literal address is a deterministic routing conflict.
func validateMeshLineAddresses(plan *exportPlan, tailnetPrefixes []string) error {
	prefixes := make([]netip.Prefix, 0, len(tailnetPrefixes))
	for _, raw := range tailnetPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return errors.New(CodeMeshPolicyInvalid + ": the tailnet prefix is not canonical")
		}
		prefixes = append(prefixes, prefix)
	}
	for _, node := range plan.Nodes {
		address, err := netip.ParseAddr(node.Line.Server)
		if err != nil {
			continue
		}
		address = address.Unmap()
		for _, prefix := range prefixes {
			prefix = prefix.Masked()
			if prefix.Addr().Is4() != address.Is4() {
				continue
			}
			if prefix.Contains(address) {
				return errors.New(CodeMeshLineInTailnet + ": a literal Line address belongs to the tailnet range")
			}
		}
	}
	return nil
}

// meshClientConfig is the device-scoped sing-box client document. Field order
// is fixed by the struct layout so the output is byte-deterministic.
type meshClientConfig struct {
	Log       singBoxClientLog        `json:"log"`
	DNS       singBoxClientDNS        `json:"dns"`
	Inbounds  []singBoxClientInbound  `json:"inbounds"`
	Endpoints []meshClientEndpoint    `json:"endpoints"`
	Outbounds []singBoxClientOutbound `json:"outbounds"`
	Route     meshClientRoute         `json:"route"`
}

// meshClientEndpoint uses only the fields sing-box 1.14.3 accepts for the
// tailscale endpoint. In particular it carries no system_interface and no TUN
// or LAN option: 9c is a single-VPN proxy+mesh document, not a full-device
// tunnel.
type meshClientEndpoint struct {
	Type         string `json:"type"`
	Tag          string `json:"tag"`
	AuthKey      string `json:"auth_key"`
	ControlURL   string `json:"control_url"`
	Hostname     string `json:"hostname"`
	AcceptRoutes bool   `json:"accept_routes"`
	Ephemeral    bool   `json:"ephemeral"`
}

type meshClientRoute struct {
	DefaultDomainResolver string                `json:"default_domain_resolver"`
	Rules                 []meshClientRouteRule `json:"rules"`
	Final                 string                `json:"final"`
}

type meshClientRouteRule struct {
	IPCIDR   []string `json:"ip_cidr"`
	Outbound string   `json:"outbound"`
}
