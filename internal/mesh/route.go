package mesh

import (
	"net/netip"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The stable codes for subnet route declarations. They follow the same
// diagnostic contract as the device codes: a caller logs the code and the
// operation id, and never free-form Headscale text.
const (
	// CodeRoutePrefixInvalid: the prefix is not one canonical, aligned CIDR
	// network.
	CodeRoutePrefixInvalid = "MESH_ROUTE_PREFIX_INVALID"
	// CodeRoutePrefixNotRoutable: the prefix is syntactically valid but must
	// never be routed as a subnet route (exit route, tailnet itself, loopback,
	// link-local, multicast or documentation range).
	CodeRoutePrefixNotRoutable = "MESH_ROUTE_PREFIX_NOT_ROUTABLE"
	// CodeRouteDeclarationInvalid: the declared prefix list contradicts the
	// device purpose or exceeds the bounded declaration size.
	CodeRouteDeclarationInvalid = "MESH_ROUTE_DECLARATION_INVALID"
	// CodeRouteDesiredInvalid: the desired route state is not one of the three
	// defined values.
	CodeRouteDesiredInvalid = "MESH_ROUTE_DESIRED_INVALID"
	// CodeRouteObservedInvalid: the observed route state is not one of the four
	// defined values.
	CodeRouteObservedInvalid = "MESH_ROUTE_OBSERVED_INVALID"
	// CodeRouteSourceInvalid: the declaration source is not device or operator.
	CodeRouteSourceInvalid = "MESH_ROUTE_SOURCE_INVALID"
	// CodeRouteTransitionInvalid: the requested desired-state edge is not in the
	// route transition table, or a new route would start revoked.
	CodeRouteTransitionInvalid = "MESH_ROUTE_TRANSITION_INVALID"
)

// TailnetIPv4Prefix and TailnetIPv6Prefix are the address ranges the managed
// Headscale instance hands to mesh devices. The installer renders the same two
// values into the Headscale `prefixes` block, so the domain and the rendered
// control plane cannot drift. They are also the two ranges a subnet route must
// never claim: routing them would send the tailnet through itself.
const (
	TailnetIPv4Prefix = "100.64.0.0/10"
	TailnetIPv6Prefix = "fd7a:115c:a1e0::/48"
)

// RouteDesired is what the Hub intends for one prefix. It is MeshMux's intent,
// never a statement about Headscale: only an explicit approval action moves a
// prefix to approved, and no observation ever does.
type RouteDesired string

const (
	// RouteDesiredAdvertised: the prefix is declared (pre-declared while the
	// device is created, or declared later) and awaits an explicit approval.
	RouteDesiredAdvertised RouteDesired = "advertised"
	// RouteDesiredApproved: the operator approved the prefix. The remote
	// Headscale approval is a separate adapter action.
	RouteDesiredApproved RouteDesired = "approved"
	// RouteDesiredRevoked: the prefix was withdrawn. Terminal for this route
	// record; re-declaring it is a new, separately audited act.
	RouteDesiredRevoked RouteDesired = "revoked"
)

// Validate accepts only the three defined desired states.
func (d RouteDesired) Validate() error {
	switch d {
	case RouteDesiredAdvertised, RouteDesiredApproved, RouteDesiredRevoked:
		return nil
	default:
		return failure(CodeRouteDesiredInvalid, "desired must be advertised, approved or revoked")
	}
}

// RouteObserved is what one Headscale read reported for a prefix. The empty
// value means "not reported": a node that never advertised the prefix and a
// read that no longer lists it both look like this.
type RouteObserved string

const (
	// RouteObservedNone: Headscale reported nothing for this prefix.
	RouteObservedNone RouteObserved = ""
	// RouteObservedAdvertised: the node advertises the prefix, Headscale has
	// not approved it.
	RouteObservedAdvertised RouteObserved = "advertised"
	// RouteObservedApproved: Headscale lists the prefix as approved.
	RouteObservedApproved RouteObserved = "approved"
	// RouteObservedServed: Headscale lists the prefix as served by the node.
	RouteObservedServed RouteObserved = "served"
)

// Validate accepts only the four defined observed states, including the empty
// "nothing reported" value.
func (o RouteObserved) Validate() error {
	switch o {
	case RouteObservedNone, RouteObservedAdvertised, RouteObservedApproved, RouteObservedServed:
		return nil
	default:
		return failure(CodeRouteObservedInvalid, "observed must be empty, advertised, approved or served")
	}
}

// RouteSource records where a declaration came from. It is audit metadata and
// never a state-machine input: a pre-declared prefix and a later operator
// declaration follow the same desired-state rules.
type RouteSource string

const (
	// RouteSourceDevice: the prefix was pre-declared while a subnet_router
	// device was created.
	RouteSourceDevice RouteSource = "device"
	// RouteSourceOperator: the prefix was declared by a later explicit action.
	RouteSourceOperator RouteSource = "operator"
)

// Validate accepts only the two defined declaration sources.
func (s RouteSource) Validate() error {
	switch s {
	case RouteSourceDevice, RouteSourceOperator:
		return nil
	default:
		return failure(CodeRouteSourceInvalid, "source must be device or operator")
	}
}

// RouteTransitionAllowed reports whether a route may move from one desired
// state to another. A same-state call is an idempotent no-op. advertised and
// approved may trade places (approve, withdraw approval) and both may be
// revoked; revoked is terminal, so re-declaring a withdrawn prefix is a
// separate audited act rather than an ordinary transition.
func RouteTransitionAllowed(from, to RouteDesired) bool {
	if from == to {
		return from.Validate() == nil
	}
	switch from {
	case RouteDesiredAdvertised:
		return to == RouteDesiredApproved || to == RouteDesiredRevoked
	case RouteDesiredApproved:
		return to == RouteDesiredAdvertised || to == RouteDesiredRevoked
	default:
		return false
	}
}

// nonRoutablePrefixes are ranges a subnet route must never claim. The check is
// overlap based, so a prefix that merely contains one of these ranges (for
// example 100.0.0.0/8 around the tailnet) is refused too.
var nonRoutablePrefixes = []struct {
	prefix netip.Prefix
	detail string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "the 0.0.0.0/8 this-network range is not routable"},
	{netip.MustParsePrefix(TailnetIPv4Prefix), "the tailnet address range cannot be a subnet route"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback is not a subnet route"},
	{netip.MustParsePrefix("169.254.0.0/16"), "the IPv4 link-local range is not a subnet route"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation ranges are not subnet routes"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation ranges are not subnet routes"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation ranges are not subnet routes"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast is not a subnet route"},
	{netip.MustParsePrefix("240.0.0.0/4"), "the reserved and broadcast range is not a subnet route"},
	{netip.MustParsePrefix("::/128"), "the unspecified address is not a subnet route"},
	{netip.MustParsePrefix("::1/128"), "loopback is not a subnet route"},
	{netip.MustParsePrefix(TailnetIPv6Prefix), "the tailnet address range cannot be a subnet route"},
	{netip.MustParsePrefix("fe80::/10"), "the IPv6 link-local range is not a subnet route"},
	{netip.MustParsePrefix("ff00::/8"), "multicast is not a subnet route"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation ranges are not subnet routes"},
}

// ParseRoutePrefix parses one CIDR route prefix. It refuses host bits: a
// request for 192.168.1.5/24 is a mistake about which network the operator
// meant, so it is reported instead of being silently masked. IPv4-mapped IPv6
// prefixes are refused for the same reason: they name an IPv4 network through a
// second notation.
func ParseRoutePrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, failure(CodeRoutePrefixInvalid, "need one CIDR prefix such as 192.168.1.0/24")
	}
	if prefix.Addr().Is4In6() {
		return netip.Prefix{}, failure(CodeRoutePrefixInvalid, "an IPv4-mapped IPv6 prefix is not accepted")
	}
	if prefix.Masked() != prefix {
		return netip.Prefix{}, failure(CodeRoutePrefixInvalid, "host bits must be zero: declare the network prefix")
	}
	return prefix, nil
}

// ValidateRoutablePrefix accepts an already parsed prefix only when it may be
// routed as a subnet route. An exit route (/0), the tailnet's own ranges and
// loopback, link-local, multicast, unspecified, reserved and documentation
// ranges are all refused: approving one would either capture the tailnet or
// point the mesh at addresses that cannot carry a LAN.
func ValidateRoutablePrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return failure(CodeRoutePrefixInvalid, "need one parsed CIDR prefix")
	}
	if prefix.Addr().Is4In6() {
		return failure(CodeRoutePrefixInvalid, "an IPv4-mapped IPv6 prefix is not accepted")
	}
	if prefix.Masked() != prefix {
		return failure(CodeRoutePrefixInvalid, "host bits must be zero: declare the network prefix")
	}
	if prefix.Bits() == 0 {
		return failure(CodeRoutePrefixNotRoutable, "an exit route (/0) is not a subnet route")
	}
	for _, blocked := range nonRoutablePrefixes {
		if blocked.prefix.Overlaps(prefix) {
			return failure(CodeRoutePrefixNotRoutable, blocked.detail)
		}
	}
	return nil
}

// NormalizeRoutePrefix parses, checks and canonicalizes one prefix. The
// canonical string is what gets stored and compared, so two spellings of the
// same network cannot become two declarations.
func NormalizeRoutePrefix(raw string) (string, error) {
	prefix, err := ParseRoutePrefix(raw)
	if err != nil {
		return "", err
	}
	if err := ValidateRoutablePrefix(prefix); err != nil {
		return "", err
	}
	return prefix.String(), nil
}

// maxDeclaredRoutes bounds one device's declaration list. It is a storage and
// request-size guard, not a product limit: a real LAN has a handful of
// prefixes.
const maxDeclaredRoutes = 64

// NormalizeDeclaredPrefixes validates and canonicalizes the prefixes declared
// while a subnet_router device is created. Only a subnet_router may declare
// them: a proxy_mesh or mesh_only device is not the router of a LAN. Empty
// entries (a form line left blank) are ignored and a repeated prefix is kept
// once, because the declaration is a set, not an ordered list.
func NormalizeDeclaredPrefixes(purpose Purpose, raw []string) ([]string, error) {
	if err := purpose.Validate(); err != nil {
		return nil, err
	}
	cleaned := make([]string, 0, len(raw))
	for _, item := range raw {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	if len(cleaned) == 0 {
		return nil, nil
	}
	if purpose != PurposeSubnetRouter {
		return nil, failure(CodeRouteDeclarationInvalid, "only a subnet_router device can declare subnet routes")
	}
	if len(cleaned) > maxDeclaredRoutes {
		return nil, failure(CodeRouteDeclarationInvalid, "at most 64 prefixes can be declared for one device")
	}
	out := make([]string, 0, len(cleaned))
	seen := make(map[string]struct{}, len(cleaned))
	for _, item := range cleaned {
		prefix, err := NormalizeRoutePrefix(item)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

// MeshRoute is one declared subnet route of one mesh device. The record is a
// declaration plus the last observed evidence; it carries no Headscale state
// machine of its own. Desired is MeshMux's intent, Observed is the latest
// reported evidence, and neither is derived from the other: an observation
// never approves a prefix, and an approval never claims the prefix is served.
type MeshRoute struct {
	DeviceID string
	Prefix   string
	Desired  RouteDesired
	Observed RouteObserved
	Source   RouteSource
}

// Validate checks the record without any I/O. The prefix must be stored in its
// canonical form, so a hand-edited row cannot introduce a second spelling of an
// already declared network.
func (r MeshRoute) Validate() error {
	if err := subscription.ValidateID(r.DeviceID); err != nil {
		return failure(CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	normalized, err := NormalizeRoutePrefix(r.Prefix)
	if err != nil {
		return err
	}
	if normalized != r.Prefix {
		return failure(CodeRoutePrefixInvalid, "the stored prefix must be canonical")
	}
	if err := r.Desired.Validate(); err != nil {
		return err
	}
	if err := r.Observed.Validate(); err != nil {
		return err
	}
	return r.Source.Validate()
}
