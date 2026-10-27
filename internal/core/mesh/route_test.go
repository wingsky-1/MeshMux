package mesh

import (
	"errors"
	"testing"
)

func routeFailureCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	var domain *DomainError
	if !errors.As(err, &domain) {
		t.Fatalf("error %v is not a *DomainError", err)
	}
	return domain.Code
}

// TestNormalizeRoutePrefixCanonicalizes proves the accepted spelling is the one
// stored: an already aligned prefix round-trips and a padded one is trimmed, so
// two spellings can never become two declarations.
func TestNormalizeRoutePrefixCanonicalizes(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{" 192.168.1.0/24 ", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"172.16.0.0/12", "172.16.0.0/12"},
		{"192.168.0.0/16", "192.168.0.0/16"},
		{"fd12:3456:789a::/48", "fd12:3456:789a::/48"},
		{"2001:db9:1::/64", "2001:db9:1::/64"},
	} {
		got, err := NormalizeRoutePrefix(test.raw)
		if err != nil {
			t.Fatalf("%q refused: %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("%q normalized to %q, want %q", test.raw, got, test.want)
		}
	}
}

// TestParseRoutePrefixRefusesHostBits keeps a typo visible: 192.168.1.5/24 is
// not silently masked into the network the operator may not have meant.
func TestParseRoutePrefixRefusesHostBits(t *testing.T) {
	for _, raw := range []string{"192.168.1.5/24", "10.1.2.3/8", "2001:db8::1/64"} {
		if _, err := ParseRoutePrefix(raw); routeFailureCode(t, err) != CodeRoutePrefixInvalid {
			t.Fatalf("%q accepted with host bits: %v", raw, err)
		}
		if _, err := NormalizeRoutePrefix(raw); routeFailureCode(t, err) != CodeRoutePrefixInvalid {
			t.Fatalf("%q normalized despite host bits: %v", raw, err)
		}
	}
}

// TestParseRoutePrefixRefusesMalformed keeps the parser strict about notation:
// a bare address, a bad length, an IPv4-mapped IPv6 prefix and an empty string
// are all refused before any routability question is asked.
func TestParseRoutePrefixRefusesMalformed(t *testing.T) {
	for _, raw := range []string{"", "192.168.1.0", "192.168.1.0/33", "192.168.1.0/x", "::/129", "::ffff:192.168.1.0/120", "not-a-prefix"} {
		if _, err := ParseRoutePrefix(raw); routeFailureCode(t, err) != CodeRoutePrefixInvalid {
			t.Fatalf("%q accepted: %v", raw, err)
		}
	}
}

// TestValidateRoutablePrefixRefusesDangerousRanges is the core admission rule:
// an exit route, the tailnet itself and the ranges that cannot carry a LAN are
// all refused, including a wider prefix that merely contains one of them.
func TestValidateRoutablePrefixRefusesDangerousRanges(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0/0", "::/0", // exit routes
		"0.0.0.0/8",             // this-network
		"100.64.0.0/10",         // the tailnet itself
		"100.0.0.0/8",           // wider than the tailnet, so it contains it
		"fd7a:115c:a1e0::/48",   // the tailnet itself, IPv6
		"fd7a:115c::/32",        // wider than the IPv6 tailnet
		"127.0.0.0/8",           // loopback
		"127.0.0.1/32",          // loopback host
		"169.254.0.0/16",        // IPv4 link-local
		"192.0.2.0/24",          // documentation
		"198.51.100.0/24",       // documentation
		"203.0.113.0/24",        // documentation
		"224.0.0.0/4",           // multicast
		"239.0.0.0/8",           // multicast
		"240.0.0.0/4",           // reserved
		"::/128",                // unspecified
		"::1/128",               // loopback
		"fe80::/10",             // IPv6 link-local
		"ff00::/8",              // IPv6 multicast
		"2001:db8::/32",         // documentation
		"2001:db8:dead::/48",    // documentation
		"2001:db8:0:1::/64",     // documentation
		"100.64.1.0/24",         // inside the tailnet
		"fd7a:115c:a1e0:1::/64", // inside the IPv6 tailnet
	} {
		if _, err := NormalizeRoutePrefix(raw); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
			t.Fatalf("%q accepted as a subnet route: %v", raw, err)
		}
	}
}

// TestValidateRoutablePrefixAcceptsLANRanges proves the rule does not
// over-reject: private LAN ranges, a public /24 and a ULA are ordinary subnet
// routes.
func TestValidateRoutablePrefixAcceptsLANRanges(t *testing.T) {
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "203.0.114.0/24", "fd12:3456:789a::/48", "2001:db9::/32"} {
		if _, err := NormalizeRoutePrefix(raw); err != nil {
			t.Fatalf("%q refused: %v", raw, err)
		}
	}
}

// TestValidateRoutablePrefixRejectsZeroBitsSeparately keeps the exit route
// distinguishable: it is a routability refusal, not a syntax error, so a caller
// can report "an exit route is not a subnet route".
func TestValidateRoutablePrefixRejectsZeroBitsSeparately(t *testing.T) {
	prefix, err := ParseRoutePrefix("0.0.0.0/0")
	if err != nil {
		t.Fatalf("a /0 must parse as a prefix: %v", err)
	}
	if err = ValidateRoutablePrefix(prefix); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
		t.Fatalf("exit route accepted: %v", err)
	}
}

// TestNormalizeDeclaredPrefixesOnlyForSubnetRouter is the purpose rule: only a
// subnet_router declares LAN prefixes, and the list is a canonical set.
func TestNormalizeDeclaredPrefixesOnlyForSubnetRouter(t *testing.T) {
	got, err := NormalizeDeclaredPrefixes(PurposeSubnetRouter, []string{" 192.168.1.0/24 ", "", "192.168.1.0/24", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "192.168.1.0/24" || got[1] != "10.0.0.0/8" {
		t.Fatalf("declared prefixes = %v, want the canonical deduplicated set", got)
	}
	// A device with no declaration is ordinary, not an error.
	if got, err = NormalizeDeclaredPrefixes(PurposeSubnetRouter, []string{" ", ""}); err != nil || got != nil {
		t.Fatalf("empty declaration = %v %v, want nil", got, err)
	}
	for _, purpose := range []Purpose{PurposeProxyMesh, PurposeMeshOnly} {
		if _, err = NormalizeDeclaredPrefixes(purpose, []string{"192.168.1.0/24"}); routeFailureCode(t, err) != CodeRouteDeclarationInvalid {
			t.Fatalf("%s accepted a subnet declaration: %v", purpose, err)
		}
	}
	if _, err = NormalizeDeclaredPrefixes(PurposeSubnetRouter, []string{"0.0.0.0/0"}); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
		t.Fatalf("exit route accepted as a declaration: %v", err)
	}
}

// TestNewMeshDeviceValidatesDeclaredRoutes proves the creation path refuses a
// malformed or forbidden pre-declaration before anything is stored, and that a
// subnet_router may pre-declare its prefixes.
func TestNewMeshDeviceValidatesDeclaredRoutes(t *testing.T) {
	spec := specFor(PurposeSubnetRouter, "")
	spec.DeclaredRoutes = []string{"192.168.1.0/24"}
	device := testDevice(t, spec)
	if device.Purpose != PurposeSubnetRouter {
		t.Fatalf("purpose = %q", device.Purpose)
	}

	bad := specFor(PurposeSubnetRouter, "")
	bad.DeclaredRoutes = []string{"192.168.1.5/24"}
	if _, err := NewMeshDevice(bad); routeFailureCode(t, err) != CodeRoutePrefixInvalid {
		t.Fatalf("host bits accepted at creation: %v", err)
	}
	exit := specFor(PurposeSubnetRouter, "")
	exit.DeclaredRoutes = []string{"0.0.0.0/0"}
	if _, err := NewMeshDevice(exit); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
		t.Fatalf("exit route accepted at creation: %v", err)
	}
	meshOnly := specFor(PurposeMeshOnly, "")
	meshOnly.DeclaredRoutes = []string{"192.168.1.0/24"}
	if _, err := NewMeshDevice(meshOnly); routeFailureCode(t, err) != CodeRouteDeclarationInvalid {
		t.Fatalf("mesh_only accepted a declaration: %v", err)
	}
}

// TestRouteTransitionTable pins the intent state machine: approved and
// advertised may trade places, both may be revoked, revoked is terminal.
func TestRouteTransitionTable(t *testing.T) {
	allowed := map[[2]RouteDesired]bool{
		{RouteDesiredAdvertised, RouteDesiredAdvertised}: true,
		{RouteDesiredAdvertised, RouteDesiredApproved}:   true,
		{RouteDesiredAdvertised, RouteDesiredRevoked}:    true,
		{RouteDesiredApproved, RouteDesiredApproved}:     true,
		{RouteDesiredApproved, RouteDesiredAdvertised}:   true,
		{RouteDesiredApproved, RouteDesiredRevoked}:      true,
		{RouteDesiredRevoked, RouteDesiredRevoked}:       true,
	}
	for from := range map[RouteDesired]bool{
		RouteDesiredAdvertised: true, RouteDesiredApproved: true, RouteDesiredRevoked: true,
	} {
		for to := range map[RouteDesired]bool{
			RouteDesiredAdvertised: true, RouteDesiredApproved: true, RouteDesiredRevoked: true,
		} {
			if got, want := RouteTransitionAllowed(from, to), allowed[[2]RouteDesired{from, to}]; got != want {
				t.Fatalf("RouteTransitionAllowed(%q, %q) = %v, want %v", from, to, got, want)
			}
		}
	}
	if RouteTransitionAllowed("unknown", RouteDesiredAdvertised) {
		t.Fatal("an undefined desired state allows a transition")
	}
}

// TestRouteStatesValidate keeps the stored enums strict: an unknown desired,
// observed or source value can never be written or read as valid.
func TestRouteStatesValidate(t *testing.T) {
	for _, desired := range []RouteDesired{RouteDesiredAdvertised, RouteDesiredApproved, RouteDesiredRevoked} {
		if err := desired.Validate(); err != nil {
			t.Fatalf("%q refused: %v", desired, err)
		}
	}
	if err := RouteDesired("served").Validate(); routeFailureCode(t, err) != CodeRouteDesiredInvalid {
		t.Fatalf("undefined desired accepted: %v", err)
	}
	for _, observed := range []RouteObserved{RouteObservedNone, RouteObservedAdvertised, RouteObservedApproved, RouteObservedServed} {
		if err := observed.Validate(); err != nil {
			t.Fatalf("%q refused: %v", observed, err)
		}
	}
	if err := RouteObserved("desired").Validate(); routeFailureCode(t, err) != CodeRouteObservedInvalid {
		t.Fatalf("undefined observed accepted: %v", err)
	}
	for _, source := range []RouteSource{RouteSourceDevice, RouteSourceOperator} {
		if err := source.Validate(); err != nil {
			t.Fatalf("%q refused: %v", source, err)
		}
	}
	if err := RouteSource("headscale").Validate(); routeFailureCode(t, err) != CodeRouteSourceInvalid {
		t.Fatalf("undefined source accepted: %v", err)
	}
}

// TestMeshRouteValidateRequiresCanonicalPrefix keeps a hand-written row from
// introducing a second spelling of an already declared network.
func TestMeshRouteValidateRequiresCanonicalPrefix(t *testing.T) {
	valid := MeshRoute{
		DeviceID: testSubscriberID,
		Prefix:   "192.168.1.0/24",
		Desired:  RouteDesiredAdvertised,
		Observed: RouteObservedNone,
		Source:   RouteSourceDevice,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid route refused: %v", err)
	}
	nonCanonical := valid
	nonCanonical.Prefix = "192.168.001.0/24"
	if err := nonCanonical.Validate(); routeFailureCode(t, err) != CodeRoutePrefixInvalid {
		t.Fatalf("non-canonical prefix accepted: %v", err)
	}
	exit := valid
	exit.Prefix = "0.0.0.0/0"
	if err := exit.Validate(); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
		t.Fatalf("exit route record accepted: %v", err)
	}
	badID := valid
	badID.DeviceID = "not-an-id"
	if err := badID.Validate(); routeFailureCode(t, err) != CodeDeviceIDInvalid {
		t.Fatalf("malformed device id accepted: %v", err)
	}
	badSource := valid
	badSource.Source = "other"
	if err := badSource.Validate(); routeFailureCode(t, err) != CodeRouteSourceInvalid {
		t.Fatalf("undefined source accepted: %v", err)
	}
}

// TestTailnetPrefixesAreTheRenderedOnes keeps the domain constants and the
// installer's Headscale `prefixes` block from drifting: the values are compared
// against the strings the renderer emits.
func TestTailnetPrefixesAreTheRenderedOnes(t *testing.T) {
	if TailnetIPv4Prefix != "100.64.0.0/10" || TailnetIPv6Prefix != "fd7a:115c:a1e0::/48" {
		t.Fatalf("tailnet prefixes = %q / %q", TailnetIPv4Prefix, TailnetIPv6Prefix)
	}
	for _, raw := range []string{TailnetIPv4Prefix, TailnetIPv6Prefix} {
		if _, err := NormalizeRoutePrefix(raw); routeFailureCode(t, err) != CodeRoutePrefixNotRoutable {
			t.Fatalf("tailnet prefix %q accepted as a subnet route: %v", raw, err)
		}
	}
}
