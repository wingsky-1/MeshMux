package node

import (
	"bytes"
	"strings"
	"testing"
)

// TestCompileACL_DefaultDenyAndAllowlistOrder pins the data-plane contract of
// the Out guard: no authorized source means the two VLESS drops are the whole
// chain, and every authorized source is accepted strictly before them. A
// flipped order would drop an authorized Line and admit nothing, so the
// position of every accept relative to the first drop is asserted, not just
// the presence of the strings.
func TestCompileACL_DefaultDenyAndAllowlistOrder(t *testing.T) {
	edge := validCandidate()
	edge.Role = RoleEdge
	acl, err := CompileACL(edge, nil)
	if err != nil {
		t.Fatalf("edge compile = %v", err)
	}
	if acl != nil {
		t.Fatalf("edge node rendered an Out table: %q", acl)
	}
	// An Edge never owns the Out table, so a stray allowlist renders nothing;
	// a malformed one still fails because it is a Hub defect.
	if acl, err = CompileACL(edge, []string{"203.0.113.7"}); err != nil || acl != nil {
		t.Fatalf("edge with allowlist = %q, %v; want nil, nil", acl, err)
	}
	if _, err := CompileACL(edge, []string{"not-an-ip"}); err == nil ||
		!strings.Contains(err.Error(), "ACL_SOURCE_INVALID") {
		t.Fatalf("edge with malformed allowlist = %v, want ACL_SOURCE_INVALID", err)
	}

	empty, err := CompileACL(validCandidate(), nil)
	if err != nil {
		t.Fatalf("default-deny compile = %v", err)
	}
	for _, want := range []string{
		"table inet meshmux_out",
		"delete table inet meshmux_out",
		"type filter hook input priority -10; policy accept;",
		"tcp dport 8443 drop",
		"udp dport 8443 drop",
	} {
		if !bytes.Contains(empty, []byte(want)) {
			t.Fatalf("default-deny ACL missing %q:\n%s", want, empty)
		}
	}
	if strings.Contains(strings.ReplaceAll(string(empty), "policy accept", ""), "accept") {
		t.Fatalf("empty allowlist rendered an accept rule:\n%s", empty)
	}

	allowed := []string{"203.0.113.7", "2001:db8::/32", "198.51.100.0/24"}
	rendered, err := CompileACL(validCandidate(), allowed)
	if err != nil {
		t.Fatalf("allowlist compile = %v", err)
	}
	text := string(rendered)
	for _, want := range []string{
		"ip saddr 198.51.100.0/24 tcp dport 8443 accept",
		"ip saddr 203.0.113.7/32 tcp dport 8443 accept",
		"ip6 saddr 2001:db8::/32 tcp dport 8443 accept",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("allowlist ACL missing %q:\n%s", want, text)
		}
	}
	// Every accept must precede both drops: the guard authorizes by order.
	firstDrop := strings.Index(text, "tcp dport 8443 drop")
	if firstDrop < 0 {
		t.Fatalf("allowlist ACL lost the tcp drop:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasSuffix(line, "accept") {
			continue
		}
		if index := strings.Index(text, line); index > firstDrop {
			t.Fatalf("accept rule appears after the drop:\n%s", text)
		}
	}
	// IPv6 shares the inet table: no second family table, no v4-only rule set.
	if strings.Contains(text, "table ip6 ") || strings.Contains(text, "table ip ") {
		t.Fatalf("allowlist rendered a second table:\n%s", text)
	}
	for _, forbidden := range []string{"flush ruleset", "tcp dport 22", "ct state established", "policy drop"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("ACL contains unsafe rule %q:\n%s", forbidden, text)
		}
	}
	if !strings.Contains(text, "table inet meshmux_out {}\ndelete table inet meshmux_out") {
		t.Fatalf("ACL lacks idempotent exact-table replacement:\n%s", text)
	}
}

// TestCompileACL_CanonicalizesSources pins that the same authorization always
// renders the same bytes: masked prefixes, de-duplicated and sorted, so the
// readback comparison and the LKG file hash cannot flap on input order.
func TestCompileACL_CanonicalizesSources(t *testing.T) {
	first, err := CompileACL(validCandidate(), []string{
		"203.0.113.7", "198.51.100.99/24", "2001:DB8::1", "198.51.100.0/24",
	})
	if err != nil {
		t.Fatalf("compile = %v", err)
	}
	second, err := CompileACL(validCandidate(), []string{
		"2001:db8::1/128", "198.51.100.0/24", "203.0.113.7/32",
	})
	if err != nil {
		t.Fatalf("compile = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("equivalent allowlists rendered differently:\n%s\n---\n%s", first, second)
	}
	text := string(first)
	if strings.Count(text, "198.51.100.0/24") != 1 {
		t.Fatalf("masked duplicate was not de-duplicated:\n%s", text)
	}
	if strings.Contains(text, "198.51.100.99/24") {
		t.Fatalf("unmasked prefix reached the ruleset:\n%s", text)
	}
}

// TestCompileACL_RejectsInvalidSources pins ACL_SOURCE_INVALID for every shape
// that must never become a rule: empty, junk, a zero-length prefix that would
// disable default deny, an interface zone and a v4-in-v6 literal.
func TestCompileACL_RejectsInvalidSources(t *testing.T) {
	for _, source := range []string{
		"",
		" ",
		" 203.0.113.7",
		"203.0.113.7 ",
		"0.0.0.0/0",
		"::/0",
		"not-an-ip",
		"203.0.113.7/33",
		"2001:db8::/129",
		"203.0.113.7/24/8",
		"fe80::1%eth0",
		"::ffff:203.0.113.7",
		"1.2.3.4; drop",
		"$(reboot)",
		"203.0.113.7\naccept",
		strings.Repeat("1", 65),
	} {
		if _, err := CompileACL(validCandidate(), []string{source}); err == nil ||
			!strings.Contains(err.Error(), "ACL_SOURCE_INVALID") {
			t.Errorf("source %q = %v, want ACL_SOURCE_INVALID", source, err)
		}
	}
	tooMany := make([]string, maxACLSources+1)
	for i := range tooMany {
		tooMany[i] = "203.0.113.7"
	}
	if _, err := CompileACL(validCandidate(), tooMany); err == nil ||
		!strings.Contains(err.Error(), "ACL_SOURCE_INVALID") {
		t.Fatalf("oversized allowlist = %v, want ACL_SOURCE_INVALID", err)
	}
}

// TestParseACLAllowedRoundTripsCanonicalRender pins the installer/Agent
// contract: an applied ACL file is trusted only when it is exactly the
// canonical render for the allowlist it contains.
func TestParseACLAllowedRoundTripsCanonicalRender(t *testing.T) {
	allowed := []string{"203.0.113.7", "2001:db8::/32"}
	rendered, err := CompileACL(validCandidate(), allowed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseACLAllowed(validCandidate(), rendered)
	if err != nil {
		t.Fatalf("canonical render rejected: %v", err)
	}
	if !sameACLSources(parsed, allowed) {
		t.Fatalf("parsed = %v, want %v", parsed, allowed)
	}
	empty, err := CompileACL(validCandidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err = ParseACLAllowed(validCandidate(), empty); err != nil || len(parsed) != 0 {
		t.Fatalf("default-deny render = %v, %v", parsed, err)
	}

	// A stale or hand-edited file is not a MeshMux render: it may add an
	// unauthorized accept, move one after the drop, or drop a rule entirely.
	unauthorized := bytes.Replace(rendered,
		[]byte("    tcp dport 8443 drop"),
		[]byte("    ip saddr 192.0.2.1 tcp dport 8443 accept\n    tcp dport 8443 drop"), 1)
	if _, err := ParseACLAllowed(validCandidate(), unauthorized); err == nil {
		t.Fatal("hand-added accept was accepted as canonical")
	}
	afterDrop := bytes.Replace(rendered,
		[]byte("    ip saddr 203.0.113.7/32 tcp dport 8443 accept\n"), nil, 1)
	afterDrop = append(afterDrop, []byte("    ip saddr 203.0.113.7/32 tcp dport 8443 accept\n")...)
	if _, err := ParseACLAllowed(validCandidate(), afterDrop); err == nil {
		t.Fatal("accept moved after the drop was accepted as canonical")
	}
	if _, err := ParseACLAllowed(validCandidate(), []byte("flush ruleset\n")); err == nil {
		t.Fatal("unrelated script was accepted as a MeshMux ACL")
	}
}
