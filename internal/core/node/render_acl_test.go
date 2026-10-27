package node

import (
	"bytes"
	"strings"
	"testing"
)

// TestCompileACLIsARetiredEmptyTable pins the retired guard: an Out still
// replaces inet meshmux_out in one nft -f transaction, but the replacement is
// intentionally rule-free. A stale accept or dport drop from an older release
// must not survive an apply, because the Out now admits every client that
// presents the link key regardless of source address.
func TestCompileACLIsARetiredEmptyTable(t *testing.T) {
	edge := validCandidate()
	edge.Role = RoleEdge
	acl, err := CompileACL(edge, nil)
	if err != nil {
		t.Fatalf("edge compile = %v", err)
	}
	if acl != nil {
		t.Fatalf("edge node rendered an Out table: %q", acl)
	}
	if acl, err = CompileACL(edge, []string{"203.0.113.7"}); err != nil || acl != nil {
		t.Fatalf("edge with retired allowlist = %q, %v; want nil, nil", acl, err)
	}

	out, err := CompileACL(validCandidate(), nil)
	if err != nil {
		t.Fatalf("out compile = %v", err)
	}
	for _, want := range []string{
		"table inet meshmux_out",
		"delete table inet meshmux_out",
		"type filter hook input priority -10; policy accept;",
		"source allowlist is retired",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("retired ACL missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ReplaceAll(string(out), "policy accept", ""), "accept") {
		t.Fatalf("retired ACL rendered an accept rule:\n%s", out)
	}
	for _, forbidden := range []string{"drop", "saddr", "dport"} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("retired ACL still filters with %q:\n%s", forbidden, out)
		}
	}

	// The retired allowlist argument is ignored: both renders are identical.
	withSources, err := CompileACL(validCandidate(), []string{"203.0.113.7", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("compile with retired sources = %v", err)
	}
	if !bytes.Equal(out, withSources) {
		t.Fatalf("retired sources changed the render:\n%s\n---\n%s", out, withSources)
	}
}

// TestParseACLAllowedOnlyAcceptsTheRetiredTable keeps install --repair honest:
// a legacy allowlist file is not a canonical render any more, so it is never
// preserved as authorization; the neutral table is.
func TestParseACLAllowedOnlyAcceptsTheRetiredTable(t *testing.T) {
	rendered, err := CompileACL(validCandidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseACLAllowed(validCandidate(), rendered)
	if err != nil || len(parsed) != 0 {
		t.Fatalf("neutral render parse = %v, %v; want empty, nil", parsed, err)
	}

	legacy := []byte("table inet meshmux_out {\n  chain input {\n" +
		"    type filter hook input priority -10; policy accept;\n" +
		"    tcp dport 8443 drop\n    udp dport 8443 drop\n  }\n}\n")
	if _, err := ParseACLAllowed(validCandidate(), legacy); err == nil {
		t.Fatal("a legacy default-deny guard was accepted as canonical")
	}
	if _, err := ParseACLAllowed(validCandidate(), []byte("flush ruleset\n")); err == nil {
		t.Fatal("an arbitrary script was accepted as canonical")
	}
}
