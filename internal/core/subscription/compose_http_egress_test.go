package subscription

// Ruling R11: the subscription egress slot is one choice — an Out node or an
// external HTTP proxy — and the MAX_OUTS semantics stay exactly the same.
// Under client-chain egress both shapes are rendered into the client documents,
// so the subscriber's client dials the egress itself; the Line publishes no
// route any more.

import (
	"strings"
	"testing"
)

func TestComposeSubscriptionAcceptsHTTPProxyEgress(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	httpEgress := []ComposeOut{{
		OutID: "44444444444444444444444444444444", DisplayName: "办公室代理",
		Server: "proxy.example.invalid", Port: 8080, Kind: ComposeOutHTTP,
	}}
	documents, diagnostics := ComposeSubscription(lines, httpEgress, composeRules(), nil)
	if anyBlocking(diagnostics) {
		t.Fatalf("http egress blocked the artifact: %+v", diagnostics)
	}
	// The http proxy is one client outbound named by the proxy rules.
	for _, required := range []string{`"type": "http"`, `"tag": "out"`, `"server": "proxy.example.invalid"`, `"server_port": 8080`, `"outbound": "out"`} {
		if !strings.Contains(string(documents.SingBox), required) {
			t.Fatalf("sing-box document misses %q:\n%s", required, documents.SingBox)
		}
	}
	if !strings.Contains(string(documents.Mihomo), `type: "http"`) || !strings.Contains(string(documents.Mihomo), `- "RULE-SET,ai@20261026,out"`) {
		t.Fatalf("mihomo document does not render the http egress:\n%s", documents.Mihomo)
	}
	// The kind is part of the selection identity: the same endpoint identity
	// with a different egress kind must produce a different selection id, so a
	// stored snapshot can never be re-read as another kind of egress.
	outNode := []ComposeOut{{
		OutID: "44444444444444444444444444444444", DisplayName: "Out",
		Server: "proxy.example.invalid", Port: 8080, LinkKey: goldenLinkKey,
	}}
	other, otherDiagnostics := ComposeSubscription(lines, outNode, composeRules(), nil)
	if anyBlocking(otherDiagnostics) {
		t.Fatalf("out egress blocked: %+v", otherDiagnostics)
	}
	if documents.SelectionID == other.SelectionID {
		t.Fatal("selection id does not distinguish the egress kind")
	}
}

func TestComposeSubscriptionRendersHTTPProxyCredentials(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	outs := []ComposeOut{{
		OutID: "44444444444444444444444444444444", DisplayName: "办公室代理",
		Server: "proxy.example.invalid", Port: 8080, Kind: ComposeOutHTTP,
		Username: "operator", Password: "s3cret",
	}}
	documents, diagnostics := ComposeSubscription(lines, outs, composeRules(), nil)
	if anyBlocking(diagnostics) {
		t.Fatalf("credentialed http egress blocked: %+v", diagnostics)
	}
	for _, required := range []string{`"username": "operator"`, `"password": "s3cret"`} {
		if !strings.Contains(string(documents.SingBox), required) {
			t.Fatalf("sing-box document misses %q:\n%s", required, documents.SingBox)
		}
	}
	for _, required := range []string{`username: "operator"`, `password: "s3cret"`} {
		if !strings.Contains(string(documents.Mihomo), required) {
			t.Fatalf("mihomo document misses %q:\n%s", required, documents.Mihomo)
		}
	}
}

// TestComposeSubscriptionRefusesMixedEgressCredential pins that the two egress
// shapes never mix credentials: an Out carries a link key, an HTTP proxy its
// Basic pair, and a value of the other shape is refused instead of silently
// dropped from the document.
func TestComposeSubscriptionRefusesMixedEgressCredential(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	cases := map[string]ComposeOut{
		"http with link key": {
			OutID: "44444444444444444444444444444444", Server: "proxy.example.invalid", Port: 8080,
			Kind: ComposeOutHTTP, LinkKey: goldenLinkKey,
		},
		"out with basic pair": {
			OutID: "44444444444444444444444444444444", Server: "out.example.invalid", Port: 443,
			LinkKey: goldenLinkKey, Username: "operator", Password: "s3cret",
		},
		"out without link key": {
			OutID: "44444444444444444444444444444444", Server: "out.example.invalid", Port: 443,
		},
		"out with a non-canonical link key": {
			OutID: "44444444444444444444444444444444", Server: "out.example.invalid", Port: 443,
			LinkKey: "AQIDBAUGBwgJCgsMDQ4PEA",
		},
		"http password without username": {
			OutID: "44444444444444444444444444444444", Server: "proxy.example.invalid", Port: 8080,
			Kind: ComposeOutHTTP, Password: "s3cret",
		},
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			documents, diagnostics := ComposeSubscription(lines, []ComposeOut{out}, composeRules(), nil)
			if len(documents.SingBox) != 0 || len(documents.Mihomo) != 0 {
				t.Fatal("a mixed egress credential produced a document")
			}
			if !hasBlockingCode(diagnostics, CodeComposeOutInvalid) {
				t.Fatalf("diagnostics = %+v, want %s", diagnostics, CodeComposeOutInvalid)
			}
		})
	}
}

func TestComposeSubscriptionRefusesUnknownEgressKind(t *testing.T) {
	lines := []ComposeLine{composeFixture(t, "11111111111111111111111111111111", "香港 01", 1)}
	outs := []ComposeOut{{
		OutID: "44444444444444444444444444444444", DisplayName: "x",
		Server: "proxy.example.invalid", Port: 8080, Kind: "socks5",
	}}
	if _, diagnostics := ComposeSubscription(lines, outs, composeRules(), nil); !hasBlockingCode(diagnostics, CodeComposeOutInvalid) {
		t.Fatalf("unknown egress kind was not refused: %+v", diagnostics)
	}
}

func hasBlockingCode(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Level == DiagnosticBlocking && diagnostic.Code == code {
			return true
		}
	}
	return false
}
