package subscription

// Ruling R11: the subscription egress slot is one choice — an Out node or an
// external HTTP proxy — and the MAX_OUTS semantics stay exactly the same. The
// composer only needs the operator-visible endpoint and the kind: the HTTP
// credentials stay in the Line candidate's private egress, never in a client
// document.

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
	if len(documents.LineRoutes) != 1 {
		t.Fatalf("line routes = %d, want the http egress to select the out tag", len(documents.LineRoutes))
	}
	if !strings.Contains(string(documents.LineRoutes[0].Fragment), `"outbound": "out"`) {
		t.Fatal("http egress did not render the outbound tag")
	}
	// The kind is part of the selection identity: the same endpoint identity
	// with a different egress kind must produce a different selection id, so a
	// stored snapshot can never be re-read as another kind of egress.
	outNode := []ComposeOut{{
		OutID: "44444444444444444444444444444444", DisplayName: "Out",
		Server: "proxy.example.invalid", Port: 8080,
	}}
	other, otherDiagnostics := ComposeSubscription(lines, outNode, composeRules(), nil)
	if anyBlocking(otherDiagnostics) {
		t.Fatalf("out egress blocked: %+v", otherDiagnostics)
	}
	if documents.SelectionID == other.SelectionID {
		t.Fatal("selection id does not distinguish the egress kind")
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
