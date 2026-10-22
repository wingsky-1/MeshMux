package route

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testRulesetPayload is the bytes a fake fetch returns. It never leaves the
// test: the route package treats a ruleset as opaque bytes and only proves the
// pinned digest.
var testRulesetPayload = []byte(`{"version":1,"rules":[{"domain_suffix":["example.invalid"]}]}`)

func testPin() RulesetPin {
	sum := sha256.Sum256(testRulesetPayload)
	return RulesetPin{
		Source:  "https://rulesets.example.invalid/ai/2026.10.21.srs",
		Version: "2026.10.21",
		SHA256:  hex.EncodeToString(sum[:]),
	}
}

// fakeResolver builds a resolver that records how often it was called, so a
// test can prove a path never touches the ruleset.
func fakeResolver(t *testing.T, payload []byte, err error) (RulesetFetcher, *int) {
	t.Helper()
	calls := 0
	return func(context.Context, string) ([]byte, error) {
		calls++
		if err != nil {
			return nil, err
		}
		return payload, nil
	}, &calls
}

// blockedCode returns the stable code of a refusal, or "" when err is nil or
// not a refusal.
func blockedCode(err error) string {
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		return blocked.Code
	}
	return ""
}

func blockedDetail(err error) string {
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		return blocked.Detail
	}
	return ""
}

// TestAIRuleset_FailClosedOnOutOffline is the brief case: an unavailable Out
// never falls back to the Line on its own, a ruleset that cannot be resolved
// refuses the publication, and only an explicit opt-in with an operation id may
// send AI traffic down the direct Line.
func TestAIRuleset_FailClosedOnOutOffline(t *testing.T) {
	resolve, calls := fakeResolver(t, testRulesetPayload, nil)
	base := AIEgressRequest{
		LineID:        strings.Repeat("a", 32),
		OutID:         strings.Repeat("b", 32),
		OutConfigured: true,
		Pin:           testPin(),
	}
	pin := testPin()

	// A configured Out that is offline blocks AI traffic by default: it must
	// not silently use the Line, because that is exactly the leak the fail-closed
	// rule exists to prevent.
	req := base
	req.OutCode = "OUT_OFFLINE"
	decision, err := resolveAIEgress(context.Background(), resolve, req)
	if decision.Mode != "" || blockedCode(err) != CodeOutOfflineFailClosed || blockedDetail(err) != "OUT_OFFLINE" {
		t.Fatalf("offline decision = %+v err=%v, want a blocked OUT_OFFLINE_FAIL_CLOSED/OUT_OFFLINE", decision, err)
	}
	if *calls != 0 {
		t.Fatalf("offline path resolved the ruleset %d times, want 0", *calls)
	}

	// A ruleset that cannot be resolved refuses publication even when the Out
	// is healthy: publishing a config that names an unverifiable ruleset would
	// hand the client a document that cannot match AI domains.
	failing, failedCalls := fakeResolver(t, nil, errors.New(CodeRulesetFetchFailed+": download failed"))
	req = base
	req.OutAvailable = true
	decision, err = resolveAIEgress(context.Background(), failing, req)
	if decision.Mode != "" || blockedCode(err) != CodeOutOfflineFailClosed || blockedDetail(err) != CodeRulesetFetchFailed {
		t.Fatalf("ruleset failure decision = %+v err=%v, want blocked/OUT_OFFLINE_FAIL_CLOSED with RULESET_FETCH_FAILED", decision, err)
	}
	if *failedCalls != 1 {
		t.Fatalf("ruleset failure resolved %d times, want 1", *failedCalls)
	}

	// The explicit opt-in is the only way back to the Line, and it is only
	// auditable together with the administrator operation id.
	req = base
	req.OutCode = "OUT_OFFLINE"
	req.FallbackToLine = true
	if _, err = resolveAIEgress(context.Background(), resolve, req); err == nil ||
		!strings.HasPrefix(err.Error(), CodeOutFallbackUnaudited) {
		t.Fatalf("unaudited fallback error = %v, want %s", err, CodeOutFallbackUnaudited)
	}

	req.OperationID = "abcdefghijklmnopqrstuv"
	decision, err = resolveAIEgress(context.Background(), resolve, req)
	if err != nil {
		t.Fatalf("explicit fallback error = %v", err)
	}
	if decision.Mode != AIEgressLineFallback || decision.Code != CodeOutOfflineFailClosed ||
		decision.Detail != "OUT_OFFLINE" || decision.OperationID != req.OperationID || decision.Payload != nil {
		t.Fatalf("explicit fallback decision = %+v, want an audited line fallback", decision)
	}

	// A healthy Out publishes the verified ruleset and records its pin.
	resolve, calls = fakeResolver(t, testRulesetPayload, nil)
	req = base
	req.OutAvailable = true
	decision, err = resolveAIEgress(context.Background(), resolve, req)
	if err != nil {
		t.Fatalf("healthy out error = %v", err)
	}
	if decision.Mode != AIEgressOut || decision.Payload == nil || string(decision.Payload) != string(testRulesetPayload) ||
		decision.Ruleset != pin || decision.OperationID != "" {
		t.Fatalf("healthy out decision = %+v, want out with the pinned payload", decision)
	}
	if *calls != 1 {
		t.Fatalf("healthy path resolved %d times, want 1", *calls)
	}

	// The ruleset failure cannot be hidden behind the fallback flag: with the
	// Out unavailable the fallback is allowed, but it is still reported as an
	// explicit fallback, never as a healthy Out.
	req = base
	req.OutAvailable = true
	req.FallbackToLine = true
	req.OperationID = "abcdefghijklmnopqrstuv"
	decision, err = resolveAIEgress(context.Background(), failing, req)
	if err != nil || decision.Mode != AIEgressLineFallback || decision.Detail != CodeRulesetFetchFailed {
		t.Fatalf("ruleset failure fallback = %+v err=%v, want an audited line fallback", decision, err)
	}
}

// TestAIRuleset_NoOutIsNotAFailure separates "no Out configured" from "the Out
// is broken": an Out-free deployment egresses directly, which is its configured
// state, not a silent fallback.
func TestAIRuleset_NoOutIsNotAFailure(t *testing.T) {
	resolve, calls := fakeResolver(t, testRulesetPayload, nil)
	decision, err := resolveAIEgress(context.Background(), resolve, AIEgressRequest{
		LineID: strings.Repeat("a", 32),
		Pin:    testPin(),
	})
	if err != nil {
		t.Fatalf("out-free decision error = %v", err)
	}
	if decision.Mode != AIEgressLine || decision.Code != "" || decision.Detail != "" || decision.OperationID != "" {
		t.Fatalf("out-free decision = %+v, want a plain line egress", decision)
	}
	if *calls != 0 {
		t.Fatalf("out-free path resolved the ruleset %d times, want 0", *calls)
	}
}

// TestAIRuleset_PinIsVersionLocked rejects every mutable or malformed pin, so a
// publication can never depend on an unintended artifact.
func TestAIRuleset_PinIsVersionLocked(t *testing.T) {
	good := testPin()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	cases := []struct {
		name string
		pin  RulesetPin
	}{
		{"http source", RulesetPin{Source: "http://rulesets.example.invalid/a.srs", Version: "1", SHA256: good.SHA256}},
		{"no host", RulesetPin{Source: "https:///a.srs", Version: "1", SHA256: good.SHA256}},
		{"userinfo", RulesetPin{Source: "https://user:secret@rulesets.example.invalid/a.srs", Version: "1", SHA256: good.SHA256}},
		{"query", RulesetPin{Source: "https://rulesets.example.invalid/a.srs?x=1", Version: "1", SHA256: good.SHA256}},
		{"fragment", RulesetPin{Source: "https://rulesets.example.invalid/a.srs#x", Version: "1", SHA256: good.SHA256}},
		{"latest channel", RulesetPin{Source: "https://rulesets.example.invalid/latest/a.srs", Version: "1", SHA256: good.SHA256}},
		{"master channel", RulesetPin{Source: "https://rulesets.example.invalid/master/a.srs", Version: "1", SHA256: good.SHA256}},
		{"main channel", RulesetPin{Source: "https://rulesets.example.invalid/main/a.srs", Version: "1", SHA256: good.SHA256}},
		{"loopback literal", RulesetPin{Source: "https://127.0.0.1/a.srs", Version: "1", SHA256: good.SHA256}},
		{"private literal", RulesetPin{Source: "https://10.0.0.1/a.srs", Version: "1", SHA256: good.SHA256}},
		{"localhost name", RulesetPin{Source: "https://localhost/a.srs", Version: "1", SHA256: good.SHA256}},
		{"v4 in v6 literal", RulesetPin{Source: "https://[::ffff:10.0.0.1]/a.srs", Version: "1", SHA256: good.SHA256}},
		{"empty version", RulesetPin{Source: good.Source, Version: "", SHA256: good.SHA256}},
		{"mutable version", RulesetPin{Source: good.Source, Version: "latest", SHA256: good.SHA256}},
		{"version with space", RulesetPin{Source: good.Source, Version: "2026 10", SHA256: good.SHA256}},
		{"short digest", RulesetPin{Source: good.Source, Version: "1", SHA256: strings.Repeat("a", 63)}},
		{"uppercase digest", RulesetPin{Source: good.Source, Version: "1", SHA256: strings.ToUpper(good.SHA256)}},
		{"non hex digest", RulesetPin{Source: good.Source, Version: "1", SHA256: strings.Repeat("z", 64)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.pin.Validate()
			if err == nil || !strings.HasPrefix(err.Error(), CodeRulesetPinInvalid) {
				t.Fatalf("Validate() = %v, want %s", err, CodeRulesetPinInvalid)
			}
		})
	}
}

// TestAIRuleset_ResolveVerifiesBytes proves the resolver trusts only bytes that
// match the pinned digest, and that no failure leaks the source URL.
func TestAIRuleset_ResolveVerifiesBytes(t *testing.T) {
	pin := testPin()
	fetch := func(context.Context, string) ([]byte, error) { return testRulesetPayload, nil }
	payload, err := resolveAIRuleset(context.Background(), fetch, pin, 1<<20)
	if err != nil || string(payload) != string(testRulesetPayload) {
		t.Fatalf("resolve = %q err=%v, want the pinned payload", payload, err)
	}

	// A tampered artifact is refused, not truncated or trusted.
	tampered := pin
	tampered.SHA256 = strings.Repeat("a", 64)
	if _, err = resolveAIRuleset(context.Background(), fetch, tampered, 1<<20); err == nil ||
		!strings.HasPrefix(err.Error(), CodeRulesetFetchFailed) {
		t.Fatalf("tampered resolve error = %v, want %s", err, CodeRulesetFetchFailed)
	}
	if strings.Contains(err.Error(), pin.Source) {
		t.Fatal("resolution error leaked the pinned source")
	}

	for name, body := range map[string][]byte{"empty": {}, "oversized": make([]byte, 17)} {
		body := body
		t.Run(name, func(t *testing.T) {
			_, err := resolveAIRuleset(context.Background(), func(context.Context, string) ([]byte, error) {
				return body, nil
			}, pin, 16)
			if err == nil || !strings.HasPrefix(err.Error(), CodeRulesetFetchFailed) {
				t.Fatalf("resolve(%s) error = %v, want %s", name, err, CodeRulesetFetchFailed)
			}
		})
	}

	// A fetch failure is one stable code and never carries the URL or the
	// transport error text.
	transport := errors.New("dial tcp 203.0.113.9:443: connection refused")
	_, err = resolveAIRuleset(context.Background(), func(context.Context, string) ([]byte, error) {
		return nil, transport
	}, pin, 1<<20)
	if err == nil || !strings.HasPrefix(err.Error(), CodeRulesetFetchFailed) {
		t.Fatalf("transport error = %v, want %s", err, CodeRulesetFetchFailed)
	}
	if strings.Contains(err.Error(), "203.0.113.9") || strings.Contains(err.Error(), pin.Source) {
		t.Fatal("resolution error leaked the transport detail or source")
	}

	// An invalid pin is a configuration defect and never reaches the network.
	calls := 0
	bad := pin
	bad.Source = "http://rulesets.example.invalid/a.srs"
	_, err = resolveAIRuleset(context.Background(), func(context.Context, string) ([]byte, error) {
		calls++
		return testRulesetPayload, nil
	}, bad, 1<<20)
	if err == nil || !strings.HasPrefix(err.Error(), CodeRulesetPinInvalid) || calls != 0 {
		t.Fatalf("invalid pin error = %v calls=%d, want %s without a fetch", err, calls, CodeRulesetPinInvalid)
	}
}

// TestAIRuleset_HTTPSFetcherIsBounded exercises the production fetcher against
// a local test server: only a 200 with a bounded body is accepted, and
// redirects are never followed because the pin names one exact artifact.
func TestAIRuleset_HTTPSFetcherIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write(testRulesetPayload)
		case "/missing":
			http.NotFound(w, r)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/oversized":
			w.Header().Set("Content-Length", "1024")
			_, _ = w.Write(make([]byte, 1024))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	body, err := fetchPinnedRuleset(context.Background(), server.URL+"/ok", 1<<20)
	if err != nil || string(body) != string(testRulesetPayload) {
		t.Fatalf("fetch ok = %q err=%v", body, err)
	}
	for _, path := range []string{"/missing", "/redirect"} {
		if _, err := fetchPinnedRuleset(context.Background(), server.URL+path, 1<<20); err == nil {
			t.Fatalf("fetch %s succeeded, want a failure", path)
		}
	}
	if _, err := fetchPinnedRuleset(context.Background(), server.URL+"/oversized", 16); err == nil {
		t.Fatal("oversized fetch succeeded, want a failure")
	}
}
