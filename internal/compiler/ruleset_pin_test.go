package compiler

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
// test: the compiler package treats a ruleset as opaque bytes and only proves
// the pinned digest.
var testRulesetPayload = []byte(`{"version":1,"rules":[{"domain_suffix":["example.invalid"]}]}`)

func testPin() RulesetPin {
	sum := sha256.Sum256(testRulesetPayload)
	return RulesetPin{
		Source:  "https://rulesets.example.invalid/ai/2026.10.21.srs",
		Version: "2026.10.21",
		SHA256:  hex.EncodeToString(sum[:]),
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
