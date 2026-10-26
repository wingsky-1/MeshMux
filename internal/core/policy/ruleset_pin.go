package policy

// The ruleset version lock and the retained AI ruleset byte verification.
//
// Issue #8 originally resolved one AI egress decision here. The rule library
// (internal/policy + the subscription composer, ADR-0008) now owns that
// decision, so the decision types and functions were removed in Task 6. What
// remains is the version lock itself, which is still the only contract for a
// pinned artifact:
//
//   - A ruleset is only usable when it is pinned (HTTPS source, immutable
//     version, SHA-256) and its bytes match the pin. A pin that is mutable or
//     malformed is a configuration defect (RULESET_PIN_INVALID); a download,
//     digest or size failure is RULESET_FETCH_FAILED. Both refuse publication
//     instead of shipping a client document that names an unverifiable file.
//   - ResolveAIRuleset is deliberately kept although the current publication
//     path does not call it: pins are the future way to consume a ruleset, and
//     the byte check is the security half of that contract (Task 6 Keep list).
//
// This file still does not render client documents, read subscription tokens,
// install or upgrade nodes, run a ruleset marketplace, latency probes or
// multi-Out load balancing.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// The stable codes this file reports. They are part of the diagnostic
// contract: a caller logs the code and the operation id, never the source URL,
// the response body or the transport error.
const (
	// CodeRulesetFetchFailed: the pinned artifact could not be downloaded,
	// was empty, exceeded the size bound or did not match its digest.
	CodeRulesetFetchFailed = "RULESET_FETCH_FAILED"
	// CodeRulesetPinInvalid: the pin itself is mutable or malformed, so no
	// download is attempted.
	CodeRulesetPinInvalid = "RULESET_PIN_INVALID"
	// CodeOutOfflineFailClosed: a configured Out cannot carry the AI traffic
	// and the request did not opt in to the Line fallback.
	CodeOutOfflineFailClosed = "OUT_OFFLINE_FAIL_CLOSED"
	// CodeOutFallbackUnaudited: the caller asked for the Line fallback without
	// a request operation id, so the deviation could not be audited.
	CodeOutFallbackUnaudited = "OUT_FALLBACK_UNAUDITED"
)

// AI egress modes of one decision.
const (
	// AIEgressOut: the AI traffic egresses through the authorized Out and the
	// pinned ruleset was verified.
	AIEgressOut = protocol.OutboundOutTag
	// AIEgressLine: no Out is configured, so the Line is the configured egress.
	AIEgressLine = "line"
	// AIEgressLineFallback: an administrator explicitly chose the Line because
	// the configured Out cannot carry the traffic.
	AIEgressLineFallback = "line-fallback"
)

// RulesetPin is the version lock of one AI ruleset artifact. Source must be an
// exact public HTTPS URL, Version an immutable label and SHA256 the lowercase
// hex digest of the bytes the renderer will embed. The shape and the shared
// predicates live in the subscription IR; this layer maps a refusal to the
// policy error code.
type RulesetPin struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Validate rejects every pin whose artifact is not a single immutable object.
// It never performs I/O, so a configuration defect is reported before any
// network access.
func (p RulesetPin) Validate() error {
	if detail := ir.PinDetail(p.Source, p.Version, p.SHA256); detail != "" {
		return errors.New(CodeRulesetPinInvalid + ": " + detail)
	}
	return nil
}

// RulesetFetcher downloads exactly the artifact a pin names. It is a seam so a
// test can prove the decision path without a network.
type RulesetFetcher func(ctx context.Context, source string) ([]byte, error)

// rulesetHTTPClient never follows a redirect: the pin names one artifact, and a
// redirect would let the served bytes decide where they came from. The timeout
// stays below the Web server's write timeout, so a slow artifact is reported as
// RULESET_FETCH_FAILED instead of a cut response.
var rulesetHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchPinnedRuleset is the production fetcher. The source is already an exact
// HTTPS URL validated by RulesetPin.Validate; the body is read through a
// bounded reader so a wrong or hostile response cannot exhaust the Hub.
func fetchPinnedRuleset(ctx context.Context, source string, limit int64) ([]byte, error) {
	failed := func() error {
		return errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset could not be downloaded")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, failed()
	}
	response, err := rulesetHTTPClient.Do(request)
	if err != nil {
		return nil, failed()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, failed()
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, failed()
	}
	if int64(len(body)) > limit {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset exceeds the size bound")
	}
	return body, nil
}

// productionRulesetFetcher is the bounded HTTPS fetch used by the retained
// byte-verification entry point.
func productionRulesetFetcher(ctx context.Context, source string) ([]byte, error) {
	return fetchPinnedRuleset(ctx, source, MaxRulesetBytes)
}

// ResolveAIRuleset downloads the pinned artifact and returns its bytes only
// after they match the pinned digest. It is the retained half of the former
// AI-egress decision path: the rule library owns egress selection now, while
// pins stay a version-locked byte contract for a future ruleset consumer.
// The function is deliberately not called by the current publication path;
// keeping it is the documented Task 6 exception (pins 未来用).
//
// Every failure is RULESET_FETCH_FAILED (an invalid pin is
// RULESET_PIN_INVALID) and carries no URL, body or transport text, so a log
// line stays safe. The caller refuses publication on any error.
func ResolveAIRuleset(pin RulesetPin) ([]byte, error) {
	return resolveAIRuleset(context.Background(), productionRulesetFetcher, pin, MaxRulesetBytes)
}

// resolveAIRuleset is the testable form of ResolveAIRuleset.
func resolveAIRuleset(ctx context.Context, fetch RulesetFetcher, pin RulesetPin, maxBytes int64) ([]byte, error) {
	if err := pin.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := fetch(ctx, pin.Source)
	if err != nil {
		// The fetcher's own error may quote the URL or the transport. Only the
		// stable code leaves this function.
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset could not be downloaded")
	}
	if len(payload) == 0 {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset is empty")
	}
	if maxBytes > 0 && int64(len(payload)) > maxBytes {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset exceeds the size bound")
	}
	sum := sha256.Sum256(payload)
	expected, decodeErr := hex.DecodeString(pin.SHA256)
	if decodeErr != nil || subtle.ConstantTimeCompare(sum[:], expected) != 1 {
		return nil, errors.New(CodeRulesetFetchFailed + ": the pinned AI ruleset does not match its digest")
	}
	return payload, nil
}

// BlockedError is a refused decision. Code is the stable refusal code and
// Detail the stable underlying reason, so the caller can report both without
// inventing prose.
type BlockedError struct {
	Code   string
	Detail string
}

func (e *BlockedError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}
