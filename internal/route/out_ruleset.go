package route

// AI egress selection and the ruleset version lock.
//
// Issue #8 keeps one Out optional and one Line direct. The rule this file
// encodes is deliberately narrow and is the server-side contract every future
// renderer and publish path must obey:
//
//   - "no Out configured" is a configured state, not a failure: the AI domains
//     use the Line directly, exactly like every other destination.
//   - "the Out is configured but unavailable" must never silently use the Line.
//     The client would believe it is on a double hop while its AI traffic
//     leaves from the Line address, which is the leak the fail-closed rule
//     exists to prevent. The decision is refused with
//     OUT_OFFLINE_FAIL_CLOSED and the caller reports it instead of publishing.
//   - Falling back to the Line is an administrator decision, never a runtime
//     guess. It needs the explicit opt-in *and* the request operation id, so
//     the deviation is traceable in the audit log; a fallback without one is
//     refused rather than recorded anonymously.
//   - A ruleset is only usable when it is pinned (HTTPS source, immutable
//     version, SHA-256) and its bytes match the pin. A pin that is mutable or
//     malformed is a configuration defect (RULESET_PIN_INVALID); a download,
//     digest or size failure is RULESET_FETCH_FAILED. Both refuse publication
//     instead of shipping a client document that names an unverifiable file.
//
// This package still does not render client documents, read subscription
// tokens, install or upgrade nodes, run a ruleset marketplace, latency probes or
// multi-Out load balancing. It returns a decision and the verified bytes; the
// renderer that consumes them is out of #8's scope.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The stable codes this package reports. They are part of the diagnostic
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
	AIEgressOut = "out"
	// AIEgressLine: no Out is configured, so the Line is the configured egress.
	AIEgressLine = "line"
	// AIEgressLineFallback: an administrator explicitly chose the Line because
	// the configured Out cannot carry the traffic.
	AIEgressLineFallback = "line-fallback"
)

// maxRulesetBytes bounds one downloaded artifact. The Out guard and the client
// document both stay small; an unbounded body would be a memory lever on the
// Hub.
const maxRulesetBytes = 8 << 20

// rulesetVersionPattern accepts one immutable version label. A path-style
// channel such as "latest" is rejected by the denylist below even though it
// matches the character set.
var rulesetVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$`)

// mutableRulesetVersions are the labels that mean "whatever is newest", which
// is exactly what a version lock may not accept.
var mutableRulesetVersions = map[string]bool{
	"latest":  true,
	"head":    true,
	"main":    true,
	"master":  true,
	"stable":  true,
	"dev":     true,
	"nightly": true,
}

// stableCodePattern is the shape of every value that reaches a log field or an
// operator-facing detail.
var stableCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// RulesetPin is the version lock of one AI ruleset artifact. Source must be an
// exact public HTTPS URL, Version an immutable label and SHA256 the lowercase
// hex digest of the bytes the renderer will embed.
type RulesetPin struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Validate rejects every pin whose artifact is not a single immutable object.
// It never performs I/O, so a configuration defect is reported before any
// network access.
func (p RulesetPin) Validate() error {
	invalid := func(reason string) error {
		return errors.New(CodeRulesetPinInvalid + ": " + reason)
	}
	if p.Source == "" || len(p.Source) > 512 || strings.TrimSpace(p.Source) != p.Source {
		return invalid("the source must be one exact URL")
	}
	parsed, err := url.Parse(p.Source)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || strings.ContainsAny(p.Source, " \t\r\n") {
		return invalid("the source must be one exact public HTTPS URL without credentials, query or fragment")
	}
	// A literal network address is not a public ruleset host. This is not a
	// full SSRF defence (the Hub never accepts the URL from a request), it
	// keeps the deployment from pinning a loopback or private artifact by
	// mistake, which would make the "public, reproducible" claim false.
	if addr, addrErr := netip.ParseAddr(parsed.Hostname()); addrErr == nil {
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
			return invalid("the source must not be a loopback, private or unspecified literal address")
		}
	}
	if host := parsed.Hostname(); host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return invalid("the source must be a public ruleset host")
	}
	if !rulesetVersionPattern.MatchString(p.Version) || mutableRulesetVersions[strings.ToLower(p.Version)] {
		return invalid("the version must be one immutable label, not a mutable channel")
	}
	// A path that names a mutable channel is the same defect spelled in the
	// URL: the file behind it changes without the pin changing.
	for _, segment := range strings.Split(parsed.Path, "/") {
		if mutableRulesetVersions[strings.ToLower(segment)] {
			return invalid("the source must name one immutable artifact, not a mutable channel")
		}
	}
	if !artifactDigestPattern.MatchString(p.SHA256) {
		return invalid("the digest must be 64 lowercase hex characters")
	}
	return nil
}

// artifactDigestPattern is the one accepted digest spelling.
var artifactDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

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

// ResolveAIRuleset downloads the pinned artifact and returns its bytes only
// after they match the pinned digest.
//
// Every failure is RULESET_FETCH_FAILED (an invalid pin is
// RULESET_PIN_INVALID) and carries no URL, body or transport text, so a log
// line stays safe. The caller refuses publication on any error.
func ResolveAIRuleset(pin RulesetPin) ([]byte, error) {
	return resolveAIRuleset(context.Background(), productionRulesetFetcher, pin, maxRulesetBytes)
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

// AIEgressRequest is one AI egress decision input. The caller derives the Out
// facts from the binding and the Out synchronization projection:
//
//	OutConfigured: an enabled binding exists for the Line.
//	OutAvailable:  the Out is reachable and its authorization is confirmed.
//	OutCode:       the stable reason when OutAvailable is false.
//
// FallbackToLine is the administrator's explicit opt-in and OperationID is the
// request operation that records it.
type AIEgressRequest struct {
	LineID         string
	OutID          string
	OutConfigured  bool
	OutAvailable   bool
	OutCode        string
	Pin            RulesetPin
	FallbackToLine bool
	OperationID    string
}

// AIEgressDecision is one resolved AI egress. Payload carries the verified
// ruleset bytes only in AIEgressOut; a fallback never carries a ruleset,
// because the Line does not render one.
type AIEgressDecision struct {
	Mode        string
	Code        string
	Detail      string
	OperationID string
	Ruleset     RulesetPin
	Payload     []byte
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

// resolveAIEgress resolves one AI egress decision.
//
// The order of the checks is the security property: an unavailable Out is never
// turned into a Line egress unless the caller opted in with an auditable
// operation id, and a ruleset is only fetched when the Out path is supposed to
// carry the traffic.
func resolveAIEgress(ctx context.Context, fetch RulesetFetcher, req AIEgressRequest) (AIEgressDecision, error) {
	if err := subscription.ValidateID(req.LineID); err != nil {
		return AIEgressDecision{}, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	if !req.OutConfigured {
		// No Out is a configured direct egress, not a degradation.
		return AIEgressDecision{Mode: AIEgressLine}, nil
	}
	if err := subscription.ValidateID(req.OutID); err != nil {
		return AIEgressDecision{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	detail := stableCode(req.OutCode, "OUT_OFFLINE")

	// When the Out path is supposed to work, the ruleset must resolve. Its
	// failure is as fatal as the Out being unavailable: a client document that
	// names an unverified ruleset cannot match AI domains.
	failure := ""
	var payload []byte
	var pin RulesetPin
	if req.OutAvailable {
		resolved, err := resolveAIRuleset(ctx, fetch, req.Pin, maxRulesetBytes)
		if err != nil {
			if !isRulesetCode(err) {
				return AIEgressDecision{}, err
			}
			failure = stableCode(err.Error(), CodeRulesetFetchFailed)
		} else {
			payload, pin = resolved, req.Pin
		}
	} else {
		failure = detail
	}
	if failure == "" {
		return AIEgressDecision{
			Mode:    AIEgressOut,
			Ruleset: pin,
			Payload: payload,
		}, nil
	}
	if !req.FallbackToLine {
		return AIEgressDecision{}, &BlockedError{Code: CodeOutOfflineFailClosed, Detail: failure}
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return AIEgressDecision{}, errors.New(CodeOutFallbackUnaudited + ": the explicit line fallback needs an operation id so the deviation can be audited")
	}
	return AIEgressDecision{
		Mode:        AIEgressLineFallback,
		Code:        CodeOutOfflineFailClosed,
		Detail:      failure,
		OperationID: req.OperationID,
	}, nil
}

// isRulesetCode reports whether an error is one of this package's stable
// ruleset codes rather than a caller programming error.
func isRulesetCode(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, CodeRulesetFetchFailed) || strings.HasPrefix(message, CodeRulesetPinInvalid)
}

// stableCode keeps only a value that already looks like a stable code, so a
// free-form error can never become a log field or an operator detail.
func stableCode(raw, fallback string) string {
	value := strings.TrimSpace(raw)
	if index := strings.Index(value, ":"); index > 0 {
		value = strings.TrimSpace(value[:index])
	}
	if !stableCodePattern.MatchString(value) {
		return fallback
	}
	return value
}

// DecideAIEgress is the exported entry point for the server-side selection.
// It downloads the pinned ruleset with the production fetcher and returns the
// decision, a *BlockedError for a fail-closed refusal, or a plain error for an
// invalid request (LINE_ID_INVALID / OUT_BINDING_INVALID).
func DecideAIEgress(ctx context.Context, req AIEgressRequest) (AIEgressDecision, error) {
	return decideAIEgressWithFetcher(ctx, productionRulesetFetcher, req)
}

// DecideAIEgressWithFetcher is the same decision with an injectable artifact
// source. A nil fetcher selects the production HTTPS fetcher; the seam exists so
// a caller (or a test) can resolve the pin from an already verified artifact
// without reaching the network.
func DecideAIEgressWithFetcher(ctx context.Context, fetch RulesetFetcher, req AIEgressRequest) (AIEgressDecision, error) {
	if fetch == nil {
		fetch = productionRulesetFetcher
	}
	return decideAIEgressWithFetcher(ctx, fetch, req)
}

// productionRulesetFetcher is the bounded HTTPS fetch used by the Hub.
func productionRulesetFetcher(ctx context.Context, source string) ([]byte, error) {
	return fetchPinnedRuleset(ctx, source, maxRulesetBytes)
}

// decideAIEgressWithFetcher is the single decision implementation.
func decideAIEgressWithFetcher(ctx context.Context, fetch RulesetFetcher, req AIEgressRequest) (AIEgressDecision, error) {
	return resolveAIEgress(ctx, fetch, req)
}
