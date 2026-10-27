package policy

// Publication assembly.
//
// Under the client-chain model the Hub publishes proxy ports and credentials
// only: a Line candidate carries its listener and user set, and every routing
// rule lives in the client document a subscriber downloads. A publication
// therefore validates the active intent and gates the client preview documents;
// it never renders a server route and never writes a Line candidate.
//
//	active revision -> Validate -> RenderSingBox / RenderMihomo (preview)
//	-> kernel gate (sing-box check, mihomo -t) -> receipt
//
// The fields `RouteFragment` and `Targets` stay on PolicyAssembly for wire
// compatibility and are always empty: their producer (the server-route
// delivery chain) is retired.
//
// Nothing here executes a shell: both kernels are reached through the fixed
// verifier wrapper of common/publish_verifier.go, which runs one argv without a
// shell.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/control/store/clientdoc"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/policy"
)

// PolicySchemaVersion is the schema of the stored policy tables. Every
// publication receipt carries it together with route_policy_revisions, so an
// upgrade manifest (#11) can prove which policy revision it published.
const PolicySchemaVersion = 8

// Stable publication refusals that no lower layer owns.
const (
	// CodePublishNoLines: no Line carries stored transport, so a server
	// policy has no target.
	CodePublishNoLines = "PUBLISH_NO_LINES"
	// CodePublishNoPolicy: the requested layer has no active revision.
	CodePublishNoPolicy = "POLICY_NOT_FOUND"
)

// Aggregate AI egress states of one server publication. A publication targets
// every Line, so its receipt describes the whole fleet: the per-Line states of
// coredomain.AIEgressLine, coredomain.AIEgressOut and coredomain.AIEgressLineFallback stay as
// they are, and a fleet whose Lines disagree is reported as mixed instead of
// hiding every Line behind the first one.
const (
	// PolicyEgressFailClosed: the Line has a bound Out that cannot carry the
	// AI traffic and no explicit Line fallback was taken.
	PolicyEgressFailClosed = "fail-closed"
	// PolicyEgressMixed: the target Lines resolved to different egress states,
	// so no single state describes the publication.
	PolicyEgressMixed = "mixed"
)

// PublishTarget is retired with the server-route delivery chain. The type is
// kept so a receipt or a caller that still names the shape compiles; no
// publication produces one any more.
type PublishTarget struct {
	LineID     string
	Candidate  node.Candidate
	Config     []byte
	ConfigHash string
	Egress     string
	EgressCode string
}

// PolicyAssembly is the gated result of one publication attempt. It carries no
// secret: the rendered fragments, digests and stable codes only.
type PolicyAssembly struct {
	OperationID string
	Layer       string
	// EgressState is the aggregate of every target Line's AI egress
	// projection, not the first Line's: a fleet whose Lines disagree reads as
	// "mixed" instead of hiding one Line behind another. Each Line keeps its
	// own state in Targets.
	EgressState string
	EgressCode  string
	// RouteFragment is retired: the server never renders or delivers a route, so
	// the field is always nil.
	RouteFragment []byte
	// ClientDocument and MihomoDocument are the rendered preview documents of
	// the client layer. They are gated as evidence and never stored: the
	// client layer has no consumer in the standard subscription export.
	ClientDocument []byte
	MihomoDocument []byte
	// Targets is retired: a publication writes no Line candidate any more, so
	// the slice is always empty.
	Targets              []PublishTarget
	ClientRevision       int64
	ServerRevision       int64
	RoutePolicyRevisions map[string]int64
	PolicySchema         int
	Checks               []PolicyCheckEvidence
}

// PolicyPublishRequest is the strict body of POST /policies/publish.
type PolicyPublishRequest struct {
	Layer          string `json:"layer"`
	OperationID    string `json:"operation_id"`
	FallbackToLine bool   `json:"fallback_to_line"`
}

// PolicyPublishReceipt is the stable receipt. A publication reports ok only
// when every gate passed and every target candidate was stored.
type PolicyPublishReceipt struct {
	OK                   bool                     `json:"ok"`
	Status               string                   `json:"status"`
	Revision             int64                    `json:"revision,omitempty"`
	EgressState          string                   `json:"egress_state,omitempty"`
	EgressCode           string                   `json:"egress_code,omitempty"`
	PolicySchema         int                      `json:"policy_schema"`
	RoutePolicyRevisions map[string]int64         `json:"route_policy_revisions"`
	Checks               []PolicyCheckEvidence    `json:"checks"`
	Candidate            *PolicyCandidateEvidence `json:"candidate,omitempty"`
	Lines                []PolicyLineEvidence     `json:"lines,omitempty"`
	ErrorCode            string                   `json:"error_code,omitempty"`
	Detail               string                   `json:"detail,omitempty"`
	NextAction           string                   `json:"next_action,omitempty"`
	OperationID          string                   `json:"operation_id"`
}

// PolicyCheckEvidence is one kernel gate result. Detail is a short summary,
// never the checked document and never a full kernel transcript.
type PolicyCheckEvidence struct {
	Stage  string `json:"stage"`
	Kernel string `json:"kernel"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// PolicyCandidateEvidence references the immutable candidate the publication
// produced.
type PolicyCandidateEvidence struct {
	Revision int64  `json:"revision"`
	Lines    int    `json:"lines"`
	Config   string `json:"config_sha256"`
}

// PolicyLineEvidence is one Line's outcome in a publication.
type PolicyLineEvidence struct {
	LineID      string `json:"line_id"`
	Revision    int64  `json:"revision"`
	EgressState string `json:"egress_state"`
	EgressCode  string `json:"egress_code,omitempty"`
	Status      string `json:"status"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// ParsePolicyPublishRequest decodes and validates the publish body.
func ParsePolicyPublishRequest(raw json.RawMessage) (PolicyPublishRequest, error) {
	var request PolicyPublishRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return PolicyPublishRequest{}, errors.New(codePolicyPayloadInvalid + ": the publish body must be the documented JSON")
	}
	if strings.TrimSpace(string(raw)) == "" {
		return PolicyPublishRequest{}, errors.New(codePolicyPayloadInvalid + ": the publish body is empty")
	}
	request.Layer = strings.TrimSpace(request.Layer)
	request.OperationID = strings.TrimSpace(request.OperationID)
	if request.OperationID == "" || len(request.OperationID) > 128 {
		return PolicyPublishRequest{}, errors.New(codePolicyOperationRequired + ": publication needs a non-empty operation id")
	}
	switch request.Layer {
	case "", string(PolicyLayerClient), string(PolicyLayerServer):
	default:
		return PolicyPublishRequest{}, errors.New(codePolicyLayerInvalid + ": layer must be client, server or empty for both")
	}
	return request, nil
}

// assemblePolicyPublication reads the active revisions, validates and renders
// them, assembles every target Line candidate and runs the kernel gate. It
// writes nothing: the caller's transaction decides whether anything is stored.
//
// layer=client requires an active client revision, layer=server requires an
// active server revision, and an empty layer publishes every active layer and
// requires at least one.
func (s *Store) AssemblePolicyPublication(ctx context.Context, verifier common.PublishVerifier, request PolicyPublishRequest, now time.Time) (PolicyAssembly, error) {
	assembly := PolicyAssembly{
		OperationID:          request.OperationID,
		Layer:                request.Layer,
		PolicySchema:         PolicySchemaVersion,
		RoutePolicyRevisions: map[string]int64{},
	}
	// layer="" publishes the server layer plus any active client layer. The
	// Line candidate is the only publication artifact the Hub stores; the
	// client documents are rendered and gated as a preview because a client
	// layer without its kernel check would be a claim the Hub cannot prove.
	// They have no consumer: the standard subscription export is generated
	// from lines and credentials only.
	publishClient := request.Layer == "" || request.Layer == string(PolicyLayerClient)
	publishServer := request.Layer == "" || request.Layer == string(PolicyLayerServer)
	if request.Layer == "" {
		if _, _, err := s.ActivePolicyIntent(PolicyLayerClient); err != nil {
			if !IsNotFound(err) {
				return assembly, err
			}
			publishClient = false
		}
	}
	if publishClient {
		revision, document, mihomo, err := s.publishClientDocuments()
		if err != nil {
			return assembly, err
		}
		assembly.ClientRevision, assembly.ClientDocument = revision, document
		assembly.MihomoDocument = mihomo
		assembly.RoutePolicyRevisions[string(PolicyLayerClient)] = revision
	}
	if publishServer {
		revision, egress, code, err := s.assembleServerLayer()
		if err != nil {
			return assembly, err
		}
		// The server layer is a validated record only. No route fragment and no
		// Line candidate are produced, so nothing routing-related reaches an
		// Agent; the egress reported for the server side is direct by
		// construction.
		assembly.ServerRevision = revision
		assembly.EgressState, assembly.EgressCode = egress, code
		assembly.RoutePolicyRevisions[string(PolicyLayerServer)] = revision
	}
	if assembly.ClientRevision == 0 && assembly.ServerRevision == 0 {
		return assembly, errors.New(CodePublishNoPolicy + ": no active policy revision exists for the requested layer")
	}
	if publishServer && assembly.ServerRevision == 0 {
		return assembly, errors.New(CodePublishNoPolicy + ": no active server policy revision exists")
	}
	if err := s.gatePolicyAssembly(ctx, verifier, &assembly); err != nil {
		return assembly, err
	}
	return assembly, nil
}

// publishClientDocuments validates the active client revision and assembles
// the sing-box and Mihomo preview documents the gate checks. The documents are
// evidence only: nothing stores them and no download path reads them.
func (s *Store) publishClientDocuments() (int64, []byte, []byte, error) {
	record, intent, err := s.ActivePolicyIntent(PolicyLayerClient)
	if err != nil {
		return 0, nil, nil, err
	}
	clientPolicy := coredomain.ClientPolicy{Default: intent.Default, Rules: intent.Rules}
	if err := clientPolicy.Validate(); err != nil {
		return record.Revision, nil, nil, err
	}
	pins, err := DecodePins(record.Pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	singBoxFragment, err := coredomain.RenderSingBox(clientPolicy, pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	singBox, err := clientdoc.SingBox(singBoxFragment)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	mihomoFragment, err := coredomain.RenderMihomo(clientPolicy, pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	mihomo, err := clientdoc.Mihomo(mihomoFragment, pins, clientPolicy.Rules)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	return record.Revision, singBox, mihomo, nil
}

// assembleServerLayer validates the active server revision and reports the
// server-side egress state.
//
// The server publishes proxy ports and credentials only (iron rule ①): no route
// fragment is rendered, no Line candidate is written and no `out` selection is
// resolved, so a policy revision can never deliver routing rules to an Agent.
// From the server's own point of view every Line egresses directly — the client
// chooses the hop in its own document.
//
// Validation is kept because a corrupt or hand-edited active payload must still
// be refused with a stable code instead of being published as healthy intent.
func (s *Store) assembleServerLayer() (int64, string, string, error) {
	record, intent, err := s.ActivePolicyIntent(PolicyLayerServer)
	if err != nil {
		return 0, "", "", err
	}
	serverIntent := coredomain.ServerPolicy{Default: intent.Default, Rules: intent.Rules}
	if err := serverIntent.Validate(); err != nil {
		return record.Revision, "", "", err
	}
	return record.Revision, coredomain.AIEgressLine, "", nil
}

// gatePolicyAssembly runs the fixed kernel gates. A missing or unusable kernel
// is a refusal with its own code; it is never treated as a passing check.
func (s *Store) gatePolicyAssembly(ctx context.Context, verifier common.PublishVerifier, assembly *PolicyAssembly) error {
	if verifier == nil {
		return errors.New(common.PublishGateCode + ": no kernel verifier is configured")
	}
	evidence := make([]PolicyCheckEvidence, 0, len(assembly.Targets)+2)
	for _, target := range assembly.Targets {
		detail, err := verifier.CheckSingBox(ctx, target.Config)
		if err != nil {
			return err
		}
		evidence = append(evidence, PolicyCheckEvidence{Stage: "line-candidate", Kernel: common.KernelSingBox, Status: "passed", Detail: detail})
	}
	if len(assembly.ClientDocument) > 0 {
		detail, err := verifier.CheckSingBox(ctx, assembly.ClientDocument)
		if err != nil {
			return err
		}
		evidence = append(evidence, PolicyCheckEvidence{Stage: "client-document", Kernel: common.KernelSingBox, Status: "passed", Detail: detail})
	}
	if len(assembly.MihomoDocument) > 0 {
		detail, err := verifier.CheckMihomo(ctx, assembly.MihomoDocument)
		if err != nil {
			return err
		}
		evidence = append(evidence, PolicyCheckEvidence{Stage: "client-document", Kernel: common.KernelMihomo, Status: "passed", Detail: detail})
	}
	assembly.Checks = evidence
	return nil
}

// AggregatePolicyEgress reduces the per-Line states of one publication to the
// single state its receipt reports.
//
// Each Line keeps its own state: coredomain.AIEgressLine, coredomain.AIEgressOut,
// coredomain.AIEgressLineFallback or PolicyEgressFailClosed. The receipt reports
// that state only when every Line agrees; as soon as the Lines differ the
// result is PolicyEgressMixed, because one Line's egress must never be
// presented as every Line's egress. Fail-closed is not loosened by the
// aggregate: a Line whose bound Out cannot carry the traffic still fails the
// publication through coredomain.ResolveServerPolicy (or, when the policy does
// not use the Out, keeps its own fail-closed row in Targets). The reported
// code is the first real reason among the Lines, so it always names a state
// one Line actually reported.
func AggregatePolicyEgress(states, codes []string) (string, string) {
	if len(states) == 0 {
		return "", ""
	}
	code := ""
	for _, candidate := range codes {
		if candidate != "" {
			code = candidate
			break
		}
	}
	aggregate := states[0]
	for _, state := range states[1:] {
		if state != aggregate {
			return PolicyEgressMixed, code
		}
	}
	return aggregate, code
}

// DecodePins decodes the stored rule-set pins of one revision.
func DecodePins(raw json.RawMessage) (coredomain.RuleSetPins, error) {
	pins := coredomain.RuleSetPins{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return pins, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pins); err != nil {
		return pins, errors.New(codePolicyPinsInvalid + ": pins must be the documented RuleSetPins JSON")
	}
	return pins, nil
}

// publishRefusalCodes are every stable code a publication can report. The list
// is explicit so an unknown message never leaks and never becomes a 500.
var publishRefusalCodes = []string{
	codePolicyOperationRequired, codePolicyPayloadInvalid, codePolicyLayerInvalid,
	CodePublishNoPolicy, codePolicyPinsInvalid, codePolicyCorrupt, codePolicySecretRefused,
	CodePolicyLayerRetired, // defensive: publication never writes a policy layer
	CodePolicyPayloadRetired,
	coredomain.CodePolicyInvalid, coredomain.CodePolicyConflict, coredomain.CodeRulesetUnpinned,
	coredomain.CodeOutOfflineFailClosed, coredomain.CodeOutFallbackUnaudited,
	coredomain.CodeRulesetFetchFailed, coredomain.CodeRulesetPinInvalid,
	"OUT_BINDING_INVALID", storenode.CodeOutNotAuthorized,
	CodePublishNoLines, common.PublishGateCode,
	node.CodePublishSingBoxMissing, node.CodePublishCheckSingBox,
	node.CodePublishMihomoMissing, node.CodePublishMihomoVersion, node.CodePublishCheckMihomo,
	CodePublishRevisionChanged, CodePublishTasksInProgress, codePublishCandidateChanged,
}

// policyPublishFailure maps one refusal onto the HTTP contract: the stable code,
// the operator detail and the status class.
func PolicyPublishFailure(err error) (int, string, string) {
	raw := err.Error()
	code, detail, _ := strings.Cut(raw, ": ")
	if detail == "" {
		detail = raw
		code = raw
	}
	known := false
	for _, candidate := range publishRefusalCodes {
		if code == candidate {
			known = true
			break
		}
	}
	if !known {
		return 500, common.PublishGateCode, "发布未完成，且失败原因不在已登记的错误码内。"
	}
	status := 422
	switch code {
	case codePolicyOperationRequired, codePolicyPayloadInvalid, codePolicyLayerInvalid, CodePolicyPayloadRetired:
		status = 400
	case CodePublishNoPolicy:
		status = 404
	case coredomain.CodePolicyConflict, coredomain.CodeOutOfflineFailClosed, coredomain.CodeOutFallbackUnaudited,
		"OUT_BINDING_INVALID", storenode.CodeOutNotAuthorized, CodePublishTasksInProgress,
		CodePublishRevisionChanged, codePublishCandidateChanged:
		status = 409
	case CodePolicyLayerRetired:
		// Defensive only: AssemblePolicyPublication reads the active policy and
		// renders it; it never creates, revises or activates a revision, so this
		// refusal cannot originate from the publish path today. It stays mapped
		// (409) so a future publication path that does validate a write answers
		// with the stable code instead of becoming a 500 PUBLISH_GATE_FAILED.
		status = 409
	case common.PublishGateCode, node.CodePublishSingBoxMissing, node.CodePublishMihomoMissing:
		status = 503
	}
	return status, code, detail
}

// IsNotFound reports the single "no active revision" store refusal.
func IsNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), CodePublishNoPolicy)
}
