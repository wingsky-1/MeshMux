package web

// Publication assembly for issue #10 (10d-2b). The pipeline has one order and
// no shortcut:
//
//	active revision -> Validate -> ResolveServerPolicy (fail-closed Out)
//	-> RuleSetPins.Validate -> RenderServerRoute / RenderSingBox / RenderMihomo
//	-> kernel gate (sing-box check, mihomo -t) -> candidate publication
//
// Nothing here executes a shell: both kernels are reached through the fixed
// verifier wrapper of publish_verifier.go, which runs one argv without a shell.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/route"
)

// policySchemaVersion is the schema of the stored policy tables. Every
// publication receipt carries it together with route_policy_revisions, so an
// upgrade manifest (#11) can prove which policy revision it published.
const policySchemaVersion = 8

// Stable publication refusals that no lower layer owns.
const (
	// codePublishNoLines: no Line carries stored transport, so a server
	// policy has no target.
	codePublishNoLines = "PUBLISH_NO_LINES"
	// codePublishGate: the gate could not run at all.
	codePublishGate = "PUBLISH_GATE_FAILED"
	// codePublishNoPolicy: the requested layer has no active revision.
	codePublishNoPolicy = "POLICY_NOT_FOUND"
)

// publishTarget is one Line the assembled server route is published to.
type publishTarget struct {
	LineID     string
	Candidate  node.Candidate
	Config     []byte
	ConfigHash string
	Egress     string
	EgressCode string
}

// policyAssembly is the gated result of one publication attempt. It carries no
// secret: the rendered fragments, digests and stable codes only.
type policyAssembly struct {
	OperationID          string
	Layer                string
	EgressState          string
	EgressCode           string
	RouteFragment        []byte
	ClientDocument       []byte
	MihomoDocument       []byte
	Targets              []publishTarget
	ClientRevision       int64
	ServerRevision       int64
	RoutePolicyRevisions map[string]int64
	PolicySchema         int
	Checks               []policyCheckEvidence
}

// policyPublishRequest is the strict body of POST /policies/publish.
type policyPublishRequest struct {
	Layer          string `json:"layer"`
	OperationID    string `json:"operation_id"`
	FallbackToLine bool   `json:"fallback_to_line"`
}

// policyPublishReceipt is the stable receipt. A publication reports ok only
// when every gate passed and every target candidate was stored.
type policyPublishReceipt struct {
	OK                   bool                     `json:"ok"`
	Status               string                   `json:"status"`
	Revision             int64                    `json:"revision,omitempty"`
	EgressState          string                   `json:"egress_state,omitempty"`
	EgressCode           string                   `json:"egress_code,omitempty"`
	PolicySchema         int                      `json:"policy_schema"`
	RoutePolicyRevisions map[string]int64         `json:"route_policy_revisions"`
	Checks               []policyCheckEvidence    `json:"checks"`
	Candidate            *policyCandidateEvidence `json:"candidate,omitempty"`
	Lines                []policyLineEvidence     `json:"lines,omitempty"`
	ErrorCode            string                   `json:"error_code,omitempty"`
	Detail               string                   `json:"detail,omitempty"`
	NextAction           string                   `json:"next_action,omitempty"`
	OperationID          string                   `json:"operation_id"`
}

// policyCheckEvidence is one kernel gate result. Detail is a short summary,
// never the checked document and never a full kernel transcript.
type policyCheckEvidence struct {
	Stage  string `json:"stage"`
	Kernel string `json:"kernel"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// policyCandidateEvidence references the immutable candidate the publication
// produced.
type policyCandidateEvidence struct {
	Revision int64  `json:"revision"`
	Lines    int    `json:"lines"`
	Config   string `json:"config_sha256"`
}

// policyLineEvidence is one Line's outcome in a publication.
type policyLineEvidence struct {
	LineID      string `json:"line_id"`
	Revision    int64  `json:"revision"`
	EgressState string `json:"egress_state"`
	EgressCode  string `json:"egress_code,omitempty"`
	Status      string `json:"status"`
	ErrorCode   string `json:"error_code,omitempty"`
}

// parsePolicyPublishRequest decodes and validates the publish body.
func parsePolicyPublishRequest(raw json.RawMessage) (policyPublishRequest, error) {
	var request policyPublishRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return policyPublishRequest{}, errors.New("POLICY_PAYLOAD_INVALID: the publish body must be the documented JSON")
	}
	if strings.TrimSpace(string(raw)) == "" {
		return policyPublishRequest{}, errors.New("POLICY_PAYLOAD_INVALID: the publish body is empty")
	}
	request.Layer = strings.TrimSpace(request.Layer)
	request.OperationID = strings.TrimSpace(request.OperationID)
	if request.OperationID == "" || len(request.OperationID) > 128 {
		return policyPublishRequest{}, errors.New("POLICY_OPERATION_REQUIRED: publication needs a non-empty operation id")
	}
	switch request.Layer {
	case "", string(PolicyLayerClient), string(PolicyLayerServer):
	default:
		return policyPublishRequest{}, errors.New("POLICY_LAYER_INVALID: layer must be client, server or empty for both")
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
func (s *store) assemblePolicyPublication(ctx context.Context, verifier publishVerifier, request policyPublishRequest, now time.Time) (policyAssembly, error) {
	assembly := policyAssembly{
		OperationID:          request.OperationID,
		Layer:                request.Layer,
		PolicySchema:         policySchemaVersion,
		RoutePolicyRevisions: map[string]int64{},
	}
	// layer="" publishes the server layer plus any active client layer. The
	// Line candidate is the only publication artifact the Hub stores; the
	// client documents are rendered and gated as evidence because a client
	// layer without its kernel check would be a publication the Hub cannot
	// prove.
	publishClient := request.Layer == "" || request.Layer == string(PolicyLayerClient)
	publishServer := request.Layer == "" || request.Layer == string(PolicyLayerServer)
	if request.Layer == "" {
		if _, _, err := s.activePolicyIntent(PolicyLayerClient); err != nil {
			if !isPolicyNotFound(err) {
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
		fragment, revision, egress, code, targets, err := s.publishServerRoute(request.FallbackToLine, request.OperationID, now)
		if err != nil {
			return assembly, err
		}
		assembly.ServerRevision, assembly.RouteFragment = revision, fragment
		assembly.EgressState, assembly.EgressCode = egress, code
		assembly.Targets = targets
		assembly.RoutePolicyRevisions[string(PolicyLayerServer)] = revision
	}
	if assembly.ClientRevision == 0 && assembly.ServerRevision == 0 {
		return assembly, errors.New(codePublishNoPolicy + ": no active policy revision exists for the requested layer")
	}
	if publishServer && assembly.ServerRevision == 0 {
		return assembly, errors.New(codePublishNoPolicy + ": no active server policy revision exists")
	}
	if err := s.gatePolicyAssembly(ctx, verifier, &assembly); err != nil {
		return assembly, err
	}
	return assembly, nil
}

// publishClientDocuments validates the active client revision and assembles
// the sing-box and Mihomo documents the gate checks.
func (s *store) publishClientDocuments() (int64, []byte, []byte, error) {
	record, intent, err := s.activePolicyIntent(PolicyLayerClient)
	if err != nil {
		return 0, nil, nil, err
	}
	policy := compiler.ClientPolicy{Default: intent.Default, Rules: intent.Rules}
	if err := policy.Validate(); err != nil {
		return record.Revision, nil, nil, err
	}
	pins, err := decodePolicyPins(record.Pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	singBoxFragment, err := compiler.RenderSingBox(policy, pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	singBox, err := assembleSingBoxClient(singBoxFragment)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	mihomoFragment, err := compiler.RenderMihomo(policy, pins)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	mihomo, err := assembleMihomoClient(mihomoFragment, pins, policy.Rules)
	if err != nil {
		return record.Revision, nil, nil, err
	}
	return record.Revision, singBox, mihomo, nil
}

// publishServerRoute resolves the active server revision per Line and renders
// one route fragment per Line.
//
// The Out facts are read per Line: no enabled binding is a configured direct
// egress, while an unhealthy bound Out fails closed unless the caller opted in.
// The operation id reaches the resolver so an explicit fallback is auditable.
func (s *store) publishServerRoute(fallbackToLine bool, operationID string, now time.Time) ([]byte, int64, string, string, []publishTarget, error) {
	record, intent, err := s.activePolicyIntent(PolicyLayerServer)
	if err != nil {
		return nil, 0, "", "", nil, err
	}
	pins, err := decodePolicyPins(record.Pins)
	if err != nil {
		return nil, record.Revision, "", "", nil, err
	}
	lines, err := s.listLines()
	if err != nil {
		return nil, record.Revision, "", "", nil, err
	}
	lineIDs := make([]string, 0, len(lines))
	for _, line := range lines {
		lineIDs = append(lineIDs, line.NodeID)
	}
	sort.Strings(lineIDs)
	if len(lineIDs) == 0 {
		return nil, record.Revision, "", "", nil, errors.New(codePublishNoLines + ": no line carries stored transport")
	}
	var fragment []byte
	var egressState, egressCode string
	targets := make([]publishTarget, 0, len(lineIDs))
	for _, lineID := range lineIDs {
		facts, err := s.OutEgressFacts(lineID, now)
		if err != nil {
			return nil, record.Revision, "", "", nil, err
		}
		policy := compiler.ServerPolicy{
			Default:        intent.Default,
			Rules:          intent.Rules,
			OutConfigured:  facts.Configured,
			OutAvailable:   facts.Available,
			FallbackToLine: fallbackToLine && facts.Configured && !facts.Available,
			OperationID:    operationID,
		}
		state, code := policyEgressState(facts, policy.FallbackToLine)
		resolved, err := compiler.ResolveServerPolicy(policy)
		if err != nil {
			return nil, record.Revision, state, code, nil, err
		}
		if err := pins.Validate(resolved.Rules); err != nil {
			return nil, record.Revision, state, code, nil, err
		}
		lineFragment, err := compiler.RenderServerRoute(resolved, pins)
		if err != nil {
			return nil, record.Revision, state, code, nil, err
		}
		if fragment == nil {
			fragment, egressState, egressCode = lineFragment, state, code
		}
		target, err := s.publishTarget(lineID, lineFragment, facts.Configured, state, code)
		if err != nil {
			return nil, record.Revision, state, code, nil, err
		}
		targets = append(targets, target)
	}
	return fragment, record.Revision, egressState, egressCode, targets, nil
}

// publishTarget builds the next candidate of one Line with the route embedded
// and compiles it exactly the way the Agent compiles it, so the gate checks the
// bytes the node would run.
//
// The candidate revision read here is advisory: the publication transaction
// recomputes it under the write lock, so a concurrent subscriber change is
// never overwritten.
func (s *store) publishTarget(lineID string, fragment []byte, outConfigured bool, egressState, egressCode string) (publishTarget, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return publishTarget{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	revision, err := nextCandidateRevisionTx(tx, lineID)
	if err != nil {
		return publishTarget{}, err
	}
	candidate, err := buildLineCandidateTx(tx, lineID, revision)
	if err != nil {
		return publishTarget{}, err
	}
	candidate.Route = json.RawMessage(fragment)
	config, err := node.CompileCandidateWithRoute(candidate, json.RawMessage(fragment), outConfigured)
	if err != nil {
		return publishTarget{}, err
	}
	return publishTarget{
		LineID: lineID, Candidate: candidate, Config: config,
		ConfigHash: compiler.Hash(config), Egress: egressState, EgressCode: egressCode,
	}, nil
}

// gatePolicyAssembly runs the fixed kernel gates. A missing or unusable kernel
// is a refusal with its own code; it is never treated as a passing check.
func (s *store) gatePolicyAssembly(ctx context.Context, verifier publishVerifier, assembly *policyAssembly) error {
	if verifier == nil {
		return errors.New(codePublishGate + ": no kernel verifier is configured")
	}
	evidence := make([]policyCheckEvidence, 0, len(assembly.Targets)+2)
	for _, target := range assembly.Targets {
		detail, err := verifier.CheckSingBox(ctx, target.Config)
		if err != nil {
			return err
		}
		evidence = append(evidence, policyCheckEvidence{Stage: "line-candidate", Kernel: "sing-box", Status: "passed", Detail: detail})
	}
	if len(assembly.ClientDocument) > 0 {
		detail, err := verifier.CheckSingBox(ctx, assembly.ClientDocument)
		if err != nil {
			return err
		}
		evidence = append(evidence, policyCheckEvidence{Stage: "client-document", Kernel: "sing-box", Status: "passed", Detail: detail})
	}
	if len(assembly.MihomoDocument) > 0 {
		detail, err := verifier.CheckMihomo(ctx, assembly.MihomoDocument)
		if err != nil {
			return err
		}
		evidence = append(evidence, policyCheckEvidence{Stage: "client-document", Kernel: "mihomo", Status: "passed", Detail: detail})
	}
	assembly.Checks = evidence
	return nil
}

// policyEgressState maps the Out facts onto the documented states.
func policyEgressState(facts OutEgressFacts, fallback bool) (string, string) {
	if !facts.Configured {
		return route.AIEgressLine, ""
	}
	if facts.Available {
		return route.AIEgressOut, ""
	}
	if fallback {
		return route.AIEgressLineFallback, route.CodeOutOfflineFailClosed
	}
	return "fail-closed", route.CodeOutOfflineFailClosed
}

func decodePolicyPins(raw json.RawMessage) (compiler.RuleSetPins, error) {
	pins := compiler.RuleSetPins{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return pins, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pins); err != nil {
		return pins, errors.New("POLICY_PINS_INVALID: pins must be the documented RuleSetPins JSON")
	}
	return pins, nil
}

// assemblyReceipt is the receipt of a gated assembly that has not been stored
// yet. It is the evidence a caller needs to decide whether to publish.
func assemblyReceipt(assembly policyAssembly) policyPublishReceipt {
	receipt := policyPublishReceipt{
		OK:                   true,
		Status:               "validated",
		Revision:             assembly.ServerRevision,
		EgressState:          assembly.EgressState,
		EgressCode:           assembly.EgressCode,
		PolicySchema:         assembly.PolicySchema,
		RoutePolicyRevisions: assembly.RoutePolicyRevisions,
		Checks:               assembly.Checks,
		NextAction:           "装配与门禁已通过；节点候选下发在下一阶段接入。",
	}
	if receipt.Revision == 0 {
		receipt.Revision = assembly.ClientRevision
	}
	return receipt
}

// writePublicationReceipt writes one receipt with its operation id.
func writePublicationReceipt(w http.ResponseWriter, status int, receipt policyPublishReceipt, operationID string) {
	receipt.OperationID = operationID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(receipt)
}

// publishRefusalCodes are every stable code a publication can report. The list
// is explicit so an unknown message never leaks and never becomes a 500.
var publishRefusalCodes = []string{
	"POLICY_OPERATION_REQUIRED", "POLICY_PAYLOAD_INVALID", "POLICY_LAYER_INVALID",
	"POLICY_NOT_FOUND", "POLICY_PINS_INVALID", "POLICY_CORRUPT", "POLICY_SECRET_REFUSED",
	compiler.CodePolicyInvalid, compiler.CodePolicyConflict, compiler.CodeRulesetUnpinned,
	route.CodeOutOfflineFailClosed, route.CodeOutFallbackUnaudited,
	route.CodeRulesetFetchFailed, route.CodeRulesetPinInvalid,
	"OUT_BINDING_INVALID", codeOutNotAuthorized,
	codePublishNoLines, codePublishGate,
	node.CodePublishSingBoxMissing, node.CodePublishCheckSingBox,
	node.CodePublishMihomoMissing, node.CodePublishMihomoVersion, node.CodePublishCheckMihomo,
}

// policyPublishFailure maps one refusal onto the HTTP contract: the stable code,
// the operator detail and the status class.
func policyPublishFailure(err error) (int, string, string) {
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
		return 500, codePublishGate, "发布未完成，且失败原因不在已登记的错误码内。"
	}
	status := 422
	switch code {
	case "POLICY_OPERATION_REQUIRED", "POLICY_PAYLOAD_INVALID", "POLICY_LAYER_INVALID":
		status = 400
	case "POLICY_NOT_FOUND":
		status = 404
	case compiler.CodePolicyConflict, route.CodeOutOfflineFailClosed, route.CodeOutFallbackUnaudited,
		"OUT_BINDING_INVALID", codeOutNotAuthorized:
		status = 409
	case codePublishGate, node.CodePublishSingBoxMissing, node.CodePublishMihomoMissing:
		status = 503
	}
	return status, code, detail
}

// isPolicyNotFound reports the single "no active revision" store refusal.
func isPolicyNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), codePublishNoPolicy)
}
