package store

// Subscription composition for the aggregation rebuild (Task 4, ADR-0008 §7).
//
// One subscription artifact is built in one order and one only:
//
//	draft (identities + credentials, read-only)
//	-> ComposeSubscription (pure) -> kernel gate (sing-box required, mihomo only
//	when installed) -> one atomic save that stores the selection and the
//	approved artifact digest
//
// The draft exists because the artifact digest depends on the VLESS UUIDs: the
// wizard must gate the exact bytes the download will later re-derive, so the
// credentials are minted before the gate and written unchanged after it. A save
// therefore writes nothing at all when any layer blocks, and the approved digest
// can never disagree with the credentials it was computed from.
//
// The composed bytes are never stored. The snapshot stores the selection and the
// digest of the approved artifact; a download re-composes from the same
// selection and compares the digest, so a stored byte could never silently
// drift from the choice that produced it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// Stable composition refusals owned by the store.
const (
	// CodeComposeGateFailed: the kernel gate refused the assembled documents.
	CodeComposeGateFailed = "SUBSCRIPTION_GATE_FAILED"
	// CodeComposeGateUnavailable: the gate could not run (no sing-box).
	CodeComposeGateUnavailable = "SUBSCRIPTION_GATE_UNAVAILABLE"
	// CodeComposeMihomoSkipped is a non-blocking note, not an error: the
	// mihomo gate did not run because the pinned binary is not installed.
	CodeComposeMihomoSkipped = "SUBSCRIPTION_MIHOMO_GATE_SKIPPED"
)

// SelectionPreview is the fail-fast result of one submitted selection. It is
// the four-layer contract of ADR-0008 §7:
//
//	layer 1 (input)   : reminders only, rendered with "!"
//	layer 2 (save)    : strict validation, a blocking diagnostic
//	layer 3 (compose) : conflicts and the Out slot, a blocking diagnostic
//	layer 4 (gate)    : kernel check, a blocking diagnostic
//
// A preview never writes. Approved is true only when no blocking diagnostic
// exists and every available gate passed.
type SelectionPreview struct {
	Diagnostics []subscription.Diagnostic
	Documents   subscription.ComposeDocuments
	// Approved is true when the artifact may be saved as the approved one.
	Approved bool
	// ContentID is the artifact digest of the composed documents.
	ContentID string
	// Gates lists the kernels that actually ran, in order.
	Gates []string
	// MihomoSkipped is true when the pinned Mihomo binary is absent. It is a
	// reminder, never a silent pass.
	MihomoSkipped bool
}

// Blocking reports whether the preview refused the artifact.
func (p SelectionPreview) Blocking() bool {
	return hasBlockingDiagnostic(p.Diagnostics)
}

// Code returns the first blocking code, or "" when the preview is approved.
func (p SelectionPreview) Code() string {
	for _, diagnostic := range p.Diagnostics {
		if diagnostic.Level == subscription.DiagnosticBlocking {
			return diagnostic.Code
		}
	}
	return ""
}

// SubscriptionDraft is one validated, not yet written selection: the subscriber
// identity (new or existing), the exact credentials the artifact will carry and
// the composer inputs. Nothing here is persisted until SaveSubscriptionDraft.
type SubscriptionDraft struct {
	Subscriber  subscription.Subscriber
	Create      bool
	Credentials []subscription.Credential
	Selection   subscription.Selection
	inputs      selectionInputs
	diagnostics []subscription.Diagnostic
}

// DraftSubscriptionSelection validates one submitted selection without writing
// anything. A missing subscriber identity means the create form: a fresh
// subscriber identity is minted here, so the preview can gate the exact
// credentials the save will persist.
func (s *Store) DraftSubscriptionSelection(subscriberID, displayName string, spec SelectionSpec) (SubscriptionDraft, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	draft, err := buildSubscriptionDraftTx(tx, subscriberID, displayName, spec)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	if err := tx.Commit(); err != nil {
		return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return draft, nil
}

// buildSubscriptionDraftTx is the one draft builder. It never writes.
func buildSubscriptionDraftTx(tx *sql.Tx, subscriberID, displayName string, spec SelectionSpec) (SubscriptionDraft, error) {
	draft := SubscriptionDraft{}
	diagnostics := []subscription.Diagnostic{}
	block := func(code, detail string) {
		diagnostics = append(diagnostics, subscription.Diagnostic{Level: subscription.DiagnosticBlocking, Code: code, Detail: detail})
	}
	if strings.TrimSpace(subscriberID) == "" {
		sub, err := subscription.NewSubscriber(displayName)
		if err != nil {
			return SubscriptionDraft{}, err
		}
		draft.Subscriber, draft.Create = sub, true
	} else {
		if err := subscription.ValidateID(subscriberID); err != nil {
			return SubscriptionDraft{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
		}
		sub, err := getSubscriberTx(tx, subscriberID)
		if err != nil {
			return SubscriptionDraft{}, err
		}
		if sub.State != subscription.StateActive {
			return SubscriptionDraft{}, errors.New("SUBSCRIBER_NOT_ACTIVE: activate the subscriber before changing its selection")
		}
		draft.Subscriber = sub
	}

	// Layer 2 is strict: an unusable identity shape is an error, not a
	// diagnostic, so a caller can never mistake a malformed request for a
	// rendered finding.
	lineIDs, err := normalizeLineSelection(spec.LineIDs)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	ruleRevisions, err := normalizeRuleSelection(spec.Rules)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	deviceIDs, err := normalizeDeviceSelection(spec.NetworkIDs)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	outID := strings.TrimSpace(spec.OutID)
	if outID != "" && !validNodeID(outID) {
		return SubscriptionDraft{}, errors.New(CodeSelectionInvalid + ": out_id must be 32 lowercase hex characters")
	}

	// Layer 2: every reference must exist and be selectable.
	for _, nodeID := range lineIDs {
		if err := validateLineTx(tx, nodeID); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	if err := validateSelectionOutTx(tx, outID); err != nil {
		return SubscriptionDraft{}, err
	}
	for _, revision := range ruleRevisions {
		if err := validateRuleRevisionTx(tx, revision); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	for _, deviceID := range deviceIDs {
		if err := validateSelectionDeviceTx(tx, deviceID); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	// The same-Line Out rule applies to a create as well: the new subscriber is
	// not persisted yet, so every existing row on these Lines is a potential
	// conflict and must already agree with the submitted Out choice.
	if err := enforceSameLineOutTx(tx, draft.Subscriber.ID, lineIDs, outID); err != nil {
		return SubscriptionDraft{}, err
	}

	// The credentials are minted now and written unchanged after the gate, so
	// the approved digest is computed over the exact UUIDs the download serves.
	credentials := make([]subscription.Credential, 0, len(lineIDs))
	for _, nodeID := range lineIDs {
		credential, err := reusableCredentialTx(tx, draft.Subscriber.ID, nodeID, draft.Create)
		if err != nil {
			return SubscriptionDraft{}, err
		}
		credentials = append(credentials, credential)
	}
	draft.Credentials = credentials

	// Layer 3: the composer inputs and the pure composition.
	inputs := selectionInputs{}
	for index, nodeID := range lineIDs {
		line, err := downloadLineTx(tx, nodeID)
		if err != nil {
			block(subscription.CodeComposeLineInvalid, "所选 Line 已不可用")
			continue
		}
		inputs.Lines = append(inputs.Lines, subscription.ComposeLine{Line: publicLine(line), Credential: credentials[index]})
	}
	if outID != "" {
		out, err := selectionOutTx(tx, outID)
		if err != nil {
			block(subscription.CodeComposeOutInvalid, "所选 Out 已不可用或未配置出口地址")
		} else {
			inputs.Out = []subscription.ComposeOut{out}
		}
	}
	rules, err := selectionRulesTx(tx, ruleRevisions)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	inputs.Rules = rules
	for _, deviceID := range deviceIDs {
		var name string
		err := tx.QueryRow(`SELECT display_name FROM mesh_devices WHERE id=?`, deviceID).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			block(subscription.CodeComposeLineInvalid, "所选组网设备不存在")
			continue
		}
		if err != nil {
			return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
		}
		inputs.Network = append(inputs.Network, subscription.ComposeNetwork{DeviceID: deviceID, DisplayName: name})
	}
	draft.inputs = inputs
	draft.diagnostics = diagnostics

	// The snapshot model is built from the same order the composer used.
	selection := subscription.Selection{SubscriberID: draft.Subscriber.ID}
	if !draft.Create {
		var stored int64
		err := tx.QueryRow(`SELECT version FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).Scan(&stored)
		switch {
		case err == nil:
			selection.Version = stored
		case errors.Is(err, sql.ErrNoRows):
		default:
			return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	selection.Version++
	for position, nodeID := range lineIDs {
		lineRevision := int64(0)
		if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&lineRevision); err != nil {
			return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
		}
		selection.Lines = append(selection.Lines, subscription.SelectionLine{NodeID: nodeID, Position: position, LineRevision: lineRevision})
	}
	if outID != "" {
		outRevision := int64(0)
		if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, outID).Scan(&outRevision); err != nil {
			return SubscriptionDraft{}, errors.New("DATABASE_UNAVAILABLE")
		}
		selection.Out = &subscription.SelectionOut{OutID: outID, Position: 0, OutRevision: outRevision}
	}
	for position, revision := range ruleRevisions {
		selection.Rules = append(selection.Rules, subscription.SelectionRule{StableKey: revision.StableKey, Version: revision.Version, Position: position})
	}
	for position, deviceID := range deviceIDs {
		selection.Networks = append(selection.Networks, subscription.SelectionNetwork{DeviceID: deviceID, Position: position})
	}
	draft.Selection = selection
	return draft, nil
}

// storedCredentialTx reads the stored credential of one subscriber on one Line,
// active or not. The artifact path uses it because a saved selection must
// already carry a usable credential; minting one here would change the bytes
// after the fact.
func storedCredentialTx(tx *sql.Tx, subscriberID, nodeID string) (subscription.Credential, error) {
	var credential subscription.Credential
	err := tx.QueryRow(`SELECT id, subscriber_id, node_id, uuid FROM proxy_credentials
	  WHERE subscriber_id=? AND node_id=? AND active=1`, subscriberID, nodeID).
		Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.Credential{}, errors.New("CREDENTIAL_NOT_FOUND: no active credential for this line")
	}
	if err != nil {
		return subscription.Credential{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return credential, nil
}

// reusableCredentialTx returns the credential a selected Line will carry: the
// existing one when it is still usable, a fresh one otherwise. The read is the
// same row SelectLines uses, so a save can never mint a second UUID for one
// Line.
func reusableCredentialTx(tx *sql.Tx, subscriberID, nodeID string, creating bool) (subscription.Credential, error) {
	if !creating {
		var credential subscription.Credential
		err := tx.QueryRow(`SELECT id, subscriber_id, node_id, uuid FROM proxy_credentials WHERE subscriber_id=? AND node_id=?`,
			subscriberID, nodeID).Scan(&credential.ID, &credential.SubscriberID, &credential.NodeID, &credential.UUID)
		switch {
		case err == nil:
			return credential, nil
		case errors.Is(err, sql.ErrNoRows):
		default:
			return subscription.Credential{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	credential, err := subscription.NewCredential(subscriberID, nodeID)
	if err != nil {
		return subscription.Credential{}, errors.New("CREDENTIAL_CREATE_FAILED")
	}
	return credential, nil
}

// PreviewDraftSelection composes and gates one draft without writing anything.
func (s *Store) PreviewDraftSelection(draft SubscriptionDraft, verifier PublishVerifier) SelectionPreview {
	return s.composeAndGate(context.Background(), draft.inputs, verifier, draft.diagnostics)
}

// SaveSubscriptionDraft writes one draft in a single transaction: the
// subscriber and its token (create only), the four edge groups, the credentials
// and the snapshot with the approved artifact digest. It returns the plaintext
// bearer exactly once for a create.
//
// artifactID may be empty, which records a saved-but-unapproved selection; the
// download refuses such a snapshot instead of falling back to older bytes.
func (s *Store) SaveSubscriptionDraft(draft SubscriptionDraft, artifactID string, now time.Time) (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	bearer := ""
	if draft.Create {
		if _, err = tx.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at) VALUES(?,?,?,1,?,?)`,
			draft.Subscriber.ID, draft.Subscriber.DisplayName, string(draft.Subscriber.State), now.Unix(), now.Unix()); err != nil {
			return "", errors.New("SUBSCRIBER_CREATE_FAILED")
		}
		record, token, tErr := subscription.NewSubscriptionToken(draft.Subscriber.ID)
		if tErr != nil {
			return "", errors.New("TOKEN_CREATE_FAILED")
		}
		if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
			record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
			return "", errors.New("TOKEN_CREATE_FAILED")
		}
		bearer = token
	}
	lineIDs := make([]string, 0, len(draft.Selection.Lines))
	for _, line := range draft.Selection.Lines {
		lineIDs = append(lineIDs, line.NodeID)
	}
	deviceIDs := make([]string, 0, len(draft.Selection.Networks))
	for _, device := range draft.Selection.Networks {
		deviceIDs = append(deviceIDs, device.DeviceID)
	}
	ruleRevisions := make([]RuleRevision, 0, len(draft.Selection.Rules))
	for _, rule := range draft.Selection.Rules {
		ruleRevisions = append(ruleRevisions, RuleRevision{StableKey: rule.StableKey, Version: rule.Version})
	}
	outID := ""
	if draft.Selection.Out != nil {
		outID = draft.Selection.Out.OutID
	}
	if err := writeSelectionEdgesTx(tx, draft.Subscriber.ID, lineIDs, outID, ruleRevisions, deviceIDs, now); err != nil {
		return "", err
	}
	if err := writeDraftCredentialsTx(tx, draft, now); err != nil {
		return "", err
	}
	if err := writeSnapshotTx(tx, draft.Selection, artifactID, now); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`UPDATE subscribers SET revision=revision+1, updated_at=? WHERE id=?`, now.Unix(), draft.Subscriber.ID); err != nil {
		return "", errors.New("SUBSCRIBER_UPDATE_FAILED")
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New("DATABASE_UNAVAILABLE")
	}
	// The save ends here on purpose (Ruling R10): a subscription selection is not an
	// ACL input, so it must not republish any Out. The Line's own publication is
	// driven by the caller's PrepareSubscriberSync, and the Out allowlist follows
	// node lifecycle events only.
	return bearer, nil
}

// writeDraftCredentialsTx materializes exactly the draft credentials: a kept
// Line keeps its row (reactivated when it was dropped), a new Line gets the
// minted row, and a dropped Line is only deactivated.
func writeDraftCredentialsTx(tx *sql.Tx, draft SubscriptionDraft, now time.Time) error {
	keep := make(map[string]struct{}, len(draft.Credentials))
	for _, credential := range draft.Credentials {
		keep[credential.NodeID] = struct{}{}
		var active int
		err := tx.QueryRow(`SELECT active FROM proxy_credentials WHERE id=?`, credential.ID).Scan(&active)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err = tx.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at) VALUES(?,?,?,?,1,?,?)`,
				credential.ID, credential.SubscriberID, credential.NodeID, credential.UUID, now.Unix(), now.Unix()); err != nil {
				return errors.New("CREDENTIAL_CREATE_FAILED")
			}
		case err != nil:
			return errors.New("DATABASE_UNAVAILABLE")
		case active != 1:
			if _, err = tx.Exec(`UPDATE proxy_credentials SET active=1, updated_at=? WHERE id=?`, now.Unix(), credential.ID); err != nil {
				return errors.New("CREDENTIAL_UPDATE_FAILED")
			}
		}
	}
	if _, err := deactivateDroppedCredentials(tx, draft.Subscriber.ID, keep, now.Unix()); err != nil {
		return err
	}
	return nil
}

// SaveResult is the outcome of one wizard save: the preview the caller renders,
// the subscriber it applied to, the one-time bearer of a create and whether the
// save wrote anything at all.
type SaveResult struct {
	Preview      SelectionPreview
	SubscriberID string
	// Bearer is the plaintext subscription token of a create. It is filled only
	// for the single response that issues it.
	Bearer string
	// Saved is true only when the artifact was approved and persisted.
	Saved bool
}

// ApproveSubscriptionSelection is the wizard's save: it gates the draft, and
// only an approved artifact is written. A blocked draft writes nothing at all,
// so the page can always say "not saved" honestly.
func (s *Store) ApproveSubscriptionSelection(ctx context.Context, subscriberID, displayName string, spec SelectionSpec, verifier PublishVerifier, now time.Time) (SaveResult, error) {
	draft, err := s.DraftSubscriptionSelection(subscriberID, displayName, spec)
	if err != nil {
		return SaveResult{}, err
	}
	result := SaveResult{Preview: s.composeAndGate(ctx, draft.inputs, verifier, draft.diagnostics), SubscriberID: draft.Subscriber.ID}
	if result.Preview.Blocking() {
		return result, nil
	}
	bearer, err := s.SaveSubscriptionDraft(draft, result.Preview.ContentID, now)
	if err != nil {
		return SaveResult{}, err
	}
	result.Bearer, result.Saved = bearer, true
	return result, nil
}

// selectionInputs is the pure composer's input set for one selection.
type selectionInputs struct {
	Lines   []subscription.ComposeLine
	Out     []subscription.ComposeOut
	Rules   []subscription.ComposeRule
	Network []subscription.ComposeNetwork
}

// selectionOutTx resolves one Out into its operator-visible dial parameters.
// The link credential stays in out_settings: a subscription never carries it.
func selectionOutTx(tx *sql.Tx, outID string) (subscription.ComposeOut, error) {
	var role, displayName, server string
	var port int
	err := tx.QueryRow(`SELECT n.role, n.display_name, s.server, s.port
	  FROM nodes n JOIN out_settings s ON s.node_id=n.id WHERE n.id=?`, outID).
		Scan(&role, &displayName, &server, &port)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the out has no transport")
	}
	if err != nil {
		return subscription.ComposeOut{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return subscription.ComposeOut{}, errors.New("OUT_ROLE_INVALID: only out nodes can be selected")
	}
	return subscription.ComposeOut{OutID: outID, DisplayName: displayName, Server: server, Port: port}, nil
}

// selectionRulesTx resolves the pinned rule revisions into composer rules with
// their pinned artifacts.
//
// The pin source comes from the active server policy revision, which is the
// deployment's single artifact lock. A rule that needs an artifact the active
// revision does not pin is refused by the composer with
// COMPOSE_RULESET_UNPINNED, so a subscription can never fetch an unpinned file.
func selectionRulesTx(tx *sql.Tx, revisions []RuleRevision) ([]subscription.ComposeRule, error) {
	if len(revisions) == 0 {
		return []subscription.ComposeRule{}, nil
	}
	pins, err := activePolicyPinsTx(tx)
	if err != nil {
		return nil, err
	}
	out := make([]subscription.ComposeRule, 0, len(revisions))
	for _, revision := range revisions {
		var name, action, kind, raw string
		err := tx.QueryRow(`SELECT name, action, matcher_kind, matcher_value FROM policy_rules WHERE stable_key=? AND version=?`,
			revision.StableKey, revision.Version).Scan(&name, &action, &kind, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("RULE_NOT_FOUND: a selected rule revision no longer exists")
		}
		if err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, errors.New("RULE_INVALID: a stored rule is not readable")
		}
		out = append(out, subscription.ComposeRule{
			StableKey: revision.StableKey,
			Version:   revision.Version,
			Action:    subscription.Action(action),
			Kind:      subscription.MatcherKind(kind),
			Values:    values,
			Pins:      pinsForRule(subscription.MatcherKind(kind), values, pins),
		})
	}
	return out, nil
}

// activePolicyPinsTx reads the pinned artifacts of the active server policy
// revision. No active revision means no pins, so a geo/ruleset rule is refused
// instead of rendering an unversioned reference.
func activePolicyPinsTx(tx *sql.Tx) (compiler.RuleSetPins, error) {
	record, _, err := activePolicyIntentTx(tx, PolicyLayerServer)
	if err != nil {
		if isPolicyNotFound(err) {
			return compiler.RuleSetPins{}, nil
		}
		return compiler.RuleSetPins{}, err
	}
	return decodePolicyPins(record.Pins)
}

// pinsForRule maps the artifact pins of the active revision onto one composer
// rule, keyed by the geo code or the remote tag the rule names.
func pinsForRule(kind subscription.MatcherKind, values []string, pins compiler.RuleSetPins) map[string]subscription.RuleSetPin {
	out := make(map[string]subscription.RuleSetPin, len(values))
	for _, value := range values {
		var pin compiler.RulesetPin
		var ok bool
		switch kind {
		case subscription.MatcherGeoSite:
			pin, ok = pins.GeoSite[value]
		case subscription.MatcherGeoIP:
			pin, ok = pins.GeoIP[value]
		case subscription.MatcherRuleSet:
			pin, ok = pins.Remote[value]
		default:
			continue
		}
		if !ok {
			continue
		}
		out[value] = subscription.RuleSetPin{Source: pin.Source, Version: pin.Version, SHA256: pin.SHA256}
	}
	return out
}

// composeAndGate runs the pure composer and then the kernel gate. A blocking
// composer finding stops before any binary runs.
func (s *Store) composeAndGate(ctx context.Context, inputs selectionInputs, verifier PublishVerifier, diagnostics []subscription.Diagnostic) SelectionPreview {
	documents, composeDiagnostics := subscription.ComposeSubscription(inputs.Lines, inputs.Out, inputs.Rules, inputs.Network)
	diagnostics = append(diagnostics, composeDiagnostics...)
	preview := SelectionPreview{Diagnostics: diagnostics, Documents: documents, ContentID: documents.ContentID}
	if hasBlockingDiagnostic(diagnostics) {
		return preview
	}
	if verifier == nil {
		preview.Diagnostics = append(preview.Diagnostics, subscription.Diagnostic{
			Level: subscription.DiagnosticBlocking, Code: CodeComposeGateUnavailable,
			Detail: "缺少内核门禁，无法批准订阅产物",
		})
		return preview
	}
	if _, err := verifier.CheckSingBox(ctx, documents.SingBox); err != nil {
		preview.Diagnostics = append(preview.Diagnostics, subscription.Diagnostic{
			Level: subscription.DiagnosticBlocking, Code: CodeComposeGateFailed,
			Detail: "sing-box 拒绝组装后的客户端文档",
		})
		return preview
	}
	preview.Gates = append(preview.Gates, "sing-box")
	if _, err := verifier.CheckMihomo(ctx, documents.Mihomo); err != nil {
		if isMihomoMissing(err) {
			// An absent Mihomo binary is not a failure of the artifact: the
			// pinned client is optional deployment configuration. It is still
			// reported, so "mihomo was not checked" is never mistaken for
			// "mihomo accepted the document".
			preview.MihomoSkipped = true
			preview.Diagnostics = append(preview.Diagnostics, subscription.Diagnostic{
				Level: subscription.DiagnosticReminder, Code: CodeComposeMihomoSkipped,
				Detail: "未安装固定版本的 Mihomo，本次只校验 sing-box 文档",
			})
		} else {
			preview.Diagnostics = append(preview.Diagnostics, subscription.Diagnostic{
				Level: subscription.DiagnosticBlocking, Code: CodeComposeGateFailed,
				Detail: "Mihomo 拒绝组装后的客户端文档",
			})
			return preview
		}
	} else {
		preview.Gates = append(preview.Gates, "mihomo")
	}
	preview.Approved = true
	return preview
}

// isMihomoMissing recognises the gate's own "binary is absent" refusal. Only
// that code downgrades the Mihomo check; a version mismatch or a rejected
// document stays a blocking failure.
func isMihomoMissing(err error) bool {
	return strings.HasPrefix(err.Error(), node.CodePublishMihomoMissing)
}

// SubscriptionArtifact re-composes one subscriber's saved selection and returns
// the documents together with the approved digest. It is the download's single
// source of truth: a saved selection without an approved artifact, or one whose
// recomposition no longer matches the approved digest, is refused.
//
// The recomposition reads the edges and the active credentials of the saved
// selection. It never mints anything, so a missing credential is a refusal
// instead of a silently different document.
func (s *Store) SubscriptionArtifact(subscriberID string) (subscription.ComposeDocuments, string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return subscription.ComposeDocuments{}, "", errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.ComposeDocuments{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return subscription.ComposeDocuments{}, "", err
	}
	selection, err := readSelectionTx(tx, subscriberID)
	if err != nil {
		return subscription.ComposeDocuments{}, "", err
	}
	inputs := selectionInputs{}
	for _, line := range selection.Ordered().Lines {
		lineRecord, err := downloadLineTx(tx, line.NodeID)
		if err != nil {
			return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": a selected Line is no longer available")
		}
		credential, err := storedCredentialTx(tx, subscriberID, line.NodeID)
		if err != nil {
			return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": a selected Line has no active credential")
		}
		inputs.Lines = append(inputs.Lines, subscription.ComposeLine{Line: publicLine(lineRecord), Credential: credential})
	}
	if selection.Out != nil {
		out, err := selectionOutTx(tx, selection.Out.OutID)
		if err != nil {
			return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": the selected Out is no longer available")
		}
		inputs.Out = []subscription.ComposeOut{out}
	}
	revisions := make([]RuleRevision, 0, len(selection.Rules))
	for _, rule := range selection.Ordered().Rules {
		revisions = append(revisions, RuleRevision{StableKey: rule.StableKey, Version: rule.Version})
	}
	rules, err := selectionRulesTx(tx, revisions)
	if err != nil {
		return subscription.ComposeDocuments{}, "", err
	}
	inputs.Rules = rules
	for _, device := range selection.Ordered().Networks {
		var name string
		if err := tx.QueryRow(`SELECT display_name FROM mesh_devices WHERE id=?`, device.DeviceID).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": a selected mesh device no longer exists")
			}
			return subscription.ComposeDocuments{}, "", errors.New("DATABASE_UNAVAILABLE")
		}
		inputs.Network = append(inputs.Network, subscription.ComposeNetwork{DeviceID: device.DeviceID, DisplayName: name})
	}
	var artifactID string
	var approved int
	err = tx.QueryRow(`SELECT artifact_id, artifact_approved FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).
		Scan(&artifactID, &approved)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactNotApproved + ": the selection was never approved")
	}
	if err != nil {
		return subscription.ComposeDocuments{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if err := tx.Commit(); err != nil {
		return subscription.ComposeDocuments{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if approved != 1 || artifactID == "" {
		return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactNotApproved + ": the selection was never approved")
	}
	documents, diagnostics := subscription.ComposeSubscription(inputs.Lines, inputs.Out, inputs.Rules, inputs.Network)
	if hasBlockingDiagnostic(diagnostics) {
		return subscription.ComposeDocuments{}, "", errors.New(CodeComposeGateFailed + ": the saved selection no longer composes")
	}
	if artifactID != documents.ContentID {
		return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": the composed artifact no longer matches the approved one")
	}
	return documents, artifactID, nil
}

// hasBlockingDiagnostic reports whether one diagnostic set refuses the artifact.
func hasBlockingDiagnostic(diagnostics []subscription.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Level == subscription.DiagnosticBlocking {
			return true
		}
	}
	return false
}
