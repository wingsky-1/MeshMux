package store

// Subscription draft, preview, approval and artifact read-back (ADR-0008 §7).
//
// One subscription artifact is built in one order and one only:
//
//	draft    (identities + credentials, read-only)
//	preview  (pure composer + kernel gate, read-only)
//	approve  (draft -> preview -> save, only an approved digest is written)
//	save     (one transaction: edges, credentials, snapshot + digest)
//	artifact (download: re-compose from the stored selection, compare digest)
//
// The five steps are separate functions so a caller can stop at any of them:
// the wizard's preview stops after `preview`, and a blocked save stops there
// too — nothing is written at all. The digest depends on the VLESS UUIDs, so
// the draft mints them before the gate and the save writes them unchanged; that
// is why an approved digest can never disagree with the credentials the
// download later re-derives.
//
// The composed bytes are never stored. The snapshot stores the selection and the
// digest of the approved artifact; a download re-composes from the same
// selection and compares the digest, so a stored byte could never silently drift
// from the choice that produced it.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
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
// anything.
//
// Flow: Normalize (shape, dedupe) -> one read transaction -> subscriber identity
// (new identity for the create form, stored record for an existing one) ->
// reference validation -> same-Line Out agreement -> credential material ->
// composer inputs -> snapshot model. Nothing is INSERTed, UPDATEd or DELETEd.
func (s *Store) DraftSubscriptionSelection(subscriberID, displayName string, spec SelectionSpec) (SubscriptionDraft, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return SubscriptionDraft{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return SubscriptionDraft{}, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	draft, err := buildSubscriptionDraftTx(tx, subscriberID, displayName, spec)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	if err := tx.Commit(); err != nil {
		return SubscriptionDraft{}, errors.New(CodeDatabaseUnavailable)
	}
	return draft, nil
}

// buildSubscriptionDraftTx is the one draft builder. It never writes. The
// spec must already be normalized; a second Normalize here would silently
// reorder a caller's positions.
func buildSubscriptionDraftTx(tx *sql.Tx, subscriberID, displayName string, spec SelectionSpec) (SubscriptionDraft, error) {
	draft := SubscriptionDraft{}
	diagnostics := make([]subscription.Diagnostic, 0, 4)

	// Layer 2 is strict: an unusable identity shape is an error, not a
	// diagnostic, so a caller can never mistake a malformed request for a
	// rendered finding.
	if strings.TrimSpace(subscriberID) == "" {
		sub, err := subscription.NewSubscriber(displayName)
		if err != nil {
			return SubscriptionDraft{}, err
		}
		draft.Subscriber, draft.Create = sub, true
	} else {
		if err := subscription.ValidateID(subscriberID); err != nil {
			return SubscriptionDraft{}, errSubscriberIDInvalid()
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

	// Layer 2: every reference must exist and be selectable.
	for _, nodeID := range spec.LineIDs {
		if err := validateLineTx(tx, nodeID); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	if err := validateSelectionOutTx(tx, spec.OutID); err != nil {
		return SubscriptionDraft{}, err
	}
	for _, revision := range spec.Rules {
		if err := validateRuleRevisionTx(tx, revision); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	for _, deviceID := range spec.NetworkIDs {
		if err := validateSelectionDeviceTx(tx, deviceID); err != nil {
			return SubscriptionDraft{}, err
		}
	}
	// The same-Line Out rule applies to a create as well: the new subscriber is
	// not persisted yet, so every existing row on these Lines is a potential
	// conflict and must already agree with the submitted Out choice.
	if err := enforceSameLineOutTx(tx, draft.Subscriber.ID, spec.LineIDs, spec.OutID); err != nil {
		return SubscriptionDraft{}, err
	}

	// The credentials are minted now and written unchanged after the gate, so
	// the approved digest is computed over the exact UUIDs the download serves.
	credentials := make([]subscription.Credential, 0, len(spec.LineIDs))
	for _, nodeID := range spec.LineIDs {
		credential, err := reusableCredentialTx(tx, draft.Subscriber.ID, nodeID, draft.Create)
		if err != nil {
			return SubscriptionDraft{}, err
		}
		credentials = append(credentials, credential)
	}
	draft.Credentials = credentials

	// Layer 3 inputs: the composer input set plus whatever the read already
	// knows is unusable.
	assembly, err := assembleSelectionTx(tx, spec.LineIDs, credentials, spec.OutID, spec.Rules, spec.NetworkIDs)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	draft.inputs = assembly.inputs
	draft.diagnostics = append(diagnostics, assembly.diagnostics...)

	// The snapshot model is built from the same order the composer used.
	selection, err := buildSelectionTx(tx, draft.Subscriber.ID, draft.Create, spec)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	draft.Selection = selection
	return draft, nil
}

// buildSelectionTx builds the snapshot identity of one canonical selection: the
// next version, the ordered references and the informational current revisions.
// It reads, it never writes; the version is only committed by a real save.
func buildSelectionTx(tx *sql.Tx, subscriberID string, creating bool, spec SelectionSpec) (subscription.Selection, error) {
	selection := subscription.Selection{SubscriberID: subscriberID}
	if !creating {
		stored, err := storedSelectionVersionTx(tx, subscriberID)
		if err != nil {
			return subscription.Selection{}, err
		}
		selection.Version = stored
	}
	selection.Version++
	for position, nodeID := range spec.LineIDs {
		revision, err := latestCandidateRevisionTx(tx, nodeID)
		if err != nil {
			return subscription.Selection{}, err
		}
		selection.Lines = append(selection.Lines, subscription.SelectionLine{NodeID: nodeID, Position: position, LineRevision: revision})
	}
	if spec.OutID != "" {
		revision, err := latestCandidateRevisionTx(tx, spec.OutID)
		if err != nil {
			return subscription.Selection{}, err
		}
		selection.Out = &subscription.SelectionOut{OutID: spec.OutID, Position: 0, OutRevision: revision}
	}
	for position, revision := range spec.Rules {
		selection.Rules = append(selection.Rules, subscription.SelectionRule{StableKey: revision.StableKey, Version: revision.Version, Position: position})
	}
	for position, deviceID := range spec.NetworkIDs {
		selection.Networks = append(selection.Networks, subscription.SelectionNetwork{DeviceID: deviceID, Position: position})
	}
	return selection, nil
}

// latestCandidateRevisionTx reads the newest stored candidate revision of one
// node, or zero when it has none. The value is informational for a Line (its
// transport is not versioned by the subscription) and is recorded honestly.
func latestCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	var revision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New(CodeDatabaseUnavailable)
	}
	return revision, nil
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
		return subscription.Credential{}, errors.New(CodeDatabaseUnavailable)
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
			return subscription.Credential{}, errors.New(CodeDatabaseUnavailable)
		}
	}
	credential, err := subscription.NewCredential(subscriberID, nodeID)
	if err != nil {
		return subscription.Credential{}, errCredentialCreateFailed
	}
	return credential, nil
}

// PreviewDraftSelection composes and gates one draft without writing anything.
//
// Flow: pure composer -> blocking check -> kernel gate (sing-box required,
// mihomo optional) -> approved/digest. A blocked composer never runs a binary.
func (s *Store) PreviewDraftSelection(draft SubscriptionDraft, verifier PublishVerifier) SelectionPreview {
	return runComposeGate(context.Background(), draft.inputs, verifier, draft.diagnostics)
}

// SaveSubscriptionDraft writes one draft in a single transaction: the subscriber
// and its token (create only), the four edge groups, the credentials and the
// snapshot with the approved artifact digest. It returns the plaintext bearer
// exactly once for a create.
//
// artifactID may be empty, which records a saved-but-unapproved selection; the
// download refuses such a snapshot instead of falling back to older bytes.
func (s *Store) SaveSubscriptionDraft(draft SubscriptionDraft, artifactID string, now time.Time) (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	bearer := ""
	if draft.Create {
		if _, err = tx.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at) VALUES(?,?,?,1,?,?)`,
			draft.Subscriber.ID, draft.Subscriber.DisplayName, string(draft.Subscriber.State), now.Unix(), now.Unix()); err != nil {
			return "", errSubscriberCreateFailed
		}
		record, token, tErr := subscription.NewSubscriptionToken(draft.Subscriber.ID)
		if tErr != nil {
			return "", errTokenCreateFailed
		}
		if _, err = tx.Exec(`INSERT INTO subscription_tokens(id, subscriber_id, token_hash, revoked, created_at, revoked_at) VALUES(?,?,?,0,?,0)`,
			record.ID, record.SubscriberID, record.Hash, now.Unix()); err != nil {
			return "", errTokenCreateFailed
		}
		bearer = token
	}
	if err := writeSelectionEdgesTx(tx, draft.Selection, now); err != nil {
		return "", err
	}
	if err := writeDraftCredentialsTx(tx, draft, now); err != nil {
		return "", err
	}
	if err := writeSnapshotTx(tx, draft.Selection, artifactID, now); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`UPDATE subscribers SET revision=revision+1, updated_at=? WHERE id=?`, now.Unix(), draft.Subscriber.ID); err != nil {
		return "", errSubscriberUpdateFailed
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New(CodeDatabaseUnavailable)
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
				return errCredentialCreateFailed
			}
		case err != nil:
			return errors.New(CodeDatabaseUnavailable)
		case active != 1:
			if _, err = tx.Exec(`UPDATE proxy_credentials SET active=1, updated_at=? WHERE id=?`, now.Unix(), credential.ID); err != nil {
				return errCredentialUpdateFailed
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

// ApproveSubscriptionSelection is the wizard's save: draft, gate, and write only
// an approved artifact. A blocked draft writes nothing at all, so the page can
// always say "not saved" honestly.
//
// It is the composition of three public steps, and each is also callable on its
// own; this function adds no fourth behaviour.
func (s *Store) ApproveSubscriptionSelection(ctx context.Context, subscriberID, displayName string, spec SelectionSpec, verifier PublishVerifier, now time.Time) (SaveResult, error) {
	draft, err := s.DraftSubscriptionSelection(subscriberID, displayName, spec)
	if err != nil {
		return SaveResult{}, err
	}
	result := SaveResult{Preview: runComposeGate(ctx, draft.inputs, verifier, draft.diagnostics), SubscriberID: draft.Subscriber.ID}
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

// runComposeGate runs the pure composer and then the kernel gate. A blocking
// composer finding stops before any binary runs. It is a free function because
// it holds no store state: the draft already carries every input.
func runComposeGate(ctx context.Context, inputs selectionInputs, verifier PublishVerifier, diagnostics []subscription.Diagnostic) SelectionPreview {
	documents, composeDiagnostics := subscription.ComposeSubscription(inputs.Lines, inputs.Out, inputs.Rules, inputs.Network)
	diagnostics = append(diagnostics, composeDiagnostics...)
	preview := SelectionPreview{Diagnostics: diagnostics, Documents: documents, ContentID: documents.ContentID}
	if hasBlockingDiagnostic(diagnostics) {
		return preview
	}
	if verifier == nil {
		preview.Diagnostics = append(preview.Diagnostics, blockingDiagnostic(CodeComposeGateUnavailable, "缺少内核门禁，无法批准订阅产物"))
		return preview
	}
	if _, err := verifier.CheckSingBox(ctx, documents.SingBox); err != nil {
		preview.Diagnostics = append(preview.Diagnostics, blockingDiagnostic(CodeComposeGateFailed, "sing-box 拒绝组装后的客户端文档"))
		return preview
	}
	preview.Gates = append(preview.Gates, kernelSingBox)
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
			preview.Diagnostics = append(preview.Diagnostics, blockingDiagnostic(CodeComposeGateFailed, "Mihomo 拒绝组装后的客户端文档"))
			return preview
		}
	} else {
		preview.Gates = append(preview.Gates, kernelMihomo)
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
// Flow: validate id -> read subscriber, selection and approved digest in one
// transaction -> resolve inputs from STORED credentials (never mint) -> commit
// -> pure compose -> compare digest. Any missing record is a refusal, never a
// silently different document.
func (s *Store) SubscriptionArtifact(subscriberID string) (subscription.ComposeDocuments, string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return subscription.ComposeDocuments{}, "", errSubscriberIDInvalid()
	}
	stored, err := s.savedArtifactSelection(subscriberID)
	if err != nil {
		return subscription.ComposeDocuments{}, "", err
	}
	documents, diagnostics := subscription.ComposeSubscription(stored.inputs.Lines, stored.inputs.Out, stored.inputs.Rules, stored.inputs.Network)
	if hasBlockingDiagnostic(diagnostics) {
		return subscription.ComposeDocuments{}, "", errors.New(CodeComposeGateFailed + ": the saved selection no longer composes")
	}
	if stored.artifactID != documents.ContentID {
		return subscription.ComposeDocuments{}, "", errors.New(CodeArtifactDrift + ": the composed artifact no longer matches the approved one")
	}
	return documents, stored.artifactID, nil
}

// savedArtifact is the read half of one download: composer inputs and the
// approved digest of the snapshot that recorded them.
type savedArtifact struct {
	inputs     selectionInputs
	artifactID string
}

// savedArtifactSelection reads one subscriber's stored selection into composer
// inputs inside one transaction. It never writes and never mints a credential.
func (s *Store) savedArtifactSelection(subscriberID string) (savedArtifact, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return savedArtifact{}, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return savedArtifact{}, err
	}
	selection, err := readSelectionTx(tx, subscriberID)
	if err != nil {
		return savedArtifact{}, err
	}
	credentials := make([]subscription.Credential, 0, len(selection.Lines))
	for _, line := range selection.Ordered().Lines {
		credential, err := storedCredentialTx(tx, subscriberID, line.NodeID)
		if err != nil {
			return savedArtifact{}, errors.New(CodeArtifactDrift + ": a selected Line has no active credential")
		}
		credentials = append(credentials, credential)
	}
	revisions := make([]RuleRevision, 0, len(selection.Rules))
	for _, rule := range selection.Ordered().Rules {
		revisions = append(revisions, RuleRevision{StableKey: rule.StableKey, Version: rule.Version})
	}
	deviceIDs := make([]string, 0, len(selection.Networks))
	for _, device := range selection.Ordered().Networks {
		deviceIDs = append(deviceIDs, device.DeviceID)
	}
	assembly, err := assembleSelectionTx(tx, lineIDsOf(selection), credentials, outIDOf(selection), revisions, deviceIDs)
	if err != nil {
		return savedArtifact{}, artifactAssemblyError(err)
	}
	if hasBlockingDiagnostic(assembly.diagnostics) {
		return savedArtifact{}, errors.New(CodeArtifactDrift + ": a selected reference is no longer available")
	}
	artifactID, hasSnapshot, err := snapshotArtifactTx(tx, subscriberID)
	if err != nil {
		return savedArtifact{}, err
	}
	if err := tx.Commit(); err != nil {
		return savedArtifact{}, errors.New(CodeDatabaseUnavailable)
	}
	if !hasSnapshot || artifactID == "" {
		return savedArtifact{}, errors.New(CodeArtifactNotApproved + ": the selection was never approved")
	}
	return savedArtifact{inputs: assembly.inputs, artifactID: artifactID}, nil
}

// artifactAssemblyError maps a read failure of the artifact path onto the
// download's stable vocabulary: a saved record that no longer resolves is drift,
// a database failure stays a database failure.
func artifactAssemblyError(err error) error {
	if ErrorCodeOf(err) == CodeDatabaseUnavailable {
		return err
	}
	return errors.New(CodeArtifactDrift + ": a selected reference is no longer available")
}

// lineIDsOf returns the ordered Line ids of one selection.
func lineIDsOf(selection subscription.Selection) []string {
	ids := make([]string, 0, len(selection.Lines))
	for _, line := range selection.Ordered().Lines {
		ids = append(ids, line.NodeID)
	}
	return ids
}

// outIDOf returns the selected egress id, or "" for a direct subscription.
func outIDOf(selection subscription.Selection) string {
	if selection.Out == nil {
		return ""
	}
	return selection.Out.OutID
}

// blockingDiagnostic builds one blocking finding. The helper exists so every
// blocking diagnostic in this package has the same shape.
func blockingDiagnostic(code, detail string) subscription.Diagnostic {
	return subscription.Diagnostic{Level: subscription.DiagnosticBlocking, Code: code, Detail: detail}
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
