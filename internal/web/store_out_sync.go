package web

// Out synchronization coordinates the optional Out node with the Lines that are
// allowed to use it as an egress.
//
// There is exactly one authorization source: the Lines the Hub has enrolled,
// paired and configured with a literal egress address. An Out never infers its
// own allowlist, and the managed nft table is never its own expectation. The Hub
// derives the source list from the stored Line, publishes it in the frozen
// four-task chain, and treats a healthy readback of a task that carried exactly
// that list as the only proof that the Out data plane matches the authorization.
//
// The same asymmetry as the subscriber synchronization applies: a Line whose Out
// path is not authorized and confirmed yet is not published, because publishing
// it would hand clients an egress that drops them. A retired Line is removed from
// the Out allowlist and the Out is republished; until that chain is confirmed the
// pair reports a transition, never healthy.
//
// Evidence levels are deliberately narrow:
//   - "the Hub authorized this source" is proven by the immutable candidate and
//     the task parameters of an Out chain;
//   - "the Agent applied exactly that set" is proven by a healthy readback of a
//     task that carried the set (the Agent compares it with its applied state and
//     fails OUT_ACL_SOURCE_MISMATCH on any difference);
//   - "this address really is the Line's egress address on the wire" is NOT
//     proven by any Hub readback. The Hub only has the stored Line address, so it
//     refuses to authorize anything that is not a literal IP instead of guessing.
//
// Retry and rollback stay explicit. An unchanged snapshot is never republished by
// an automatic poll: the operator retries it through retryOutSync, and the host
// keeps its last-known-good configuration (the Agent state file) as the rollback
// target.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// maxOutAllowlistSources mirrors the frozen protocol and Agent bound. One Out is
// bound to at most one Line today, so this is a defensive ceiling that keeps the
// derived list inside the same bounded envelope the Agent accepts.
const maxOutAllowlistSources = 256

// The Out authorization states the Hub can prove.
const (
	// outSyncHealthy: the published allowlist is the desired one and the Agent
	// readback confirmed it for the current revision.
	outSyncHealthy = "healthy"
	// outSyncVerifying: a chain is in flight, or the last one ended with the
	// expected supersession code.
	outSyncVerifying = "verifying"
	// outSyncPending: the desired authorization has not been published yet.
	outSyncPending = "pending"
	// outSyncPartial: the last chain ended in a terminal failure, or the Hub
	// cannot authorize the bound Line at all.
	outSyncPartial = "partial"
)

// The Line egress states derived from the binding plus the Out authorization.
const (
	// lineEgressDirect: no enabled Out binding, the Line egresses directly.
	lineEgressDirect = "direct"
	// lineEgressHealthy: every bound Out authorized this Line and confirmed it.
	lineEgressHealthy = "healthy"
	// lineEgressVerifying: the authorization is being applied or read back.
	lineEgressVerifying = "verifying"
	// lineEgressPartial: a bound Out cannot authorize this Line.
	lineEgressPartial = "partial"
)

// outAclSourceMismatchCode is the Agent readback code for a task whose allowlist
// differs from the applied one. Across two chains that is the expected
// retire-then-verify transition, so the Hub reports verifying and never
// republishes the identical snapshot on its own.
const outAclSourceMismatchCode = "OUT_ACL_SOURCE_MISMATCH"

// The stable codes the Hub itself reports for a Line it cannot authorize.
const (
	// codeLineEgressUnverified marks a configured Line whose transport address
	// is a host name: the Hub has no proof of the source address the Out sees.
	codeLineEgressUnverified = "LINE_EGRESS_UNVERIFIED"
	// codeLineNotAuthorized marks a bound Line without a current paired
	// identity (never paired, reissuing, or revoked).
	codeLineNotAuthorized = "LINE_NOT_AUTHORIZED"
	// codeOutSyncInProgress and codeOutSyncPending are the transition codes.
	codeOutSyncInProgress = "OUT_SYNC_IN_PROGRESS"
	codeOutSyncPending    = "OUT_SYNC_PENDING"
)

// outDrainOutcome classifies what one Out drain attempt did. It lets the retire
// path tell "nothing to reclaim" apart from "reclaim is blocked", which the
// operator has to see.
type outDrainOutcome int

const (
	// outDrainNoop: the published authorization already equals the desired one,
	// or an unchanged unconfirmed snapshot waits for an explicit retry.
	outDrainNoop outDrainOutcome = iota
	// outDrainPublished: a new immutable revision and its fixed chain were
	// enqueued in the caller's transaction.
	outDrainPublished
	// outDrainDeferred: a publish is required but cannot happen yet (a chain is
	// in flight, or the Out is offline). The change stays pending.
	outDrainDeferred
)

// OutEgressReadback is the Hub-side dual readback of one Line that egresses
// through an Out. It never mutates state and never returns a secret.
//
// The four fields mirror the four things the pair has to prove separately. A
// healthy allowlist alone is not an egress proof, and a healthy Line inbound
// alone says nothing about the Out guard.
type OutEgressReadback struct {
	LineID string `json:"line_id"`
	OutID  string `json:"out_id"`
	// Allowlist is the Out ACL readback: the published source set is the
	// authorized one and the Agent confirmed it.
	Allowlist string `json:"allowlist"`
	// AllowlistCode is the stable reason when Allowlist is not healthy.
	AllowlistCode string `json:"allowlist_code,omitempty"`
	// Inbound is the Line inbound readback: the Line proved the exact desired
	// snapshot, which includes its listener and user set.
	Inbound string `json:"inbound"`
	// InboundCode is the stable reason when Inbound is not healthy.
	InboundCode string `json:"inbound_code,omitempty"`
	// Reality is true only when the confirmed Line candidate carries the
	// REALITY transport block that its stored Line settings describe.
	Reality bool `json:"reality"`
	// FinalEgress is healthy only when the allowlist and the inbound are both
	// healthy (or the Line egresses directly and its inbound is healthy).
	FinalEgress string `json:"final_egress"`
	// FinalEgressCode is the stable reason when FinalEgress is not healthy.
	FinalEgressCode string `json:"final_egress_code,omitempty"`
	// ConfirmedRevision and ConfirmedDigest are the Hub-side rollback pointer:
	// the newest revision whose chain the node fully confirmed for the Line
	// (and, for an Out-bound Line, whose allowlist was confirmed too). Zero
	// means nothing was ever confirmed, so a rollback has no target yet.
	ConfirmedRevision int64  `json:"confirmed_revision"`
	ConfirmedDigest   string `json:"confirmed_digest,omitempty"`
	// RetryPending is the retry pointer: true when the next step is the
	// explicit retry (retryOutSync / subscriber retry), never an automatic
	// republish of an unchanged snapshot.
	RetryPending bool `json:"retry_pending"`
}

// outAllowlistSource canonicalizes one authorized source. It accepts only a
// literal address or an already aligned CIDR, so the value the Hub publishes is
// exactly the value the Agent renders: the Agent masks an unmasked prefix
// silently, which would authorize a wider network than the Hub named.
//
// A zero-length prefix is rejected here as well: it would turn the Out guard back
// into an allow-all rule.
func outAllowlistSource(raw string) (string, error) {
	if raw == "" || len(raw) > 64 || strings.TrimSpace(raw) != raw {
		return "", errors.New("OUT_ALLOWLIST_INVALID: an authorized source must be one IP or CIDR")
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		addr := prefix.Addr()
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() {
			return "", errors.New("OUT_ALLOWLIST_INVALID: an authorized source must be a plain unicast address")
		}
		if prefix.Bits() == 0 {
			return "", errors.New("OUT_ALLOWLIST_INVALID: a zero-length prefix would disable default deny")
		}
		if prefix.Masked() != prefix {
			// Never widen silently. The caller named a network with host bits
			// set; the Agent would mask it and authorize more addresses than the
			// Hub declared.
			return "", errors.New("OUT_ALLOWLIST_INVALID: an unaligned prefix would authorize a wider network than declared")
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return "", errors.New("OUT_ALLOWLIST_INVALID: an authorized source must be a plain unicast address")
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// outBindingTx is the transaction-scoped projection of GetOutBinding with the
// same three states, so the publication path never opens a second connection.
//
// A missing row is folded into the zero binding (no authorization), which is the
// deliberate T1 contract: "never configured" must not be an error here. Every
// other read failure, including DATABASE_UNAVAILABLE, propagates, so an
// unreadable binding is never mistaken for "no Out".
func outBindingTx(tx *sql.Tx, outID string) (OutBinding, error) {
	if !validBindingNodeID(outID) {
		return OutBinding{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	binding := OutBinding{OutID: outID}
	var (
		lineID  sql.NullString
		enabled int
	)
	err := tx.QueryRow(`SELECT line_id, enabled, updated_at FROM out_bindings WHERE out_id=?`, outID).
		Scan(&lineID, &enabled, &binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return binding, nil
	}
	if err != nil {
		return OutBinding{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if lineID.Valid {
		binding.LineID = lineID.String
	}
	binding.Enabled = enabled == 1
	return binding, nil
}

// lineEgressSourceTx reports whether one Line is a verifiable source for an Out
// and returns the exact source to publish.
//
// authorized=false means the Line cannot be an egress source right now: it has no
// stored transport, or it has no current paired identity (never paired,
// reissuing, or revoked). Such a Line contributes nothing to the allowlist
// instead of an address the Hub cannot vouch for.
//
// A configured, paired Line addressed by a DNS name is an error: the Hub has no
// proof of the address the Out will observe, and resolving it here would make the
// allowlist depend on DNS at publish time. The caller reports that explicitly
// instead of authorizing the wrong host.
func lineEgressSourceTx(tx *sql.Tx, lineID string) (string, bool, error) {
	if err := subscription.ValidateID(lineID); err != nil {
		return "", false, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, errors.New("LINE_NOT_FOUND: unknown line node")
	}
	if err != nil {
		return "", false, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "edge" {
		return "", false, errors.New("LINE_ROLE_INVALID: only edge nodes can be an out source")
	}
	var server string
	err = tx.QueryRow(`SELECT server FROM line_settings WHERE node_id=?`, lineID).Scan(&server)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.New("DATABASE_UNAVAILABLE")
	}
	var identities int
	if err := tx.QueryRow(`SELECT count(*) FROM node_identities WHERE node_id=? AND revoked=0`, lineID).Scan(&identities); err != nil {
		return "", false, errors.New("DATABASE_UNAVAILABLE")
	}
	if identities != 1 {
		return "", false, nil
	}
	if _, err := netip.ParseAddr(server); err != nil {
		return "", false, errors.New(codeLineEgressUnverified + ": the line transport address is a host name, so the hub cannot authorize a verifiable egress source")
	}
	source, err := outAllowlistSource(server)
	if err != nil {
		return "", false, err
	}
	return source, true, nil
}

// outAuthorizationTx is the single derivation of an Out's authorization.
//
// Only an enabled binding to a verifiable Line contributes a source. A disabled,
// unbound or never configured Out derives an explicit empty list: the Out stays
// default-deny, which is the fail-closed state, and the caller publishes that
// empty list instead of omitting the key.
//
// The derivation is the reason a transient removal is safe: a Line whose
// identity is being reissued is not verifiable, so an Out event during that
// window republishes an empty allowlist (fail-closed) and the Line's own
// post-reissue event restores it. Both states are explicit and self-healing;
// neither claims the pair is healthy while the source is unproven.
func outAuthorizationTx(tx *sql.Tx, outID string) ([]string, error) {
	binding, err := outBindingTx(tx, outID)
	if err != nil {
		return nil, err
	}
	allowed := []string{}
	if !binding.Enabled || binding.LineID == "" {
		return allowed, nil
	}
	source, authorized, err := lineEgressSourceTx(tx, binding.LineID)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return allowed, nil
	}
	if len(allowed) >= maxOutAllowlistSources {
		return nil, errors.New("OUT_ALLOWLIST_INVALID: too many authorized sources")
	}
	return append(allowed, source), nil
}

// DeriveOutAllowlist returns the source list the Hub currently authorizes for one
// Out. It is the only producer of the Out allowlist; the publication path, the
// retire path and the Web projection all consume it.
//
// Three states fold into an empty allowlist because none of them authorizes a
// source: no binding row, an unbound row and a disabled row. A missing binding is
// not an error, but an unknown or wrong-role Out node is: an Out that does not
// exist cannot be "authorized for nothing".
func (s *store) DeriveOutAllowlist(outID string) ([]string, error) {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return nil, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return nil, errors.New("OUT_ROLE_INVALID: only out nodes carry a source authorization")
	}
	return outAuthorizationTx(tx, outID)
}

// outCandidateAtRevisionTx is the compiled digest the Hub expects for one Out
// revision. An Out carries no users and no REALITY block, but its baseline tag is
// revision-scoped, so the digest is built at the exact revision under test
// instead of being treated as revision independent.
func outCandidateAtRevisionTx(tx *sql.Tx, outID string, revision int64) (string, error) {
	candidate, err := buildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return "", err
	}
	if candidate.Role != node.RoleOut || candidate.Reality != nil || len(candidate.Users) != 0 {
		return "", errors.New("OUT_CANDIDATE_INVALID: an out candidate must be the credential-free baseline")
	}
	return compiledCandidateHash(candidate)
}

// outReadbackAllowlistTx reads the allowlist that the newest chain of one
// revision carried. Because publishCandidateTx enqueues the four kinds in order,
// the newest row that points at the revision is the readback task, which is
// exactly the task the Agent compares against its applied state.
//
// The boolean reports the presence of the key: an omitted key means "no Hub
// expectation, shape-only check". This path never publishes an omission, so a
// missing key counts as not yet authorized.
func outReadbackAllowlistTx(tx *sql.Tx, outID string, revision int64) ([]string, bool, error) {
	rows, err := tx.Query(`SELECT params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC`,
		outID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback)
	if err != nil {
		return nil, false, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, false, errors.New("DATABASE_UNAVAILABLE")
		}
		var params struct {
			Revision       int64     `json:"revision"`
			AllowedSources *[]string `json:"allowed_sources"`
		}
		if json.Unmarshal([]byte(raw), &params) != nil || params.Revision != revision {
			continue
		}
		if params.AllowedSources == nil {
			return nil, false, nil
		}
		return append([]string{}, (*params.AllowedSources)...), true, nil
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.New("DATABASE_UNAVAILABLE")
	}
	return nil, false, nil
}

// outSyncStatusTx projects one Out's authorization against the persisted intent.
//
// A chain that ended with OUT_ACL_SOURCE_MISMATCH is an expected transition: the
// allowlist it was checking no longer matches what the Hub wants, so the pair
// reports verifying and waits for an explicit retry or a new authorization. The
// identical snapshot is never republished automatically.
func outSyncStatusTx(tx *sql.Tx, outID string, now time.Time) (string, string, error) {
	desired, err := outAuthorizationTx(tx, outID)
	if err != nil {
		return outSyncPartial, sanitizeSubscriberSyncCode(err.Error()), nil
	}
	revision, digest, _, found, err := latestPublishedCandidateTx(tx, outID)
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if !found {
		return outSyncPending, codeOutSyncPending, nil
	}
	desiredDigest, err := outCandidateAtRevisionTx(tx, outID, revision)
	if err != nil {
		return outSyncPartial, sanitizeSubscriberSyncCode(err.Error()), nil
	}
	published, present, err := outReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	unfinished, err := subscriberLineUnfinishedTasksTx(tx, outID)
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if digest != desiredDigest || !present || !node.SameACLSourceSet(published, desired) {
		if unfinished != 0 {
			return outSyncVerifying, codeOutSyncInProgress, nil
		}
		return outSyncPending, codeOutSyncPending, nil
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, outID, revision, digest)
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if confirmed && unfinished == 0 {
		return outSyncHealthy, "", nil
	}
	if unfinished != 0 {
		return outSyncVerifying, codeOutSyncInProgress, nil
	}
	_, code, failed, err := subscriberLineLatestTaskTx(tx, outID)
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", err
	}
	if failed {
		if code == outAclSourceMismatchCode {
			// The task carried a set the Agent did not have applied: that is the
			// retire-then-verify transition. A new authorization or an explicit
			// retry proves it; repeating the same snapshot cannot.
			return outSyncVerifying, code, nil
		}
		return outSyncPartial, code, nil
	}
	return outSyncPending, codeOutSyncPending, nil
}

// queryIDsTx runs one bounded identifier query inside the caller's transaction.
func queryIDsTx(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// enabledOutIDsForLineTx returns the enabled Outs whose egress depends on one
// Line.
func enabledOutIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return queryIDsTx(tx, `SELECT out_id FROM out_bindings WHERE line_id=? AND enabled=1 ORDER BY out_id ASC`, lineID)
}

// outIDsForLineTx returns every Out that ever bound this Line, including a row
// whose egress is currently disabled. A retired Line has to be removed from the
// published allowlist even when the binding was disabled afterwards, because the
// Out host may still run the ACL of the last enabled state.
func outIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return queryIDsTx(tx, `SELECT out_id FROM out_bindings WHERE line_id=? ORDER BY out_id ASC`, lineID)
}

// lineOutEgressStatusTx reports whether a Line may use its bound Out path.
//
// A Line with no enabled binding egresses directly and is unaffected. With a
// binding, the Line must itself be a verifiable source and every bound Out has to
// authorize it and prove it: the Hub refuses to publish the Line while the Out
// path would drop its traffic, and the Web projection shows the same state
// instead of a false healthy.
func lineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	outs, err := enabledOutIDsForLineTx(tx, lineID)
	if err != nil {
		return lineEgressPartial, "DATABASE_UNAVAILABLE", err
	}
	if len(outs) == 0 {
		return lineEgressDirect, "", nil
	}
	if _, authorized, err := lineEgressSourceTx(tx, lineID); err != nil {
		return lineEgressPartial, sanitizeSubscriberSyncCode(err.Error()), nil
	} else if !authorized {
		return lineEgressPartial, codeLineNotAuthorized, nil
	}
	state, code := lineEgressHealthy, ""
	for _, outID := range outs {
		outState, outCode, err := outSyncStatusTx(tx, outID, now)
		if err != nil {
			return lineEgressPartial, "DATABASE_UNAVAILABLE", err
		}
		switch outState {
		case outSyncHealthy:
		case outSyncPartial:
			state, code = lineEgressPartial, outCode
		default:
			if state == lineEgressHealthy {
				state, code = lineEgressVerifying, outCode
				if code == "" {
					code = codeOutSyncInProgress
				}
			}
		}
	}
	return state, code, nil
}

// lineOutPublishGateTx is the publish gate: a Line whose Out path is not
// authorized and confirmed yet is not published at all.
//
// Publishing it would hand clients an egress that drops them, and reporting it
// healthy would claim a path the Out never confirmed. The gate is a no-op for a
// Line without an enabled binding, so an Out-free deployment is unchanged.
func lineOutPublishGateTx(tx *sql.Tx, lineID string, now time.Time) error {
	state, code, err := lineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		return err
	}
	switch state {
	case lineEgressDirect, lineEgressHealthy:
		return nil
	}
	if code == "" {
		code = codeOutSyncInProgress
	}
	return errors.New(codeOutNotAuthorized + ": the line's out egress is not authorized yet (" + sanitizeSubscriberSyncCode(code) + ")")
}

// outEgressReadbackTx is the Hub-side dual readback of one Line.
//
// Each of the four facts is derived independently and reported with its own
// stable code, so a partially converged pair can never be summarized as healthy:
// the Out allowlist, the Line inbound snapshot, the REALITY block of that
// snapshot, and the resulting final egress.
func outEgressReadbackTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressReadback, error) {
	readback := OutEgressReadback{LineID: lineID}
	outs, err := enabledOutIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressReadback{}, err
	}
	if len(outs) > 0 {
		readback.OutID = outs[0]
	}
	// The allowlist fact belongs to the Out side; a direct Line has none.
	if len(outs) == 0 {
		readback.Allowlist = lineEgressDirect
	} else {
		state, code, err := lineOutEgressStatusTx(tx, lineID, now)
		if err != nil {
			return OutEgressReadback{}, err
		}
		readback.Allowlist, readback.AllowlistCode = state, code
	}
	// The Line side facts come from the Line's own confirmed snapshot, which is
	// what proves its inbound listener, user set and REALITY transport.
	inbound, inboundCode, inboundErr := subscriberLineSyncViewTx(tx, lineID, now)
	if inboundErr != nil {
		return OutEgressReadback{}, errors.New("DATABASE_UNAVAILABLE")
	}
	readback.Inbound, readback.InboundCode = inbound, inboundCode
	// REALITY is reported as its own fact because an operator must be able to
	// see it, and it is derived independently from the confirmed Line
	// candidate. For a configured Line a healthy inbound already implies it: the
	// desired digest is built from the stored transport, so the only snapshot
	// that can confirm carries the REALITY block. The extra conjunction below is
	// therefore a redundancy guard against a future change to the inbound
	// projection, not a currently reachable distinction; it never lets the pair
	// be reported healthy while the fact is false.
	readback.Reality = lineRealityConfirmedTx(tx, lineID)
	readback.ConfirmedRevision, readback.ConfirmedDigest = confirmedLineRevisionTx(tx, lineID)
	switch {
	case readback.Allowlist == lineEgressDirect:
		readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
	case readback.Allowlist == lineEgressHealthy && inbound == subscriberSyncHealthy && readback.Reality:
		readback.FinalEgress = lineEgressHealthy
	case readback.Allowlist == lineEgressHealthy && inbound == subscriberSyncHealthy:
		readback.FinalEgress = lineEgressPartial
		readback.FinalEgressCode = "OUT_EGRESS_REALITY_UNVERIFIED"
	case readback.Allowlist == lineEgressVerifying || inbound == subscriberSyncPending:
		readback.FinalEgress = lineEgressVerifying
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, codeOutSyncInProgress)
	default:
		readback.FinalEgress = lineEgressPartial
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, "OUT_SYNC_FAILED")
	}
	// A transition that needs an explicit republish is a retry pointer, not an
	// automatic one. It is derived from the same evidence the states above used.
	readback.RetryPending = readback.FinalEgress != lineEgressHealthy && readback.FinalEgress != lineEgressDirect &&
		readback.FinalEgress != lineEgressVerifying
	return readback, nil
}

// confirmedLineRevisionTx returns the newest Line revision the node confirmed
// together with its compiled digest. It is the rollback pointer of the pair: the
// host keeps this revision's files as its last-known-good state, so any later
// failed chain can be rolled back to it.
func confirmedLineRevisionTx(tx *sql.Tx, lineID string) (int64, string) {
	revision, digest, _, found, err := latestPublishedCandidateTx(tx, lineID)
	if err != nil || !found {
		return 0, ""
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return 0, ""
	}
	return revision, digest
}

// lineRealityConfirmedTx reports whether the latest confirmed Line candidate
// still carries the REALITY block its stored transport describes. An Out-bound
// Line without that block could not serve the client configuration the Hub
// publishes, so the final egress is never claimed healthy on the allowlist alone.
func lineRealityConfirmedTx(tx *sql.Tx, lineID string) bool {
	revision, digest, _, found, err := latestPublishedCandidateTx(tx, lineID)
	if err != nil || !found {
		return false
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return false
	}
	var candidateJSON string
	if err := tx.QueryRow(`SELECT candidate_json FROM node_candidates WHERE node_id=? AND revision=?`, lineID, revision).
		Scan(&candidateJSON); err != nil {
		return false
	}
	var document node.CandidateDocument
	if json.Unmarshal([]byte(candidateJSON), &document) != nil {
		return false
	}
	return document.Reality != nil && document.Role == node.RoleEdge
}

// firstStableCode returns the first non-empty value so a transition code is never
// replaced by an empty one.
func firstStableCode(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// drainOutNodeIntentTx reconciles one Out with the currently persisted
// authorization.
//
// The rules mirror the subscriber drain and keep the operation bounded:
//   - an unfinished chain is never replaced or cancelled;
//   - an identical, confirmed authorization needs no publication;
//   - an identical but unconfirmed authorization is republished only by an
//     explicit retry;
//   - a changed authorization is new intent and is published;
//   - an offline Out keeps the durable intent but receives no state-changing
//     task.
func drainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return outDrainNoop, nil
	}
	if err != nil {
		return outDrainNoop, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return outDrainNoop, nil
	}
	latestRevision, latestDigest, _, hasCandidate, err := latestPublishedCandidateTx(tx, outID)
	if err != nil {
		return outDrainNoop, err
	}
	if hasCandidate {
		desired, err := outAuthorizationTx(tx, outID)
		if err != nil {
			return outDrainNoop, err
		}
		sameAuthorization, err := outPublishedAuthorizationTx(tx, outID, latestRevision, latestDigest, desired)
		if err != nil {
			return outDrainNoop, err
		}
		confirmed, err := subscriberLineReadbackConfirmedTx(tx, outID, latestRevision, latestDigest)
		if err != nil {
			return outDrainNoop, err
		}
		unfinished, err := subscriberLineUnfinishedTasksTx(tx, outID)
		if err != nil {
			return outDrainNoop, err
		}
		if unfinished != 0 {
			// A chain always finishes first. Publishing a competing chain would
			// leave two apply steps racing on one host.
			return outDrainDeferred, nil
		}
		if sameAuthorization && confirmed {
			return outDrainNoop, nil
		}
		if sameAuthorization && !allowRetry {
			// The snapshot did not change: an automatic poll never retries it,
			// whether the last chain failed or ended without matching evidence.
			return outDrainNoop, nil
		}
	}
	offline, err := subscriberLineNodeOfflineTx(tx, outID, now)
	if err != nil {
		return outDrainNoop, err
	}
	if offline {
		return outDrainDeferred, errors.New("OUT_OFFLINE: out is offline; the authorization change stays pending")
	}
	revision, err := nextCandidateRevisionTx(tx, outID)
	if err != nil {
		return outDrainNoop, err
	}
	candidate, err := buildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return outDrainNoop, err
	}
	if _, err := publishCandidateTx(tx, outID, candidate, now); err != nil {
		return outDrainNoop, err
	}
	return outDrainPublished, nil
}

// outPublishedAuthorizationTx reports whether the published chain of one revision
// already carries exactly the desired authorization: the candidate is the
// expected credential-free baseline and the newest task names the same source
// set.
func outPublishedAuthorizationTx(tx *sql.Tx, outID string, revision int64, digest string, desired []string) (bool, error) {
	expected, err := outCandidateAtRevisionTx(tx, outID, revision)
	if err != nil {
		return false, err
	}
	if digest != expected {
		return false, nil
	}
	published, present, err := outReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return false, err
	}
	return present && node.SameACLSourceSet(published, desired), nil
}

// nextCandidateRevisionTx returns the next immutable revision of one node.
func nextCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	var revision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New("DATABASE_UNAVAILABLE")
	}
	return revision, nil
}

// OnLineRetired reclaims the authorization of a Line at every Out that ever bound
// it and republishes each affected Out with the remaining sources.
//
// It is the explicit retire path: a Line whose identity is already revoked (or
// which never had a verifiable source) is de-authorized at once. A Line that is
// still a verifiable source is refused, because a bookkeeping call must never
// silently de-authorize a live Line; that has to be an identity revocation.
//
// Republishing is explicit. An in-flight chain or an offline Out defers the
// change and the caller sees OUT_SYNC_PENDING, never a fabricated success. The
// derivation already excludes a non-current Line, so a deferred reclaim is
// fail-closed in the meantime and the next Out or Line event completes it.
func (s *store) OnLineRetired(lineID string) error {
	return s.onLineRetiredAt(lineID, time.Now())
}

// onLineRetiredAt is the request-clock variant used by the Web layer.
func (s *store) onLineRetiredAt(lineID string, now time.Time) error {
	lineID = strings.TrimSpace(lineID)
	if err := subscription.ValidateID(lineID); err != nil {
		return errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("LINE_NOT_FOUND: unknown line node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "edge" {
		return errors.New("LINE_ROLE_INVALID: only edge nodes can retire an out authorization")
	}
	if _, authorized, err := lineEgressSourceTx(tx, lineID); err != nil {
		return err
	} else if authorized {
		return errors.New("LINE_NOT_RETIRED: revoke the line identity before reclaiming its out authorization")
	}
	outs, err := outIDsForLineTx(tx, lineID)
	if err != nil {
		return err
	}
	pending := false
	var firstErr error
	for _, outID := range outs {
		outcome, err := drainOutNodeIntentTx(tx, outID, now, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if outcome == outDrainDeferred {
			pending = true
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if !pending {
		return firstErr
	}
	lineErr := errors.New(codeOutSyncPending + ": the out authorization change is queued behind an in-flight or offline out; retry the out synchronization")
	return errors.Join(firstErr, lineErr)
}

// retryOutSync is the explicit retry and rollback pointer of one Out. It
// republishes a chain even when the desired authorization did not change, which is
// exactly what an operator needs after a partial/failed or superseded chain.
// Automatic polls never call it.
func (s *store) retryOutSync(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	outcome, err := drainOutNodeIntentTx(tx, outID, now, true)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if outcome == outDrainDeferred {
		return errors.New(codeOutSyncPending + ": the out authorization change is queued behind an in-flight or offline out")
	}
	return nil
}

// drainOutNode begins its own transaction and reconciles one Out. Failures must
// not fail the request they serve: the next poll, heartbeat or result retries.
func (s *store) drainOutNode(outID string, now time.Time) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := drainOutNodeIntentTx(tx, outID, now, false); err != nil {
		return
	}
	_ = tx.Commit()
}

// outIDsForLine reads the bound Outs in their own statement so no transaction is
// held open while the per-Out drain begins its own.
func (s *store) outIDsForLine(lineID string) ([]string, error) {
	return storeIDs(s.db, `SELECT out_id FROM out_bindings WHERE line_id=? ORDER BY out_id ASC`, lineID)
}

// lineIDsForOut reads the bound Lines in their own statement.
func (s *store) lineIDsForOut(outID string) ([]string, error) {
	return storeIDs(s.db, `SELECT line_id FROM out_bindings WHERE out_id=? AND line_id IS NOT NULL ORDER BY line_id ASC`, outID)
}

// storeIDs runs one bounded identifier query and closes its rows before the
// caller opens another transaction on the single-connection pool.
func storeIDs(db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// drainOutsForLine is the "Line event" half of the coordination: a Line that just
// became verifiable, or whose snapshot was just confirmed, authorizes itself at
// every Out that serves it.
func (s *store) drainOutsForLine(lineID string, now time.Time) {
	outs, err := s.outIDsForLine(lineID)
	if err != nil {
		return
	}
	for _, outID := range outs {
		s.drainOutNode(outID, now)
	}
}

// drainLinesForOut is the "Out event" half: once an Out confirmed the
// authorization, the Lines it serves may be published.
func (s *store) drainLinesForOut(outID string, now time.Time) {
	lines, err := s.lineIDsForOut(outID)
	if err != nil {
		return
	}
	for _, lineID := range lines {
		s.drainSubscriberNode(lineID, now)
	}
}

// drainNodeCoordination runs the pre-delivery reconciliation of one node.
//
// The direction is what makes the coordination bidirectional:
//   - an Out event (heartbeat, poll, result) republishes its authorization and
//     then lets the Lines it serves be published;
//   - a Line event first gives every bound Out the chance to authorize the Line,
//     then publishes the Line itself if the gate now passes.
//
// Each step owns its own transaction, so nothing nests on the single-connection
// pool. A failure in one direction never fails the request: the next event
// retries it.
func (s *store) drainNodeCoordination(nodeID string, now time.Time) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if err != nil {
		s.drainSubscriberNode(nodeID, now)
		return
	}
	if role == "out" {
		s.drainOutNode(nodeID, now)
		s.drainLinesForOut(nodeID, now)
		return
	}
	s.drainOutsForLine(nodeID, now)
	s.drainSubscriberNode(nodeID, now)
}

// nodeCoordinationReadback reports the readback state of one node for the audit
// log: a Line reports its egress pair, an Out reports its authorization. It is a
// read-only projection and never mutates or publishes; the returned codes are
// stable identifiers only.
func (s *store) nodeCoordinationReadback(nodeID string, now time.Time) (OutEgressReadback, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return OutEgressReadback{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role); err != nil {
		return OutEgressReadback{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role == "out" {
		state, code, err := outSyncStatusTx(tx, nodeID, now)
		if err != nil {
			return OutEgressReadback{}, errors.New("DATABASE_UNAVAILABLE")
		}
		return OutEgressReadback{OutID: nodeID, Allowlist: state, AllowlistCode: code}, nil
	}
	return outEgressReadbackTx(tx, nodeID, now)
}

// outSyncStatus is the read-only projection used by tests and future Web code.
func (s *store) outSyncStatus(outID string, now time.Time) (string, string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return outSyncPartial, "DATABASE_UNAVAILABLE", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	return outSyncStatusTx(tx, outID, now)
}

// OutEgressReadback returns the dual readback of one Line. It is read-only and
// safe to call while rendering a management response.
func (s *store) OutEgressReadback(lineID string, now time.Time) (OutEgressReadback, error) {
	lineID = strings.TrimSpace(lineID)
	if err := subscription.ValidateID(lineID); err != nil {
		return OutEgressReadback{}, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return OutEgressReadback{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	return outEgressReadbackTx(tx, lineID, now)
}

// reclaimRetiredLine revokes the Out authorization of a Line that just lost its
// identity. It never fails the caller: the identity revocation has already been
// recorded, and a deferred reclaim is retried by the next Out or Line event.
func (s *store) reclaimRetiredLine(lineID string, now time.Time) error {
	return s.onLineRetiredAt(lineID, now)
}
