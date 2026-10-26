package store

// Out synchronization coordinates the optional Out node with the Lines that are
// allowed to use it as an egress.
//
// There is exactly one authorization source (Ruling R10): node membership. An Out
// authorizes the union of the transport addresses of every enrolled Line that holds a
// current pairing identity, and nothing else can authorize a source:
//
//	outAllowedSources(out) =
//	    { line_settings.server of L | L is an edge node with exactly one
//	                                  non-revoked identity }
//
// Membership is symmetric and lifecycle-driven: a Line that enrolls joins every Out,
// an Out that enrolls starts with every existing Line, and a deletion or a revoked
// identity removes the source. A Hub with no member Line authorizes nothing, which is
// the fail-closed default-deny state the Agent applies.
//
// A subscription is deliberately NOT part of this: it selects which egress a client
// document names, so creating, editing, pausing or deleting one must never republish
// an Out. That separation is what keeps the data plane stable while subscriptions
// churn, and it is asserted directly (`TestOutAuthorization_SubscriptionNeverTouchesTheACL`).
//
// The stored binding table that used to carry the relation is gone
// (migrateSchema14), so there is no second source of truth a Line could be authorized
// from, and no window in which the Hub has no authorization at all: the schema version
// that drops the table is the version whose code performs this derivation.
//
// The Hub derives the source list from the enrolled Lines, publishes it in the frozen
// four-task chain, and treats a healthy readback of a task that carried exactly that
// list as the only proof that the Out data plane matches the authorization.
//
// The same asymmetry as the subscriber synchronization applies: a Line whose own Out
// selection is not authorized and confirmed yet is not published, because publishing it
// would hand clients an egress that drops them. A retired Line or a revoked identity is
// removed from the Out allowlist and the Out is republished; until that chain is
// confirmed the pair reports a transition, never healthy.
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
	"sort"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The Out authorization states the Hub can prove.
const (
	// OutSyncHealthy: the published allowlist is the desired one and the Agent
	// readback confirmed it for the current revision.
	OutSyncHealthy = "healthy"
	// OutSyncVerifying: a chain is in flight, or the last one ended with the
	// expected supersession code.
	OutSyncVerifying = "verifying"
	// OutSyncPending: the desired authorization has not been published yet.
	OutSyncPending = "pending"
	// OutSyncPartial: the last chain ended in a terminal failure, or the Hub
	// cannot authorize a selected Line at all.
	OutSyncPartial = "partial"
)

// The Line egress states derived from the subscription selection plus the Out
// authorization.
const (
	// LineEgressDirect: no active subscription selects a configured egress for
	// this Line, so its clients egress directly. This is a routing state, not an
	// ACL state: the Line is still an authorized source at every Out (Ruling R10).
	LineEgressDirect = "direct"
	// LineEgressExternal: the Line's egress slot holds an external HTTP proxy
	// (Ruling R11). The proxy is not a managed host, so there is no Out ACL,
	// readback or deep-hook fact to prove; the Line is excluded from the Out
	// convergence gate but still has to prove its own inbound snapshot.
	LineEgressExternal = "external"
	// LineEgressHealthy: every Out selected for this Line authorized it and
	// confirmed it.
	LineEgressHealthy = "healthy"
	// LineEgressVerifying: the authorization is being applied or read back.
	LineEgressVerifying = "verifying"
	// LineEgressPartial: an Out selected for this Line cannot authorize it.
	LineEgressPartial = "partial"
)

// OutAclSourceMismatchCode is the Agent readback code for a task whose allowlist
// differs from the applied one. Across two chains that is the expected
// retire-then-verify transition, so the Hub reports verifying and never
// republishes the identical snapshot on its own.
const OutAclSourceMismatchCode = "OUT_ACL_SOURCE_MISMATCH"

// The stable codes the Hub itself reports for a Line it cannot authorize.
const (
	// CodeLineEgressUnverified marks a configured Line whose transport address
	// is a host name: the Hub has no proof of the source address the Out sees.
	CodeLineEgressUnverified = "LINE_EGRESS_UNVERIFIED"
	// CodeLineNotAuthorized marks a selected Line without a current paired
	// identity (never paired, reissuing, or revoked).
	CodeLineNotAuthorized = "LINE_NOT_AUTHORIZED"
	// CodeOutSyncInProgress and CodeOutSyncPending are the transition codes.
	CodeOutSyncInProgress = "OUT_SYNC_IN_PROGRESS"
	CodeOutSyncPending    = "OUT_SYNC_PENDING"
	// CodeOutNotAuthorized is the single refusal code of a publication that
	// depends on an Out authorization the Hub cannot vouch for yet. The publish
	// gate and every projection report it, so an operator never reads "preview
	// says fine, publish says no".
	CodeOutNotAuthorized = "OUT_NOT_AUTHORIZED"
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
	// RetryPending is the retry pointer: true only when the pair is in a
	// terminal failure that an explicit retry can resolve. The retry affordance
	// is the existing node retry route (POST /nodes/{nodeID}/retry, which
	// republishes the node's authorization) or retryOutSync from the store.
	//
	// A transition in progress (verifying) is deliberately NOT retry-pending:
	// a chain is still applying, and republishing on top of it would race two
	// apply steps on one host. An automatic poll never retries either; only the
	// explicit action does.
	RetryPending bool `json:"retry_pending"`
}

// OutAllowlistSource canonicalizes one authorized source. It accepts only a
// literal address or an already aligned CIDR, so the value the Hub publishes is
// exactly the value the Agent renders: the Agent masks an unmasked prefix
// silently, which would authorize a wider network than the Hub named.
//
// A zero-length prefix is rejected here as well: it would turn the Out guard back
// into an allow-all rule.
func OutAllowlistSource(raw string) (string, error) {
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

// validNodeID accepts exactly the canonical node identity shape that the rest of
// the domain uses (32 lowercase hex characters).
func validNodeID(id string) bool {
	return subscription.ValidateID(id) == nil
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
		return "", false, errLineIDInvalid()
	}
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, errLineNotFound
	}
	if err != nil {
		return "", false, errors.New(CodeDatabaseUnavailable)
	}
	if role != string(nodeRoleEdge) {
		return "", false, errors.New("LINE_ROLE_INVALID: only edge nodes can be an out source")
	}
	var server string
	err = tx.QueryRow(`SELECT server FROM line_settings WHERE node_id=?`, lineID).Scan(&server)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.New(CodeDatabaseUnavailable)
	}
	var identities int
	if err := tx.QueryRow(`SELECT count(*) FROM node_identities WHERE node_id=? AND revoked=0`, lineID).Scan(&identities); err != nil {
		return "", false, errors.New(CodeDatabaseUnavailable)
	}
	if identities != 1 {
		return "", false, nil
	}
	if _, err := netip.ParseAddr(server); err != nil {
		return "", false, errors.New(CodeLineEgressUnverified + ": the line transport address is a host name, so the hub cannot authorize a verifiable egress source")
	}
	source, err := OutAllowlistSource(server)
	if err != nil {
		return "", false, err
	}
	return source, true, nil
}

// OutAuthorizedLineIDsTx returns the Lines an Out authorizes under the node
// membership model (Ruling R10): every enrolled Line that currently holds a pairing
// identity, in node-id order.
//
// The result is IDENTICAL for every Out on one Hub, which is why the outID argument is
// accepted but not used: the call sites that ask "what does this Out accept" keep the
// Out in the signature so the question stays explicit at the call site, while the
// answer comes from the membership set alone. A future per-Out policy (1.1) can start
// using the argument without changing a single caller.
//
// Membership, not subscription, is the authorization source. A Line becomes a
// permitted source of every Out the moment its identity is issued, and it stops being
// one when its node row or its identity goes away. The subscription that a subscriber
// later builds selects which egress the *client document* names; it does not decide
// whether the data plane accepts the Line.
//
// The order is canonical so a caller can compare two derivations byte for byte.
func OutAuthorizedLineIDsTx(tx *sql.Tx, outID string) ([]string, error) {
	_ = outID // identical for every Out; see the contract above.
	rows, err := tx.Query(`SELECT n.id
	  FROM nodes n
	 WHERE n.role='edge'
	 ORDER BY n.id ASC`)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return ids, nil
}

// outAuthorizationTx is the single derivation of an Out's authorization.
//
// It is the only producer of the Out allowlist: the publication path, the retire
// path, the publish gate and the Web projection all consume it.
//
// Under Ruling R10 the source is node membership: every enrolled Line that holds a
// current pairing identity is permitted at every Out by default. Consequences:
//
//   - an Out enrolled into a Hub with N Lines starts with all N addresses, and a
//     Line that enrolls later is added to every Out; neither needs a subscription;
//   - a deleted node row, a revoked identity or a removed Line transport drops the
//     source on the next Out event, and the republish is fail-closed in between;
//   - a subscription edit never changes this list, so it never republishes an Out.
//
// A Line the Hub cannot vouch for still contributes nothing: no current identity
// means no address (the Hub holds no proof the Out will observe that source), and a
// DNS-named transport is a hard refusal instead of a guessed address.
func outAuthorizationTx(tx *sql.Tx, outID string) ([]string, error) {
	lineIDs, err := OutAuthorizedLineIDsTx(tx, outID)
	if err != nil {
		return nil, err
	}
	sources := make([]string, 0, len(lineIDs))
	seen := make(map[string]struct{}, len(lineIDs))
	for _, lineID := range lineIDs {
		source, authorized, err := lineEgressSourceTx(tx, lineID)
		if err != nil {
			return nil, err
		}
		if !authorized {
			// A Line that lost its identity or its transport contributes
			// nothing; it must never be replaced by a guessed address.
			continue
		}
		if _, duplicate := seen[source]; duplicate {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	if len(sources) > maxOutAllowlistSources {
		return nil, errors.New("OUT_ALLOWLIST_INVALID: too many authorized sources")
	}
	// The published order must not depend on insertion order, or an unchanged
	// authorization would be republished as a change.
	sort.Strings(sources)
	return sources, nil
}

// OutAuthorizedSubscribers names the subscriptions that select one Out, ordered by
// display name. It is a *selection* projection for the delete guard (a subscription
// naming an Out must be migrated before that Out disappears), not an authorization
// input. It never returns a credential or a token.
func (s *Store) OutAuthorizedSubscribers(outID string) ([]string, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return nil, errOutIDInvalid()
	}
	return s.selectionUsedBy(`SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	 WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
}

// OutMembershipLineIDs returns the Lines one Out authorizes under the membership
// model. It is a read-only evidence projection: the nodes page renders the
// selection and the published ACL through other queries, and the result is
// identical for every Out on one Hub. It remains the explicit way a test (or a
// future per-Out view) asks "which Lines does this Out accept?" without
// reimplementing the membership query.
func (s *Store) OutMembershipLineIDs(outID string) ([]string, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return nil, errOutIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if err := requireOutRoleTx(tx, outID); err != nil {
		return nil, err
	}
	return OutAuthorizedLineIDsTx(tx, outID)
}

// DeriveOutAllowlist returns the source list the Hub currently authorizes for one
// Out. It is the read-only public face of the same derivation the publication
// path consumes through outAuthorizationTx (which serves every Out identically
// on one Hub); it exists so the Task 5 authorization tests and an operator
// readback can ask the question without opening a transaction.
//
// An empty list is a real answer ("this Out is authorized for nothing") while an
// unknown or wrong-role Out node is a refusal: an Out that does not exist cannot
// be "authorized for nothing".
func (s *Store) DeriveOutAllowlist(outID string) ([]string, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return nil, errOutIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errOutNotFound
	}
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	if role != string(nodeRoleOut) {
		return nil, errOutRoleInvalidSource
	}
	return outAuthorizationTx(tx, outID)
}

// outCandidateAtRevisionTx is the compiled digest the Hub expects for one Out
// revision. An Out carries no users and no REALITY block, but it may carry
// the link key (v4) for its SS guard; its baseline tag is revision-scoped,
// so the digest is built at the exact revision under test instead of being
// treated as revision independent.
func outCandidateAtRevisionTx(tx *sql.Tx, outID string, revision int64) (string, error) {
	candidate, err := BuildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return "", err
	}
	if candidate.Role != node.RoleOut || candidate.Reality != nil || len(candidate.Users) != 0 {
		return "", errors.New("OUT_CANDIDATE_INVALID: an out candidate must be the baseline or the link-key document")
	}
	return compiledCandidateHash(candidate)
}

// OutReadbackAllowlistTx reads the allowlist that the newest chain of one
// revision carried. Because publishCandidateTx enqueues the four kinds in order,
// the newest row that points at the revision is the readback task, which is
// exactly the task the Agent compares against its applied state.
//
// The boolean reports the presence of the key: an omitted key means "no Hub
// expectation, shape-only check". This path never publishes an omission, so a
// missing key counts as not yet authorized.
func OutReadbackAllowlistTx(tx *sql.Tx, outID string, revision int64) ([]string, bool, error) {
	rows, err := tx.Query(`SELECT params FROM agent_tasks
 WHERE node_id=? AND kind IN (?,?,?,?) ORDER BY revision DESC`,
		outID, protocol.KindConfigCheck, protocol.KindConfigStage, protocol.KindConfigApply, protocol.KindConfigReadback)
	if err != nil {
		return nil, false, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, false, errors.New(CodeDatabaseUnavailable)
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
		return nil, false, errors.New(CodeDatabaseUnavailable)
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
		return OutSyncPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	}
	revision, digest, _, found, err := LatestPublishedCandidateTx(tx, outID)
	if err != nil {
		return OutSyncPartial, CodeDatabaseUnavailable, err
	}
	if !found {
		return OutSyncPending, CodeOutSyncPending, nil
	}
	desiredDigest, err := outCandidateAtRevisionTx(tx, outID, revision)
	if err != nil {
		return OutSyncPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	}
	published, present, err := OutReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return OutSyncPartial, CodeDatabaseUnavailable, err
	}
	unfinished, err := subscriberLineUnfinishedTasksTx(tx, outID)
	if err != nil {
		return OutSyncPartial, CodeDatabaseUnavailable, err
	}
	if digest != desiredDigest || !present || !node.SameACLSourceSet(published, desired) {
		if unfinished != 0 {
			return OutSyncVerifying, CodeOutSyncInProgress, nil
		}
		return OutSyncPending, CodeOutSyncPending, nil
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, outID, revision, digest)
	if err != nil {
		return OutSyncPartial, CodeDatabaseUnavailable, err
	}
	if confirmed && unfinished == 0 {
		return OutSyncHealthy, "", nil
	}
	if unfinished != 0 {
		return OutSyncVerifying, CodeOutSyncInProgress, nil
	}
	_, code, failed, err := SubscriberLineLatestTaskTx(tx, outID)
	if err != nil {
		return OutSyncPartial, CodeDatabaseUnavailable, err
	}
	if failed {
		if code == OutAclSourceMismatchCode {
			// The task carried a set the Agent did not have applied: that is the
			// retire-then-verify transition. A new authorization or an explicit
			// retry proves it; repeating the same snapshot cannot.
			return OutSyncVerifying, code, nil
		}
		return OutSyncPartial, code, nil
	}
	return OutSyncPending, CodeOutSyncPending, nil
}

// scanIDRows drains one single-column identifier result set, closing it before the
// caller opens another statement or transaction on the single-connection pool.
// Every failure maps to the same stable code so callers never leak driver detail.
func scanIDRows(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return out, nil
}

// queryIDsTx runs one bounded identifier query inside the caller's transaction.
func queryIDsTx(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// selectedEgressIDsForLineTx returns every egress the Line's selection names:
// managed Out nodes and external HTTP proxies (Ruling R11). The 1.0 slot holds
// one egress per subscriber and the same-Line rule makes all subscriptions on
// one Line agree, so the caller sees at most one distinct id in practice; the
// query does not rely on that to stay correct.
func selectedEgressIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return queryIDsTx(tx, `SELECT DISTINCT o.out_id
	  FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id AND s.state='active'
	  JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
	 WHERE l.node_id=?
	 ORDER BY o.out_id ASC`, lineID)
}

// enabledOutIDsForLineTx returns the managed Outs a Line's own route may egress
// through. An external HTTP proxy is deliberately excluded: it has no ACL and
// no readback, so it must never enter the Out authorization gate
// (Ruling R11). Callers that need the complete egress slot use
// selectedEgressIDsForLineTx.
//
// This is the *routing* question, not the ACL question, and Ruling R10 changed only
// the latter: the data plane authorizes Line membership, while a Line still renders
// exactly one "out" egress — the Out its section of the policy (and the subscription
// that carries it) selected. Keeping this query selection-driven is what stops an
// unrelated Out elsewhere in the pool from gating this Line's publication or being
// named in its candidate.
//
// The ACL derivation never reads this function: it reads OutAuthorizedLineIDsTx
// (membership), so a subscription edit cannot change what any Out accepts.
func enabledOutIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return queryIDsTx(tx, `SELECT DISTINCT o.out_id
	  FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id AND s.state='active'
	  JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
	  JOIN nodes n ON n.id=o.out_id AND n.role='out'
	 WHERE l.node_id=?
	 ORDER BY o.out_id ASC`, lineID)
}

// nodeRoleTx reads one node's immutable role, mapping a missing row to a stable
// refusal.
func nodeRoleTx(tx *sql.Tx, nodeID string) (string, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNodeNotFoundDetail
	}
	if err != nil {
		return "", errors.New(CodeDatabaseUnavailable)
	}
	return role, nil
}

// requireOutRoleTx refuses a node that is not an Out, so a projection cannot report
// a Line node as "an Out that authorizes nothing".
func requireOutRoleTx(tx *sql.Tx, outID string) error {
	role, err := nodeRoleTx(tx, outID)
	if err != nil {
		if strings.HasPrefix(err.Error(), "NODE_NOT_FOUND") {
			return errOutNotFound
		}
		return err
	}
	if role != string(nodeRoleOut) {
		return errOutRoleInvalidSource
	}
	return nil
}

// LineOutEgressStatusTx reports whether a Line may use its selected Out path.
//
// A Line that no active subscription pairs with an Out egresses directly and is
// unaffected. With a selection, the Line must itself be a verifiable source and the
// selected Out has to have confirmed the membership authorization: the Hub refuses to
// publish the Line while the Out path would drop its traffic, and the Web projection
// shows the same state instead of a false healthy.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	selected, err := selectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return LineEgressPartial, CodeDatabaseUnavailable, err
	}
	if len(selected) == 0 {
		return LineEgressDirect, "", nil
	}
	outs, err := enabledOutIDsForLineTx(tx, lineID)
	if err != nil {
		return LineEgressPartial, CodeDatabaseUnavailable, err
	}
	if len(outs) == 0 {
		// The slot names an external HTTP proxy: there is no Out ACL and no
		// Agent readback to prove, so the gate is deliberately excluded
		// (Ruling R11). The Line still has to prove its own inbound snapshot;
		// that fact is reported separately.
		return LineEgressExternal, "", nil
	}
	if _, authorized, err := lineEgressSourceTx(tx, lineID); err != nil {
		return LineEgressPartial, SanitizeSubscriberSyncCode(err.Error()), nil
	} else if !authorized {
		return LineEgressPartial, CodeLineNotAuthorized, nil
	}
	state, code := LineEgressHealthy, ""
	for _, outID := range outs {
		outState, outCode, err := outSyncStatusTx(tx, outID, now)
		if err != nil {
			return LineEgressPartial, CodeDatabaseUnavailable, err
		}
		switch outState {
		case OutSyncHealthy:
		case OutSyncPartial:
			state, code = LineEgressPartial, outCode
		default:
			if state == LineEgressHealthy {
				state, code = LineEgressVerifying, outCode
				if code == "" {
					code = CodeOutSyncInProgress
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
// Line that no active subscription pairs with an Out, so an Out-free deployment is
// unchanged.
func lineOutPublishGateTx(tx *sql.Tx, lineID string, now time.Time) error {
	state, code, err := LineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		return err
	}
	switch state {
	case LineEgressDirect, LineEgressExternal, LineEgressHealthy:
		return nil
	}
	if code == "" {
		code = CodeOutSyncInProgress
	}
	return errors.New(CodeOutNotAuthorized + ": the line's out egress is not authorized yet (" + SanitizeSubscriberSyncCode(code) + ")")
}

// outEgressReadbackTx is the Hub-side dual readback of one Line.
//
// Each of the four facts is derived independently and reported with its own
// stable code, so a partially converged pair can never be summarized as healthy:
// the Out allowlist, the Line inbound snapshot, the REALITY block of that
// snapshot, and the resulting final egress.
func outEgressReadbackTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressReadback, error) {
	readback := OutEgressReadback{LineID: lineID}
	selected, err := selectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressReadback{}, err
	}
	if len(selected) > 0 {
		readback.OutID = selected[0]
	}
	// The allowlist fact belongs to a managed Out; a direct Line and an
	// external HTTP proxy have none.
	if len(selected) == 0 {
		readback.Allowlist = LineEgressDirect
	} else {
		state, code, err := LineOutEgressStatusTx(tx, lineID, now)
		if err != nil {
			return OutEgressReadback{}, err
		}
		readback.Allowlist, readback.AllowlistCode = state, code
	}
	// The Line side facts come from the Line's own confirmed snapshot, which is
	// what proves its inbound listener, user set and REALITY transport.
	inbound, inboundCode, inboundErr := SubscriberLineSyncViewTx(tx, lineID, now)
	if inboundErr != nil {
		return OutEgressReadback{}, errors.New(CodeDatabaseUnavailable)
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
	case readback.Allowlist == LineEgressDirect || readback.Allowlist == LineEgressExternal:
		readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
	case readback.Allowlist == LineEgressHealthy && inbound == SubscriberSyncHealthy && readback.Reality:
		readback.FinalEgress = LineEgressHealthy
	case readback.Allowlist == LineEgressHealthy && inbound == SubscriberSyncHealthy:
		readback.FinalEgress = LineEgressPartial
		readback.FinalEgressCode = "OUT_EGRESS_REALITY_UNVERIFIED"
	case readback.Allowlist == LineEgressVerifying || inbound == SubscriberSyncPending:
		readback.FinalEgress = LineEgressVerifying
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, CodeOutSyncInProgress)
	default:
		readback.FinalEgress = LineEgressPartial
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, "OUT_SYNC_FAILED")
	}
	// The retry pointer is derived from the same evidence as the state above:
	// only a terminal failure is retryable. A direct Line has no Out path to
	// retry, and a transition is still applying its own chain.
	readback.RetryPending = readback.FinalEgress == LineEgressPartial
	return readback, nil
}

// confirmedLineRevisionTx returns the newest Line revision the node confirmed
// together with its compiled digest. It is the rollback pointer of the pair: the
// host keeps this revision's files as its last-known-good state, so any later
// failed chain can be rolled back to it.
func confirmedLineRevisionTx(tx *sql.Tx, lineID string) (int64, string) {
	revision, digest, _, found, err := LatestPublishedCandidateTx(tx, lineID)
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
	revision, digest, _, found, err := LatestPublishedCandidateTx(tx, lineID)
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

// drainOutNodeIntentTx reconciles one Out with the currently derived
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
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return outDrainNoop, nil
	}
	if err != nil {
		return outDrainNoop, errors.New(CodeDatabaseUnavailable)
	}
	if role != string(nodeRoleOut) {
		return outDrainNoop, nil
	}
	latestRevision, latestDigest, _, hasCandidate, err := LatestPublishedCandidateTx(tx, outID)
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
	offline, err := SubscriberLineNodeOfflineTx(tx, outID, now)
	if err != nil {
		return outDrainNoop, err
	}
	if offline {
		return outDrainDeferred, errors.New("OUT_OFFLINE: out is offline; the authorization change stays pending")
	}
	revision, err := NextCandidateRevisionTx(tx, outID)
	if err != nil {
		return outDrainNoop, err
	}
	candidate, err := BuildLineCandidateTx(tx, outID, revision)
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
	published, present, err := OutReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return false, err
	}
	return present && node.SameACLSourceSet(published, desired), nil
}

// NextCandidateRevisionTx returns the next immutable revision of one node.
func NextCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	var revision int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		return 0, errors.New(CodeDatabaseUnavailable)
	}
	return revision, nil
}

// retryOutSync is the explicit retry and rollback pointer of one Out. It
// republishes a chain even when the desired authorization did not change, which is
// exactly what an operator needs after a partial/failed or superseded chain.
// Automatic polls never call it.
func (s *Store) RetryOutSync(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return errOutIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	outcome, err := DrainOutNodeIntentTx(tx, outID, now, true)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New(CodeDatabaseUnavailable)
	}
	if outcome == outDrainDeferred {
		return errors.New(CodeOutSyncPending + ": the out authorization change is queued behind an in-flight or offline out")
	}
	return nil
}

// drainOutNode begins its own transaction and reconciles one Out. Failures must
// not fail the request they serve: the next poll, heartbeat or result retries.
func (s *Store) drainOutNode(outID string, now time.Time) {
	tx, err := s.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := DrainOutNodeIntentTx(tx, outID, now, false); err != nil {
		return
	}
	_ = tx.Commit()
}

// outIDsForLine reads the Out pool in its own statement so no transaction is held
// open while the per-Out drain begins its own. Under the membership model every Out
// may accept every Line, so a Line event has to reach all of them.
func (s *Store) outIDsForLine(lineID string) ([]string, error) {
	return storeIDs(s.DB, `SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
}

// lineIDsForOut reads the enrolled Lines in their own statement. An Out event
// releases every Line that the Out may be authorizing, which is the whole pool.
func (s *Store) lineIDsForOut(outID string) ([]string, error) {
	return storeIDs(s.DB, `SELECT id FROM nodes WHERE role='edge' ORDER BY id ASC`)
}

// storeIDs runs one bounded identifier query and closes its rows before the
// caller opens another transaction on the single-connection pool.
func storeIDs(db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// drainOutsForLine is the "Line event" half of the coordination: a Line that just
// became verifiable, or whose snapshot was just confirmed, authorizes itself at
// every Out a subscription paired it with.
func (s *Store) DrainOutsForLine(lineID string, now time.Time) {
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
func (s *Store) drainLinesForOut(outID string, now time.Time) {
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
//   - a Line event first gives every paired Out the chance to authorize the Line,
//     then publishes the Line itself if the gate now passes.
//
// Each step owns its own transaction, so nothing nests on the single-connection
// pool. A failure in one direction never fails the request: the next event
// retries it.
func (s *Store) drainNodeCoordination(nodeID string, now time.Time) {
	var role string
	err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if err != nil {
		s.drainSubscriberNode(nodeID, now)
		return
	}
	if role == string(nodeRoleOut) {
		s.drainOutNode(nodeID, now)
		s.drainLinesForOut(nodeID, now)
		return
	}
	s.DrainOutsForLine(nodeID, now)
	s.drainSubscriberNode(nodeID, now)
}

// RepublishOutAuthorizations reconciles the whole Out pool with the current node
// membership.
//
// It is a *node lifecycle* primitive (Ruling R10): a Line or Out enrolling, losing
// its identity or being deleted changes the membership set, and every Out has to
// converge on the new list. A subscription edit deliberately does NOT call it — a
// subscription selects the client's egress, it does not authorize a source, so
// touching the ACL on a subscription change would be a second, unrelated truth.
//
// Each drain is a no-op unless that Out's derived list actually changed, so the
// call is safe to make after any lifecycle event. It runs after the caller's
// transaction committed and never fails it: the durable node state is the intent,
// so a deferred or failed publication is completed by the next Out event.
func (s *Store) RepublishOutAuthorizations(now time.Time) {
	outIDs, err := storeIDs(s.DB, `SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
	if err != nil {
		return
	}
	for _, outID := range outIDs {
		s.drainOutNode(outID, now)
	}
}

// RepublishLineAuthorizations re-derives and republishes every Line whose route may
// name an Out that no longer exists.
//
// It is the Line-side twin of RepublishOutAuthorizations and exists for the same kind
// of event: a node lifecycle change (Ruling R9 delete). Deleting an Out must not turn
// the Lines that used it into silent direct egress, so each Line is drained through
// the ordinary publication chain, where the policy resolver refuses an Out reference the Hub
// cannot justify (OUT_BINDING_INVALID) and an unavailable Out fails closed
// (OUT_OFFLINE_FAIL_CLOSED). A Line with no such policy publishes normally.
//
// Each drain owns its own transaction and never fails the caller: the delete is
// already durable, and the refusal is visible in the Line's own sync state.
func (s *Store) RepublishLineAuthorizations(now time.Time) {
	lineIDs, err := storeIDs(s.DB, `SELECT id FROM nodes WHERE role='edge' ORDER BY id ASC`)
	if err != nil {
		return
	}
	for _, lineID := range lineIDs {
		s.drainSubscriberNode(lineID, now)
	}
}

// nodeCoordinationReadback reports the readback state of one node for the audit
// log: a Line reports its egress pair, an Out reports its authorization. It is a
// read-only projection and never mutates or publishes; the returned codes are
// stable identifiers only.
//
// An Out reports the same retry semantics as a Line: only a terminal failure is
// retry-pending. A transition is still applying its own chain, and a healthy
// authorization has nothing left to retry.
func (s *Store) NodeCoordinationReadback(nodeID string, now time.Time) (OutEgressReadback, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return OutEgressReadback{}, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role); err != nil {
		return OutEgressReadback{}, errors.New(CodeDatabaseUnavailable)
	}
	if role == string(nodeRoleOut) {
		state, code, err := outSyncStatusTx(tx, nodeID, now)
		if err != nil {
			return OutEgressReadback{}, errors.New(CodeDatabaseUnavailable)
		}
		return OutEgressReadback{
			OutID:         nodeID,
			Allowlist:     state,
			AllowlistCode: code,
			FinalEgress:   state,
			RetryPending:  state == OutSyncPartial,
		}, nil
	}
	return outEgressReadbackTx(tx, nodeID, now)
}

// OutACLCleanTx reports whether the newest published chain of one Out already
// names an explicit empty authorization, and whether the node confirmed that
// exact revision. "Clean" needs the key present and empty: an omitted key means
// "no Hub expectation" and would hide a stale guard behind a shape-only check.
func OutACLCleanTx(tx *sql.Tx, outID string, revision int64, digest string) (bool, bool, error) {
	allowed, present, err := OutReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return false, false, err
	}
	if !present || len(allowed) != 0 {
		return false, false, nil
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, outID, revision, digest)
	if err != nil {
		return false, false, err
	}
	return true, confirmed, nil
}
