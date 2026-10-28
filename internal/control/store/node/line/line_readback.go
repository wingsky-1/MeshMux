package line

// The confirmed-snapshot facts of one Line.
//
// The immutable candidate chain is the only publication record, and a healthy
// readback of an exact revision with the same compiled digest is the only proof
// the Agent applied it. These two reads are the Line half of that evidence: the
// newest confirmed revision with its digest (the rollback pointer) and whether
// that candidate still carries the REALITY block its stored transport describes.
//
// They live here because they read a Line's own candidate chain; the Out
// projection consumes them and never re-derives a second answer.

import (
	"database/sql"
	"encoding/json"

	candidatepkg "github.com/wingsky-1/MeshMux/internal/control/store/candidate"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// ConfirmedRevisionTx returns the newest Line revision the node confirmed
// together with its compiled digest. It is the rollback pointer of the Line: the
// host keeps this revision's files as its last-known-good state, so any later
// failed chain can be rolled back to it.
func ConfirmedRevisionTx(tx *sql.Tx, lineID string) (int64, string) {
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, lineID)
	if err != nil || !found {
		return 0, ""
	}
	confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return 0, ""
	}
	return revision, digest
}

// RealityConfirmedTx reports whether the latest confirmed Line candidate still
// carries the REALITY block its stored transport describes. A Line without that
// block could not serve the client configuration the Hub publishes, so an egress
// is never claimed healthy on the routing state alone.
func RealityConfirmedTx(tx *sql.Tx, lineID string) bool {
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, lineID)
	if err != nil || !found {
		return false
	}
	confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return false
	}
	var candidateJSON string
	if err := tx.QueryRow(`SELECT candidate_json FROM node_candidates WHERE node_id=? AND revision=?`, lineID, revision).
		Scan(&candidateJSON); err != nil {
		return false
	}
	var document coredomain.CandidateDocument
	if json.Unmarshal([]byte(candidateJSON), &document) != nil {
		return false
	}
	return document.Reality != nil && document.Role == coredomain.RoleEdge
}
