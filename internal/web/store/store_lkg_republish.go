package store

// LKG republish (#11c-3 Task 4, spec §4.11).
//
// The rollback target is the Agent's last-known-good candidate revision, which
// the Hub already observes in nodes.observed_revision. The explicit rollback
// action republishes that exact document as a NEW immutable revision through
// the existing fixed four-task chain. It touches no StageTarget/upgrade-target
// interface and never stamps a target, so a node whose running revision equals
// the republished one keeps the plain-stage semantics (ruling U5: a rollback
// chain may legitimately target a revision behind the current candidate).
//
// The revision is never caller-supplied: it comes from the Agent's own
// readback. A failed upgrade's rollback is therefore one explicit operator
// action, not a guessed version.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/node/protocol"
)

// republishLKG stores the observed LKG candidate as the next immutable revision
// and enqueues the fixed four-task chain in the same transaction. No adjacency
// or upgrade-version rule applies (U5 exemption), and no upgrade target is
// stamped.
func (s *Store) RepublishLKG(nodeID string, now time.Time) (storedCandidate, []protocol.Task, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var observed int64
	if err = tx.QueryRow(`SELECT observed_revision FROM nodes WHERE id=?`, nodeID).Scan(&observed); errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, nil, errNodeNotFound
	} else if err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	if observed < 1 {
		return storedCandidate{}, nil, errors.New("LKG_UNAVAILABLE: the node has no observed last-known-good revision")
	}
	var unfinished int
	if err = tx.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status IN ('pending','applying','verifying')`,
		nodeID).Scan(&unfinished); err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	if unfinished != 0 {
		return storedCandidate{}, nil, errors.New("TASKS_IN_PROGRESS: the node has an unfinished task chain")
	}
	var document []byte
	if err = tx.QueryRow(`SELECT candidate_json FROM node_candidates WHERE node_id=? AND revision=?`,
		nodeID, observed).Scan(&document); errors.Is(err, sql.ErrNoRows) {
		return storedCandidate{}, nil, errors.New("LKG_UNAVAILABLE: the observed revision has no stored candidate")
	} else if err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	var stored node.CandidateDocument
	if err := json.Unmarshal(document, &stored); err != nil || stored.Revision != observed || stored.NodeID != nodeID {
		return storedCandidate{}, nil, errors.New("LKG_UNAVAILABLE: the observed candidate is not readable")
	}
	var next int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&next); err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	candidate := stored.Candidate()
	candidate.Revision = next
	if err := candidate.Validate(); err != nil {
		return storedCandidate{}, nil, errors.New("LKG_UNAVAILABLE: the observed candidate is not valid")
	}
	// The fixed publication path: one immutable revision plus the four tasks,
	// committed together. No stampUpgradeTargetTx call: the stage row stays a
	// plain config stage.
	tasks, err := publishCandidateTx(tx, nodeID, candidate, now)
	if err != nil {
		return storedCandidate{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return storedCandidate{}, nil, errors.New(CodeDatabaseUnavailable)
	}
	republished, err := s.Candidate(nodeID, next)
	if err != nil {
		// The chain is already committed. Say so explicitly: the caller must
		// not report "not published" and invite a duplicate submission.
		return storedCandidate{}, nil, fmt.Errorf("LKG_ROLLBACK_READBACK_FAILED: %w", err)
	}
	return republished, tasks, nil
}
