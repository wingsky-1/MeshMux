package store

// Sentinel refusals the store emits from more than one file.
//
// A missing record and a corrupt record are the two answers every read path
// repeats: "this identity does not exist" and "this row exists but cannot be
// trusted". Both are declared here once so the code, and the detail a page
// renders, cannot drift between a Line, an Out, a node and a candidate.
//
// Errors, not values: a caller compares by code (ErrorCodeOf) or wraps the
// sentinel with a stable prefix. None of these is ever returned bare to an
// operator page without that code.

import "errors"

var (
	// errNodeNotFound is the refusal of every node read that finds no row.
	errNodeNotFound = errors.New("NODE_NOT_FOUND")
	// errNodeNotFoundDetail names the node in operator text.
	errNodeNotFoundDetail = errors.New("NODE_NOT_FOUND: unknown node")
	// errLineNotFound names a Line read that finds no row.
	errLineNotFound = errors.New("LINE_NOT_FOUND: unknown line node")
	// errOutNotFound names an Out read that finds no row.
	errOutNotFound = errors.New("OUT_NOT_FOUND: unknown out node")
	// errSubscriberNotFound names a subscriber read that finds no row.
	errSubscriberNotFound = errors.New("SUBSCRIBER_NOT_FOUND: unknown subscription user")
	// errCandidateNotFound names a candidate read that finds no row.
	errCandidateNotFound = errors.New("CANDIDATE_NOT_FOUND")
	// errCandidateCorrupt names a candidate row that exists but cannot be
	// parsed or does not satisfy the candidate contract.
	errCandidateCorrupt = errors.New("CANDIDATE_CORRUPT")
	// errReadbackInvalid names an Agent readback that is not the frozen shape.
	errReadbackInvalid = errors.New("READBACK_INVALID")
)
