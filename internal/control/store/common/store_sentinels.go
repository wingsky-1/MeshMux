package common

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
	// ErrNodeNotFound is the refusal of every node read that finds no row.
	ErrNodeNotFound = errors.New("NODE_NOT_FOUND")
	// ErrNodeNotFoundDetail names the node in operator text.
	ErrNodeNotFoundDetail = errors.New("NODE_NOT_FOUND: unknown node")
	// ErrLineNotFound names a Line read that finds no row.
	ErrLineNotFound = errors.New("LINE_NOT_FOUND: unknown line node")
	// ErrOutNotFound names an Out read that finds no row.
	ErrOutNotFound = errors.New("OUT_NOT_FOUND: unknown out node")
	// ErrSubscriberNotFound names a subscriber read that finds no row.
	ErrSubscriberNotFound = errors.New("SUBSCRIBER_NOT_FOUND: unknown subscription user")
	// ErrCandidateNotFound names a candidate read that finds no row.
	ErrCandidateNotFound = errors.New("CANDIDATE_NOT_FOUND")
	// ErrCandidateCorrupt names a candidate row that exists but cannot be
	// parsed or does not satisfy the candidate contract.
	ErrCandidateCorrupt = errors.New("CANDIDATE_CORRUPT")
	// ErrReadbackInvalid names an Agent readback that is not the frozen shape.
	ErrReadbackInvalid = errors.New("READBACK_INVALID")
)
