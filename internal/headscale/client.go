// Package headscale is the Hub-side adapter for the local Headscale control
// plane. It is the only place in MeshMux that talks to Headscale, and it does
// so through the pinned headscale executable over the fixed local unix socket
// of the Hub layout. It adds no Go dependency: Headscale's gRPC/protobuf client
// is not imported, so the Hub keeps its small, auditable dependency set.
//
// Scope of this package (PR-9a-2, extended by PR-9b-1):
//   - one narrow Client interface (users, nodes, one-time pre-auth keys, route
//     approval);
//   - narrow DTOs that carry only what the mesh domain needs. A node's nested
//     pre_auth_key block, including its key field, is dropped while decoding,
//     and the one plaintext pre-auth key returned by CreatePreAuthKey is a
//     separate one-shot value: it is never part of a DTO, never persisted by
//     this package and never logged;
//   - a fixed command table. Every call uses the same executable path, the
//     same --config file, machine-readable output, no shell and a hard timeout.
//     Node deletion always passes --force because a Headscale prompt would
//     block a service; the prompt is what the Hub itself replaces with an
//     explicit, audited user action.
//   - a version handshake. `headscale version -o json` must report exactly
//     HeadscaleVersion before any change is attempted; a different release is
//     refused with HEADSCALE_VERSION_MISMATCH instead of being probed with
//     flags that may mean something else.
//
// Deliberately absent: preauthkeys list. Headscale prints pre-auth key
// material in that listing, and MeshMux only needs the key it just minted for
// one device. Also absent: nodes list-routes, because `nodes list` already
// reports approved, available and subnet routes together with the node they
// belong to, and node rename and user deletion, which this Hub does not offer.
//
// Route approval (PR-9b-1) is a set operation on one node: SetApprovedRoutes
// replaces the approved list, ClearApprovedRoutes empties it, and both return
// the node Headscale reports afterwards. The adapter refuses an exit route and a
// prefix with host bits set before the CLI runs; canonicalising accepted
// prefixes belongs to the mesh domain, not here.
//
// This package performs no Web, SQLite, subscription or installer work. It
// executes no arbitrary command: the executable path and the argv shapes are
// fixed constants, and caller-supplied values are validated before they reach
// an argument.
package headscale

import (
	"context"
	"errors"
	"time"
)

// HeadscaleVersion is the single pinned Headscale release of a MeshMux Hub.
// The installer artifacts and this adapter share this value, so a release bump
// cannot update the downloaded binary while leaving the command contract or the
// version handshake behind. A drift test in internal/install enforces it.
const HeadscaleVersion = "0.29.5"

// The stable codes this package reports. They are the diagnostic contract: a
// caller logs the code and the operation id, never the Headscale stderr text,
// the socket path of another host, the pre-auth key or a node key.
const (
	// CodeVersionMismatch: the installed executable is not HeadscaleVersion,
	// so no change is attempted.
	CodeVersionMismatch = "HEADSCALE_VERSION_MISMATCH"
	// CodeSocketUnavailable: the local unix socket exists but this process may
	// not use it, or it is gone. The Hub layout must be inspected; the adapter
	// does not retry with a different address or credential.
	CodeSocketUnavailable = "HEADSCALE_SOCKET_UNAVAILABLE"
	// CodeUnavailable: the executable is missing or the local service refused
	// the connection.
	CodeUnavailable = "HEADSCALE_UNAVAILABLE"
	// CodeTimeout: the fixed command deadline elapsed. The context cancellation
	// kills the child process; the caller reports failure instead of waiting.
	CodeTimeout = "HEADSCALE_TIMEOUT"
	// CodeCommandFailed: Headscale rejected the command for a reason this
	// adapter has no stable mapping for. No stderr text is exposed.
	CodeCommandFailed = "HEADSCALE_COMMAND_FAILED"
	// CodeOutputInvalid: the machine-readable output was empty, oversized or
	// not the documented JSON shape. A half-parsed answer is never returned.
	CodeOutputInvalid = "HEADSCALE_OUTPUT_INVALID"
	// CodeArgumentInvalid: a caller-supplied value is outside the fixed shape
	// (a zero id, a non-canonical user name, an unsafe key lifetime).
	CodeArgumentInvalid = "HEADSCALE_ARGUMENT_INVALID"
	// CodeCanceled: the caller's context was canceled before Headscale answered.
	CodeCanceled = "HEADSCALE_CANCELED"
	// CodeNotFound: Headscale reported that the named node, user or key does
	// not exist. A retried node deletion treats this as already settled.
	CodeNotFound = "HEADSCALE_NOT_FOUND"
	// CodeAlreadyExists: the requested name is taken. Creating the shared user
	// again is the ordinary case, so the caller resolves it by listing.
	CodeAlreadyExists = "HEADSCALE_ALREADY_EXISTS"
	// CodeRouteInvalid: a route prefix is not a usable LAN subnet. The adapter
	// refuses an unparseable prefix, an exit route (/0) and a prefix with host
	// bits set before the CLI runs, and Headscale reports its own parse failure
	// with the same code. Approving an exit route would make one node the
	// default gateway of the whole tailnet, which is not a MeshMux capability.
	CodeRouteInvalid = "HEADSCALE_ROUTE_INVALID"
)

// Error is a stable, log-safe refusal. Code is one of the constants above and
// Error returns only that code: Headscale stderr can quote key material, socket
// paths and node names, so it stays out of the error value.
type Error struct {
	Code string
}

func (e *Error) Error() string { return e.Code }

func failure(code string) error { return &Error{Code: code} }

// CodeOf returns the stable code of a refusal from this package, or "" when err
// does not carry one.
func CodeOf(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

// User is one Headscale user. The shared default user of D2 is "meshmux"; this
// adapter can list and create users and never deletes one.
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Email       string
}

// Node is one Headscale node. The record is a snapshot of what Headscale
// reports; the durable mesh identity stays in internal/mesh and references the
// immutable ID. PreAuthKey material is absent by construction (narrow decode).
type Node struct {
	ID              uint64
	Name            string
	GivenName       string
	UserID          uint64
	UserName        string
	IPAddresses     []string
	ApprovedRoutes  []string
	AvailableRoutes []string
	SubnetRoutes    []string
	Online          bool
	Expiry          time.Time
}

// PreAuthKey is the non-secret part of a one-time enrollment key. It has no
// field for the key itself: CreatePreAuthKey returns the plaintext once as a
// separate value, and the plaintext is never returned again, stored here or
// logged.
type PreAuthKey struct {
	ID         uint64
	UserID     uint64
	Reusable   bool
	Ephemeral  bool
	Expiration time.Time
	CreatedAt  time.Time
}

// PreAuthKeyRequest is the narrow key creation input: one user and one short
// lifetime. Reusable and ephemeral are fixed to false by the command table,
// because a MeshMux device enrolls once and must keep its node after enrollment.
type PreAuthKeyRequest struct {
	UserID   uint64
	Validity time.Duration
}

// Client is the narrow Headscale capability set of a MeshMux Hub. It is an
// interface so the mesh wiring of a later PR can be tested without a live
// Headscale; the only production implementation is CLIRunner.
type Client interface {
	ListUsers(ctx context.Context) ([]User, error)
	CreateUser(ctx context.Context, name string) (User, error)
	ListNodes(ctx context.Context, user string) ([]Node, error)
	// CreatePreAuthKey mints one non-reusable key and returns its plaintext
	// once. The caller hands it to the enrolling device and must not persist or
	// log it; a second read is impossible because this package has no listing.
	CreatePreAuthKey(ctx context.Context, req PreAuthKeyRequest) (PreAuthKey, string, error)
	ExpirePreAuthKey(ctx context.Context, id uint64) error
	ExpireNode(ctx context.Context, id uint64) error
	DeleteNode(ctx context.Context, id uint64) error
	// SetApprovedRoutes replaces the approved route list of one node and
	// returns the node Headscale reports afterwards. The input is the complete
	// desired set, not an addition; at least one prefix is required and clearing
	// has its own method.
	SetApprovedRoutes(ctx context.Context, id uint64, prefixes []string) (Node, error)
	// ClearApprovedRoutes removes every approved route of one node and returns
	// the node Headscale reports afterwards. The node stays registered and keeps
	// its advertised routes; only approval is withdrawn.
	ClearApprovedRoutes(ctx context.Context, id uint64) (Node, error)
}
