package subscription

// Subscribers, their credentials and the subscription workspace.
//
// This is the top of the store's dependency order: it reads Lines, candidates,
// egress facts and policy revisions from the domains below it, and none of them
// imports it. The two facts it must supply upwards — node's convergence view and
// delete finalization — are exported here and wired into the node domain by the
// root assembly (storenode.Subscribers), so the cycle stays broken.
//
// The flow is one order and every step is a separate public function:
//
//	SelectionSpec.Normalize   the input boundary
//	reference validation      existence, egress role whitelist, same-Line Out
//	the one composer-input builder (draft and download share it)
//	draft -> preview -> approve -> save, and the snapshot read-back
//	persistence only          the edge tables, the snapshot row, used-by
//	download                  re-derive and compare the approved digest
//	impact preview            read-only, reserved extension
//	batch re-approval         per-subscriber, partial success

import (
	"database/sql"

	"github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
	storepolicy "github.com/wingsky-1/MeshMux/internal/control/store/policy"
)

// Store is the subscription persistence handle. The root store embeds one
// around the same connection.
type Store struct {
	DB *sql.DB

	// Nodes supplies the Line snapshot, the route and the egress facts a
	// subscription publishes against.
	Nodes *storenode.Store
	// Candidates is the shared candidate/task leaf.
	Candidates *candidate.Store
	// Policies supplies the active policy revision the desired Line route is
	// derived from.
	Policies *storepolicy.Store
}
