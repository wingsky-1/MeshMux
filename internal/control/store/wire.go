package store

// The assembly of the store's domains.
//
// The split gives every domain its own package, and the domains form a strict
// order: common and candidate are leaves, node is above them, policy and
// subscription are above node, and upgrade is above all of them. Two edges of
// the real data model point the other way, and this file is the only place they
// are joined:
//
//   - node needs the subscriber convergence view, the delete finalization, the
//     selection used-by projections and the drain. It declares them as the
//     node.Subscribers port, and the subscription handle satisfies it.
//   - candidate needs the Out source authorization to build an Out chain. The
//     node domain owns the derivation, so it is passed in at the call site
//     rather than imported.
//
// Both are satisfied here, once, after the database opens. Nothing else in the
// tree wires two domains together, and no domain imports a sibling that would
// import it back.

// wire joins the handles. It runs once, before the first request is served.
func (s *Store) wire() {
	s.candidateHandle.DB = s.DB
	s.meshHandle.DB = s.DB

	s.nodeHandle.DB = s.DB
	s.nodeHandle.Candidates = s.candidateHandle
	s.nodeHandle.Subscribers = s.subscriptionHandle

	s.policyHandle.DB = s.DB
	s.policyHandle.Nodes = s.nodeHandle

	s.subscriptionHandle.DB = s.DB
	s.subscriptionHandle.Nodes = s.nodeHandle
	s.subscriptionHandle.Candidates = s.candidateHandle
	s.subscriptionHandle.Policies = s.policyHandle

	s.upgradeHandle.DB = s.DB
	s.upgradeHandle.Nodes = s.nodeHandle
	s.upgradeHandle.Policies = s.policyHandle
}
