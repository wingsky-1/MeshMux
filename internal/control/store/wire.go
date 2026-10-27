package store

// The assembly of the store's domains.
//
// The split gives every domain its own package, and the domains form a strict
// order: common and candidate are leaves, node is above them, policy and
// subscription are above node, and upgrade is above all of them. One edge of the
// real data model points the other way, and this file is the only place it is
// joined:
//
//   - node needs the subscriber convergence view, the delete finalization, the
//     selection used-by projections and the drain. It declares them as the
//     node.Subscribers port, and the subscription handle satisfies it.
//
// The join runs once, after the database opens. Nothing else in the tree wires
// two domains together, and no domain imports a sibling that would import it
// back.

// wire joins the handles. It runs once, before the first request is served.
func (s *Store) wire() {
	s.candidateHandle.DB = s.DB
	s.meshHandle.DB = s.DB

	s.nodeHandle.DB = s.DB
	s.nodeHandle.Candidates = s.candidateHandle
	s.nodeHandle.Subscribers = s.subscriptionHandle

	s.policyHandle.DB = s.DB

	s.subscriptionHandle.DB = s.DB
	s.subscriptionHandle.Candidates = s.candidateHandle

	s.upgradeHandle.DB = s.DB
}
