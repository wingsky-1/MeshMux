package store

// Read-only Line/subscriber projections used by the management page and the
// Line fan-out.
//
// The selection edge (subscription_lines) is the authoritative operator
// intent: it is what the wizard writes, what the used-by graph reads and what
// the Line has to serve. proxy_credentials is the materialization of that
// intent; it is unioned in only where history matters, because a dropped Line
// still has to lose its old UUID from the Line snapshot. Handlers read these
// answers here instead of querying the tables themselves.

import (
	"errors"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// SubscriberLineIDs returns the Lines one subscriber currently selects, in
// selection order (subscription_lines). It is the intent shown on the
// subscriber page; a credential row alone is never read as "selected".
func (s *Store) SubscriberLineIDs(subscriberID string) ([]string, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return nil, errSubscriberIDInvalid()
	}
	rows, err := s.DB.Query(`SELECT node_id FROM subscription_lines WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []string{}, nil
		}
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		out = append(out, nodeID)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return out, nil
}

// LineSubscriberIDs returns every subscriber that selects one Line now
// (subscription_lines) or ever held a credential on it (proxy_credentials).
//
// The selection edge is the authority for the current intent. The credential
// history is unioned in because a subscriber that dropped the Line still has
// a stale snapshot naming its old UUID: the next publication is what removes
// that UUID, so the fan-out must reach it too.
func (s *Store) LineSubscriberIDs(nodeID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT subscriber_id FROM (
	  SELECT subscriber_id FROM subscription_lines WHERE node_id=?
	  UNION
	  SELECT subscriber_id FROM proxy_credentials WHERE node_id=?
	) ORDER BY subscriber_id`, nodeID, nodeID)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var subscriberID string
		if err := rows.Scan(&subscriberID); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		out = append(out, subscriberID)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return out, nil
}
