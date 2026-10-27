package store

// Used-by answer for the rule library, owned by the control layer.
//
// subscription_rules and subscribers are business tables of this layer; the
// policy core owns only its immutable policy_rules rows. The rule library
// therefore asks through policy.RuleUsageReader, and this file is the only
// SQL that answers it. The reader runs on the caller's querier, which lets the
// delete guard's check and delete share one transaction (I1) while the page
// read uses the pool.

import (
	"database/sql"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// RuleUsageSource returns the control-layer implementation of policy's used-by
// port. It is stateless: every call runs on the querier the policy store hands
// in, so a page read and the delete guard's transaction see the same rows.
func RuleUsageSource() policy.RuleUsageReader { return ruleUsageSource{} }

type ruleUsageSource struct{}

// RuleUsedBy names the subscribers referencing one rule revision. A missing
// edge table is honest emptiness (a database that has not reached schema 13
// yet), so the library works before the subscription wizard lands. Any other
// database doubt — a partially migrated edge table with the wrong columns, an
// unreadable subscribers table — is fail-closed (DATABASE_UNAVAILABLE), never
// mistaken for "nobody references this" (C1). Orphan edge rows (no matching
// subscriber) still count via the LEFT JOIN and surface by id, so a missing
// cascade can never blind the delete guard (I4).
//
// Column names are the selection contract:
// subscription_rules(subscriber_id, rule_stable_key, rule_version, position).
func (ruleUsageSource) RuleUsedBy(q policy.Querier, stableKey string, version int) ([]policy.RuleUsage, error) {
	var table string
	if err := q.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='subscription_rules'`).Scan(&table); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []policy.RuleUsage{}, nil
		}
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	rows, err := q.Query(`SELECT r.subscriber_id, COALESCE(s.display_name,'') FROM subscription_rules r
	  LEFT JOIN subscribers s ON s.id=r.subscriber_id
	  WHERE r.rule_stable_key=? AND r.rule_version=? ORDER BY COALESCE(s.display_name,''), r.subscriber_id`, stableKey, version)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []policy.RuleUsage{}
	for rows.Next() {
		var u policy.RuleUsage
		if err := rows.Scan(&u.SubscriberID, &u.SubscriberName); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	return out, nil
}
