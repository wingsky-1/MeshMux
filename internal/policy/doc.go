// Package policy is the rule-library domain of the subscription aggregation
// rebuild (Task 3, ADR-0008 §5): the rule model with its six matcher kinds and
// three actions, the versioned preset seed bundle, and the immutable-row store
// (identity = stable_key + version) with the preset write guard and the
// subscription used-by lookup that the delete path shares.
//
// Dependency direction: policy imports compiler (matcher value semantics) and
// the standard library only. It never imports internal/web/*; the Hub SQLite
// migration in internal/web/store reuses SchemaDDL and SeedPresetsTx, and the
// handler calls the Store on the same *sql.DB the web store owns.
//
// Validation is per row (Rule.Validate) plus the store's identity guard. A
// cross-row shadow/overlap check used to live here as ValidateRuleSet; it was
// removed in Task 6 because the subscription composer owns the selected set and
// rejects duplicates/overlaps at composition time (COMPOSE_RULE_DUPLICATE /
// COMPOSE_RULE_CONFLICT), so there is exactly one set-level validator.
package policy
