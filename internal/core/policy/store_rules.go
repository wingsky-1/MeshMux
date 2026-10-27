package policy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// SchemaDDL creates the rule library table. Rows are immutable by contract:
// (stable_key, version) is the identity Task 4 pins in its snapshot, name is
// deliberately not unique, and match/action changes arrive only as new
// versions. The DDL is idempotent so a replayed migration cannot fail on its
// own earlier write.
func SchemaDDL() string {
	return `CREATE TABLE IF NOT EXISTS policy_rules (
  stable_key TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version>0),
  name TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('direct','proxy','reject')),
  matcher_kind TEXT NOT NULL CHECK(matcher_kind IN ('domain','domain_suffix','ipcidr','geosite','geoip','ruleset')),
  matcher_value TEXT NOT NULL,
  origin TEXT NOT NULL CHECK(origin IN ('preset','custom')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(stable_key, version)
);
CREATE INDEX IF NOT EXISTS policy_rules_origin ON policy_rules(origin, stable_key);
`
}

// SeedPresetsTx inserts the bundle at PresetBundleVersion. It is insert-only:
// a re-seed keeps existing rows (same key and version) and never edits them,
// so a replay cannot rewrite a row a subscription already pinned.
func SeedPresetsTx(tx *sql.Tx, now int64) error {
	for _, p := range Presets {
		encoded, err := json.Marshal(p.Values)
		if err != nil {
			return errors.New("RULE_SEED_FAILED: the preset bundle could not be encoded")
		}
		if _, err := tx.Exec(`INSERT INTO policy_rules(stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at)
		  VALUES(?,?,?,?,?,?,?,?,?)
		  ON CONFLICT(stable_key, version) DO NOTHING`,
			p.StableKey, PresetBundleVersion, p.Name, string(p.Action), string(p.Kind), string(encoded), string(OriginPreset), now, now); err != nil {
			return errors.New("RULE_SEED_FAILED: the preset bundle was not stored")
		}
	}
	return nil
}

// Store is the rule-library persistence on a *sql.DB the caller owns (the Hub
// store hands over its handle; policy never opens a database itself).
//
// The library owns only policy_rules. The subscriptions that pin a revision
// live in the control layer's edge tables, so the used-by answer (and the
// delete guard derived from it) is an injected port, implemented by that
// layer: policy never names subscription_rules or subscribers.
type Store struct {
	db    *sql.DB
	usage RuleUsageReader
}

// New wraps the caller's database handle and the control-layer used-by reader.
// The reader may not be nil: without it the delete guard cannot prove that a
// revision is unused, so the guard fails closed instead of guessing.
func New(db *sql.DB, usage RuleUsageReader) *Store { return &Store{db: db, usage: usage} }

// Querier is the shared surface of *sql.DB and *sql.Tx the library reads
// through, so the delete guard can run its check and its delete in one
// transaction (I1).
type Querier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// RuleUsageReader names the subscriptions that pin one rule revision. The
// control layer owns those edge tables and implements this port; the querier is
// the caller's transaction, so the delete guard's check and delete stay one
// atomic unit (I1) without policy reading a control table itself.
type RuleUsageReader interface {
	RuleUsedBy(q Querier, stableKey string, version int) ([]RuleUsage, error)
}

// RuleUsage names one subscriber that references a rule revision. It is the
// delete guard's evidence and the used-by answer: both read this one query.
type RuleUsage struct {
	SubscriberID   string
	SubscriberName string
}

// DisplayName renders the usage for operator output. An orphan edge row (a
// reference whose subscriber is gone) has no name; it still counts and is
// shown by id, never silently dropped (I4).
func (u RuleUsage) DisplayName() string {
	if u.SubscriberName != "" {
		return u.SubscriberName
	}
	return "订阅 " + u.SubscriberID
}

func scanRule(row interface{ Scan(...any) error }) (Rule, error) {
	var r Rule
	var action, kind, origin, encoded string
	err := row.Scan(&r.StableKey, &r.Version, &r.Name, &action, &kind, &encoded, &origin, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, errors.New(CodeNotFound + ": unknown rule revision")
	}
	if err != nil {
		return Rule{}, errors.New(versions.CodeDatabaseUnavailable)
	}
	var values []string
	if err := json.Unmarshal([]byte(encoded), &values); err != nil {
		return Rule{}, errors.New("RULE_CORRUPT: stored matcher JSON is invalid")
	}
	r.Action, r.Kind, r.Values, r.Origin = Action(action), MatcherKind(kind), values, Origin(origin)
	return r, nil
}

const ruleSelect = `SELECT stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at FROM policy_rules`

func uniqueConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateCustomRule inserts version 1 under a fresh stable_key. A key that
// already exists (any version) or that squats the preset namespace is
// refused; a new version of an existing key is ReviseCustomRule's job.
func (s *Store) CreateCustomRule(stableKey, name string, action Action, kind MatcherKind, values []string, now time.Time) (Rule, error) {
	key := strings.TrimSpace(stableKey)
	if IsPresetKey(key) {
		return Rule{}, errors.New(CodePresetImmutable + ": stable_key " + key + " is reserved for the seed bundle")
	}
	r := Rule{StableKey: key, Name: strings.TrimSpace(name), Action: action, Kind: kind, Values: values}
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	encoded, err := json.Marshal(r.Values)
	if err != nil {
		return Rule{}, errors.New(CodeInvalid + ": matcher values could not be encoded")
	}
	unix := now.Unix()
	if _, err := s.db.Exec(`INSERT INTO policy_rules(stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at)
	  VALUES(?,1,?,?,?,?,?,?,?)`, r.StableKey, r.Name, string(r.Action), string(r.Kind), string(encoded), string(OriginCustom), unix, unix); err != nil {
		if uniqueConflict(err) {
			return Rule{}, errors.New(CodeConflict + ": stable_key " + r.StableKey + " already exists; revise it for a new version")
		}
		return Rule{}, errors.New(versions.CodeDatabaseUnavailable)
	}
	return s.GetRule(r.StableKey, 1)
}

// ReviseCustomRule inserts version+1 under the same stable_key. The old rows
// stay byte-identical so pinned subscriptions are unaffected; only an
// explicit operator migration (Task 4) moves a subscription forward. Preset
// keys are refused with RULE_PRESET_IMMUTABLE.
func (s *Store) ReviseCustomRule(stableKey, name string, action Action, kind MatcherKind, values []string, now time.Time) (Rule, error) {
	key := strings.TrimSpace(stableKey)
	if IsPresetKey(key) {
		return Rule{}, errors.New(CodePresetImmutable + ": preset rule " + key + " cannot be revised; it is replaced by versioned migration only")
	}
	latest, err := s.LatestRule(key)
	if err != nil {
		return Rule{}, err
	}
	if latest.Origin == OriginPreset {
		return Rule{}, errors.New(CodePresetImmutable + ": preset rule " + key + " cannot be revised; it is replaced by versioned migration only")
	}
	r := Rule{StableKey: key, Name: strings.TrimSpace(name), Action: action, Kind: kind, Values: values}
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	encoded, err := json.Marshal(r.Values)
	if err != nil {
		return Rule{}, errors.New(CodeInvalid + ": matcher values could not be encoded")
	}
	unix := now.Unix()
	if _, err := s.db.Exec(`INSERT INTO policy_rules(stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at)
	  VALUES(?,?,?,?,?,?,?,?,?)`, key, latest.Version+1, r.Name, string(r.Action), string(r.Kind), string(encoded), string(OriginCustom), unix, unix); err != nil {
		if uniqueConflict(err) {
			return Rule{}, errors.New(CodeConflict + ": rule " + key + " was revised concurrently")
		}
		return Rule{}, errors.New(versions.CodeDatabaseUnavailable)
	}
	return s.GetRule(key, latest.Version+1)
}

// GetRule reads one immutable revision.
func (s *Store) GetRule(stableKey string, version int) (Rule, error) {
	return getRule(s.db, stableKey, version)
}

func getRule(q Querier, stableKey string, version int) (Rule, error) {
	if version < 1 {
		return Rule{}, errors.New(CodeNotFound + ": unknown rule revision")
	}
	return scanRule(q.QueryRow(ruleSelect+` WHERE stable_key=? AND version=?`, stableKey, version))
}

// LatestRule reads the highest version under a key.
func (s *Store) LatestRule(stableKey string) (Rule, error) {
	if strings.TrimSpace(stableKey) == "" {
		return Rule{}, errors.New(CodeNotFound + ": unknown rule")
	}
	return scanRule(s.db.QueryRow(ruleSelect+` WHERE stable_key=? ORDER BY version DESC LIMIT 1`, stableKey))
}

// ListRules returns every row of one origin ("preset", "custom", or "" for
// all), newest first. LatestRules (below) is the page query; this one feeds
// audits and the version history.
func (s *Store) ListRules(origin string) ([]Rule, error) {
	query := ruleSelect
	var args []any
	if origin != "" {
		if origin != string(OriginPreset) && origin != string(OriginCustom) {
			return nil, errors.New(CodeInvalid + ": origin must be preset or custom")
		}
		query += ` WHERE origin=?`
		args = []any{origin}
	}
	rows, err := s.db.Query(query+` ORDER BY stable_key, version DESC`, args...)
	if err != nil {
		return nil, errors.New(versions.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(versions.CodeDatabaseUnavailable)
	}
	if out == nil {
		out = []Rule{}
	}
	return out, nil
}

// LatestRules returns the newest version of every key, presets first, then
// customs by key. It is the single list the library page renders.
func (s *Store) LatestRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT p.stable_key, p.version, p.name, p.action, p.matcher_kind, p.matcher_value, p.origin, p.created_at, p.updated_at
	  FROM policy_rules p WHERE p.version=(SELECT MAX(version) FROM policy_rules WHERE stable_key=p.stable_key)
	  ORDER BY CASE p.origin WHEN 'preset' THEN 0 ELSE 1 END, p.stable_key`)
	if err != nil {
		return nil, errors.New(versions.CodeDatabaseUnavailable)
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(versions.CodeDatabaseUnavailable)
	}
	return out, nil
}

// DeleteRule removes one unreferenced custom revision. Preset rows are
// refused with RULE_PRESET_IMMUTABLE; a revision referenced by any
// subscription is refused with RULE_REFERENCED_BY_SUBSCRIPTIONS carrying the
// subscriber names from the same RuleUsedBy query the page shows. The check
// and the delete run in one transaction, so a concurrent reference write
// cannot slip between them and leave a dangling edge (I1).
func (s *Store) DeleteRule(stableKey string, version int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.New(versions.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	r, err := getRule(tx, stableKey, version)
	if err != nil {
		return err
	}
	if r.Origin == OriginPreset || IsPresetKey(r.StableKey) {
		return errors.New(CodePresetImmutable + ": preset rule " + r.StableKey + " cannot be deleted; it is replaced by versioned migration only")
	}
	used, err := s.ruleUsedBy(tx, stableKey, version)
	if err != nil {
		return err
	}
	if len(used) > 0 {
		names := make([]string, 0, len(used))
		for _, u := range used {
			names = append(names, u.DisplayName())
		}
		return errors.New(CodeReferenced + ": rule " + stableKey + " v" + itoa(version) +
			" is still referenced by " + itoa(len(used)) + " subscription(s): " + strings.Join(names, "、") +
			"; migrate those subscriptions first")
	}
	result, err := tx.Exec(`DELETE FROM policy_rules WHERE stable_key=? AND version=?`, stableKey, version)
	if err != nil {
		return errors.New(versions.CodeDatabaseUnavailable)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New(versions.CodeDatabaseUnavailable)
	}
	if err := tx.Commit(); err != nil {
		return errors.New(versions.CodeDatabaseUnavailable)
	}
	return nil
}

// RuleUsedBy names the subscribers referencing one rule revision. The
// reference edge (subscription_rules) is owned by the control layer, so the
// answer is delegated to the injected reader; policy never queries a control
// table itself. The delete guard calls the same reader inside its transaction,
// so the page and the refusal cannot disagree (I1, I4).
func (s *Store) RuleUsedBy(stableKey string, version int) ([]RuleUsage, error) {
	return s.ruleUsedBy(s.db, stableKey, version)
}

// ruleUsedBy is the one read path of the used-by port, shared by the page and
// the delete guard's transaction. A missing reader is database doubt, never
// "nobody references this" (C1).
func (s *Store) ruleUsedBy(q Querier, stableKey string, version int) ([]RuleUsage, error) {
	if s.usage == nil {
		return nil, errors.New(versions.CodeDatabaseUnavailable)
	}
	return s.usage.RuleUsedBy(q, stableKey, version)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
