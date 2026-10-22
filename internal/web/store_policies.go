package web

// Policy persistence for issue #10 (10d-1a): schema 8 revision chains, create
// and read paths, and guarded intent payloads. Publication remains 10d-2.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

type PolicyLayer string
type PolicyStatus string

const (
	PolicyLayerClient PolicyLayer  = "client"
	PolicyLayerServer PolicyLayer  = "server"
	PolicyDraft       PolicyStatus = "draft"
	PolicyActive      PolicyStatus = "active"
	PolicySuperseded  PolicyStatus = "superseded"
	PolicyRevoked     PolicyStatus = "revoked"
	policyMaxBytes                 = 64 << 10
)

type RoutePolicy struct {
	ID, Name    string
	Layer       PolicyLayer
	Payload     json.RawMessage
	Pins        json.RawMessage
	Revision    int64
	Status      PolicyStatus
	OperationID string
	CreatedAt   int64
	UpdatedAt   int64
}

type routePolicyPayload struct {
	Default    compiler.Action `json:"default"`
	Rules      []compiler.Rule `json:"rules"`
	Exceptions []string        `json:"exceptions,omitempty"`
	SSIDs      []string        `json:"ssids,omitempty"`
	Note       string          `json:"note,omitempty"`
}

func policyTextGuard(label, value string) error {
	for _, marker := range []string{"key", "secret", "token", "uuid", "private", "password"} {
		if strings.Contains(strings.ToLower(value), marker) {
			return errors.New("POLICY_SECRET_REFUSED: the " + label + " must not describe credentials or keys")
		}
	}
	return nil
}

func policyOperationID(value string) (string, error) {
	if value = strings.TrimSpace(value); value == "" || len(value) > 128 {
		return "", errors.New("POLICY_OPERATION_REQUIRED: every policy write needs a non-empty operation id")
	}
	return value, nil
}

func validatePolicy(layer PolicyLayer, name string, payload, pins []byte) error {
	if layer != PolicyLayerClient && layer != PolicyLayerServer {
		return errors.New("POLICY_LAYER_INVALID: layer must be client or server")
	}
	if name == "" || len([]rune(name)) > 80 {
		return errors.New("POLICY_NAME_INVALID: use 1-80 characters")
	}
	if err := policyTextGuard("name", name); err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > policyMaxBytes || len(pins) > policyMaxBytes {
		return errors.New("POLICY_PAYLOAD_INVALID: the intent or pins JSON is missing or too large")
	}
	var intent routePolicyPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return errors.New("POLICY_PAYLOAD_INVALID: the payload must be the documented intent JSON")
	}
	if err := policyTextGuard("note", intent.Note); err != nil {
		return err
	}
	if layer == PolicyLayerClient {
		if err := (compiler.ClientPolicy{Default: intent.Default, Rules: intent.Rules}).Validate(); err != nil {
			return err
		}
	} else if err := (compiler.ServerPolicy{Default: intent.Default, Rules: intent.Rules}).Validate(); err != nil {
		return err
	}
	var pinSet compiler.RuleSetPins
	decoder = json.NewDecoder(bytes.NewReader(pins))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&pinSet) != nil {
		return errors.New("POLICY_PINS_INVALID: pins must be the documented RuleSetPins JSON")
	}
	return pinSet.Validate(intent.Rules)
}

func insertRoutePolicyTx(tx *sql.Tx, p RoutePolicy) error {
	_, err := tx.Exec(`INSERT INTO route_policies(id, revision, layer, name, payload, pins, status, operation_id, created_at, updated_at)
 VALUES(?,?,?,?,?,?,?,?,?,?)`, p.ID, p.Revision, p.Layer, p.Name, string(p.Payload), string(p.Pins), p.Status, p.OperationID, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		if uniqueConstraint(err) {
			return errors.New("POLICY_CONFLICT: the revision or the layer's active slot is already taken")
		}
		return errors.New("POLICY_WRITE_FAILED: the policy revision was not stored")
	}
	return nil
}

func recordRoutePolicyEventTx(tx *sql.Tx, p RoutePolicy, kind string, from, to PolicyStatus) error {
	if _, err := tx.Exec(`INSERT INTO route_policy_events(policy_id, revision, kind, from_status, to_status, operation_id, created_at)
 VALUES(?,?,?,?,?,?,?)`, p.ID, p.Revision, kind, from, to, p.OperationID, p.UpdatedAt); err != nil {
		return errors.New("POLICY_WRITE_FAILED: the audit event was not stored")
	}
	return nil
}

func (s *store) createRoutePolicy(layer PolicyLayer, name string, payload, pins json.RawMessage, operationID string, now time.Time) (RoutePolicy, error) {
	name = strings.TrimSpace(name)
	if len(pins) == 0 {
		pins = json.RawMessage("{}")
	}
	if err := validatePolicy(layer, name, payload, pins); err != nil {
		return RoutePolicy{}, err
	}
	operationID, err := policyOperationID(operationID)
	if err != nil {
		return RoutePolicy{}, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return RoutePolicy{}, errors.New("POLICY_WRITE_FAILED: the policy identity was not issued")
	}
	p := RoutePolicy{ID: id, Layer: layer, Name: name, Payload: append(json.RawMessage(nil), payload...), Pins: append(json.RawMessage(nil), pins...), Revision: 1, Status: PolicyDraft, OperationID: operationID, CreatedAt: now.Unix(), UpdatedAt: now.Unix()}
	tx, err := s.db.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if err = insertRoutePolicyTx(tx, p); err == nil {
		err = recordRoutePolicyEventTx(tx, p, "create", "", PolicyDraft)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return RoutePolicy{}, err
	}
	return s.getRoutePolicy(id, 1)
}

// reviseRoutePolicy appends revision+1 and supersedes the revision it replaces.
// An active policy stays active (a deliberate replacement); a draft stays draft
// until activate. Revoked and superseded chains are history and cannot revive.
func (s *store) reviseRoutePolicy(id string, payload, pins json.RawMessage, operationID string, now time.Time) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil {
		return RoutePolicy{}, errors.New("POLICY_NOT_FOUND: unknown policy")
	}
	operationID, err := policyOperationID(operationID)
	if err != nil {
		return RoutePolicy{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	latest, err := latestRoutePolicy(tx, id)
	if err != nil {
		return RoutePolicy{}, err
	}
	if latest.Status != PolicyDraft && latest.Status != PolicyActive {
		return RoutePolicy{}, errors.New("POLICY_STATE_INVALID: only a draft or active policy can be revised")
	}
	if len(pins) == 0 {
		pins = json.RawMessage("{}")
	}
	if err = validatePolicy(latest.Layer, latest.Name, payload, pins); err != nil {
		return RoutePolicy{}, err
	}
	payload, pins = append(json.RawMessage(nil), payload...), append(json.RawMessage(nil), pins...)
	next := latest
	next.Revision, next.Payload, next.Pins, next.OperationID, next.CreatedAt, next.UpdatedAt = latest.Revision+1, payload, pins, operationID, now.Unix(), now.Unix()
	_, err = tx.Exec(`UPDATE route_policies SET status=?, updated_at=? WHERE id=? AND revision=?`, PolicySuperseded, now.Unix(), id, latest.Revision)
	if err == nil {
		err = insertRoutePolicyTx(tx, next)
	}
	if err == nil {
		err = recordRoutePolicyEventTx(tx, next, "revise", latest.Status, next.Status)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return RoutePolicy{}, err
	}
	return s.getRoutePolicy(id, next.Revision)
}

// transitionRoutePolicy activates one latest draft or revokes one latest draft
// or active revision. Activation supersedes the layer's previous active policy.
func (s *store) transitionRoutePolicy(id string, revision int64, target PolicyStatus, operationID string, now time.Time) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil || revision < 1 {
		return RoutePolicy{}, errors.New("POLICY_NOT_FOUND: unknown policy revision")
	}
	operationID, err := policyOperationID(operationID)
	if err != nil {
		return RoutePolicy{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	latest, err := latestRoutePolicy(tx, id)
	if err != nil {
		return RoutePolicy{}, err
	}
	if latest.Revision != revision || (target == PolicyActive && latest.Status != PolicyDraft) ||
		(target == PolicyRevoked && latest.Status != PolicyDraft && latest.Status != PolicyActive) {
		return RoutePolicy{}, errors.New("POLICY_STATE_INVALID: the transition needs the latest draft or active revision")
	}
	kind, from := "revoke", latest.Status
	if target == PolicyActive {
		kind = "activate"
		_, err = tx.Exec(`UPDATE route_policies SET status=?, updated_at=? WHERE layer=? AND status=?`, PolicySuperseded, now.Unix(), latest.Layer, PolicyActive)
	}
	if err == nil {
		_, err = tx.Exec(`UPDATE route_policies SET status=?, updated_at=? WHERE id=? AND revision=?`, target, now.Unix(), id, revision)
	}
	if err == nil {
		latest.Status, latest.UpdatedAt, latest.OperationID = target, now.Unix(), operationID
		err = recordRoutePolicyEventTx(tx, latest, kind, from, target)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return RoutePolicy{}, err
	}
	return s.getRoutePolicy(id, revision)
}

func (s *store) activateRoutePolicy(id string, revision int64, operationID string, now time.Time) (RoutePolicy, error) {
	return s.transitionRoutePolicy(id, revision, PolicyActive, operationID, now)
}

func (s *store) revokeRoutePolicy(id string, revision int64, operationID string, now time.Time) (RoutePolicy, error) {
	return s.transitionRoutePolicy(id, revision, PolicyRevoked, operationID, now)
}

const routePolicySelect = `SELECT p.id, p.revision, p.layer, p.name, p.payload, p.pins, p.status, p.operation_id, p.created_at, p.updated_at FROM route_policies p`

func scanRoutePolicy(row interface{ Scan(...any) error }) (RoutePolicy, error) {
	var p RoutePolicy
	var layer, status string
	var payload, pins []byte
	err := row.Scan(&p.ID, &p.Revision, &layer, &p.Name, &payload, &pins, &status, &p.OperationID, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RoutePolicy{}, errors.New("POLICY_NOT_FOUND: unknown policy revision")
	}
	if err != nil {
		return RoutePolicy{}, errors.New("DATABASE_UNAVAILABLE")
	}
	p.Layer, p.Status, p.Payload, p.Pins = PolicyLayer(layer), PolicyStatus(status), payload, pins
	if !json.Valid(p.Payload) || !json.Valid(p.Pins) {
		return RoutePolicy{}, errors.New("POLICY_CORRUPT: stored policy JSON is invalid")
	}
	return p, nil
}

func latestRoutePolicy(q rowQueryer, id string) (RoutePolicy, error) {
	return scanRoutePolicy(q.QueryRow(routePolicySelect+` WHERE p.id=? ORDER BY p.revision DESC LIMIT 1`, id))
}

func (s *store) getRoutePolicy(id string, revision int64) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil {
		return RoutePolicy{}, errors.New("POLICY_NOT_FOUND: unknown policy")
	}
	if revision > 0 {
		return scanRoutePolicy(s.db.QueryRow(routePolicySelect+` WHERE p.id=? AND p.revision=?`, id, revision))
	}
	return latestRoutePolicy(s.db, id)
}

func (s *store) listRoutePolicies(layer PolicyLayer) ([]RoutePolicy, error) {
	if layer != "" && layer != PolicyLayerClient && layer != PolicyLayerServer {
		return nil, errors.New("POLICY_LAYER_INVALID: layer must be client or server")
	}
	query, args := routePolicySelect+` WHERE p.revision=(SELECT MAX(revision) FROM route_policies WHERE id=p.id)`, []any{}
	if layer != "" {
		query, args = query+` AND p.layer=?`, []any{layer}
	}
	rows, err := s.db.Query(query+` ORDER BY p.layer, p.name, p.id`, args...)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []RoutePolicy{}
	for rows.Next() {
		record, err := scanRoutePolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

func (s *store) activeRoutePolicy(layer PolicyLayer) (RoutePolicy, error) {
	if layer != PolicyLayerClient && layer != PolicyLayerServer {
		return RoutePolicy{}, errors.New("POLICY_LAYER_INVALID: layer must be client or server")
	}
	return scanRoutePolicy(s.db.QueryRow(routePolicySelect+` WHERE p.layer=? AND p.status=?`, layer, PolicyActive))
}

func migrateSchema8(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE route_policies (
  id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
  layer TEXT NOT NULL CHECK(layer IN ('client','server')),
  name TEXT NOT NULL, payload TEXT NOT NULL, pins TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('draft','active','superseded','revoked')),
  operation_id TEXT NOT NULL CHECK(operation_id<>''),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY(id, revision)
);
CREATE UNIQUE INDEX route_policies_one_active ON route_policies(layer) WHERE status='active';
CREATE TABLE route_policy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT NOT NULL, revision INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('create','revise','activate','revoke')),
  from_status TEXT NOT NULL DEFAULT '', to_status TEXT NOT NULL DEFAULT '',
  operation_id TEXT NOT NULL CHECK(operation_id<>''), created_at INTEGER NOT NULL
);
CREATE INDEX route_policy_events_policy ON route_policy_events(policy_id, id);
CREATE TRIGGER route_policy_events_append_only_update BEFORE UPDATE ON route_policy_events BEGIN
  SELECT RAISE(ABORT, 'ROUTE_POLICY_EVENT_IMMUTABLE');
END;
CREATE TRIGGER route_policy_events_append_only_delete BEFORE DELETE ON route_policy_events BEGIN
  SELECT RAISE(ABORT, 'ROUTE_POLICY_EVENT_IMMUTABLE');
END;
PRAGMA user_version=8;
`)
	return err
}
