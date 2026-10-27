package policy

// Policy persistence for issue #10 (10d-1a): schema 8 revision chains, create
// and read paths, and guarded intent payloads. Publication remains 10d-2.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// PolicyLayer is a stored policy layer: the writable server layer, or the
// retired client layer that stays readable as a gated preview.
type PolicyLayer string

// Layer is the short exported spelling the other store domains use.
type Layer = PolicyLayer

// PolicyStatus is a stored policy revision status.
type PolicyStatus string

const (
	PolicyLayerClient PolicyLayer = "client"
	PolicyLayerServer PolicyLayer = "server"

	// LayerClient and LayerServer are the exported layer values.
	LayerClient                   = PolicyLayerClient
	LayerServer                   = PolicyLayerServer
	PolicyDraft      PolicyStatus = "draft"
	PolicyActive     PolicyStatus = "active"
	PolicySuperseded PolicyStatus = "superseded"
	PolicyRevoked    PolicyStatus = "revoked"
	policyMaxBytes                = 64 << 10
)

// Stable refusals of the post-aggregation policy contract (Task 6).
//
// The client layer was the 10b client-intent store. The standard subscription
// export never read it (the composer renders the client document from the
// selected Lines and rules), so Task 6 closes it to writes while keeping the
// table and its reads: a database upgraded from an older release still renders
// and gates its legacy active revision as a preview, but no new revision can
// be created, revised, activated or revoked. The rule library is the only
// write surface for client-side routing now.
//
// exceptions and ssids were the two top-level fields of that legacy intent.
// They were never consumed after the rule library landed; silently dropping
// them made a write look applied when no byte would change. They are refused
// explicitly, and schema 17 strips the keys from rows written before this
// release.
const (
	// CodePolicyLayerRetired: the client layer is read-only.
	CodePolicyLayerRetired = "POLICY_LAYER_RETIRED"
	// CodePolicyPayloadRetired: the payload still carries exceptions or ssids.
	CodePolicyPayloadRetired = "POLICY_PAYLOAD_RETIRED"
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

// RoutePolicyPayload is the stored intent of one server revision. The client
// layer's legacy revisions may still carry exceptions/ssids keys; schema 17
// strips them, and this struct no longer models them, so a row that somehow
// escapes the migration is refused by the strict decoder instead of having the
// fields silently ignored.
type RoutePolicyPayload struct {
	Default coredomain.CompilerAction `json:"default"`
	Rules   []coredomain.CompilerRule `json:"rules"`
	Note    string                    `json:"note,omitempty"`
}

// retiredPolicyFields are the two top-level keys Task 6 removed. They are
// detected before the strict decode so the refusal names the retirement
// instead of reporting a generic unknown field; an empty array or null is
// refused too, because the key itself is the retired contract.
var retiredPolicyFields = []string{"exceptions", "ssids"}

// rejectRetiredPolicyFields refuses a payload that still carries a retired
// key. The check is on the raw object, not on decoded values: a write must not
// look accepted merely because the value happened to be empty.
func rejectRetiredPolicyFields(payload []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		// The caller's strict decoder reports the malformed payload.
		return nil
	}
	for _, name := range retiredPolicyFields {
		if _, present := fields[name]; present {
			return errors.New(CodePolicyPayloadRetired + ": " + name + " is retired; express the intent as rules")
		}
	}
	return nil
}

// writablePolicyLayer refuses a write to a read-only layer. Task 6 froze the
// client layer at the store boundary, not only in the HTTP handler, so every
// internal caller observes the same one-way door.
func writablePolicyLayer(layer PolicyLayer) error {
	if layer == PolicyLayerClient {
		return errors.New(CodePolicyLayerRetired + ": the client policy layer is read-only; use the rule library")
	}
	return nil
}

func policyTextGuard(label, value string) error {
	for _, marker := range []string{"key", "secret", "token", "uuid", "private", "password"} {
		if strings.Contains(strings.ToLower(value), marker) {
			return errors.New(codePolicySecretRefused + ": the " + label + " must not describe credentials or keys")
		}
	}
	return nil
}

func policyOperationID(value string) (string, error) {
	if value = strings.TrimSpace(value); value == "" || len(value) > 128 {
		return "", errors.New(codePolicyOperationRequired + ": every policy write needs a non-empty operation id")
	}
	return value, nil
}

func validatePolicy(layer PolicyLayer, name string, payload, pins []byte) error {
	if layer != PolicyLayerClient && layer != PolicyLayerServer {
		return errors.New(codePolicyLayerInvalid + ": layer must be client or server")
	}
	if err := writablePolicyLayer(layer); err != nil {
		return err
	}
	if name == "" || len([]rune(name)) > 80 {
		return errors.New(codePolicyNameInvalid + ": use 1-80 characters")
	}
	if err := policyTextGuard("name", name); err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > policyMaxBytes || len(pins) > policyMaxBytes {
		return errors.New(codePolicyPayloadInvalid + ": the intent or pins JSON is missing or too large")
	}
	if err := rejectRetiredPolicyFields(payload); err != nil {
		return err
	}
	var intent RoutePolicyPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return errors.New(codePolicyPayloadInvalid + ": the payload must be the documented intent JSON")
	}
	if err := policyTextGuard("note", intent.Note); err != nil {
		return err
	}
	if layer == PolicyLayerClient {
		if err := (coredomain.ClientPolicy{Default: intent.Default, Rules: intent.Rules}).Validate(); err != nil {
			return err
		}
	} else if err := (coredomain.ServerPolicy{Default: intent.Default, Rules: intent.Rules}).Validate(); err != nil {
		return err
	}
	var pinSet coredomain.RuleSetPins
	decoder = json.NewDecoder(bytes.NewReader(pins))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&pinSet) != nil {
		return errors.New(codePolicyPinsInvalid + ": pins must be the documented RuleSetPins JSON")
	}
	return pinSet.Validate(intent.Rules)
}

func insertRoutePolicyTx(tx *sql.Tx, p RoutePolicy) error {
	_, err := tx.Exec(`INSERT INTO route_policies(id, revision, layer, name, payload, pins, status, operation_id, created_at, updated_at)
 VALUES(?,?,?,?,?,?,?,?,?,?)`, p.ID, p.Revision, p.Layer, p.Name, string(p.Payload), string(p.Pins), p.Status, p.OperationID, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		if common.IsUniqueConstraint(err) {
			return errors.New(coredomain.CodePolicyConflict + ": the revision or the layer's active slot is already taken")
		}
		return errors.New(codePolicyWriteFailed + ": the policy revision was not stored")
	}
	return nil
}

func recordRoutePolicyEventTx(tx *sql.Tx, p RoutePolicy, kind string, from, to PolicyStatus) error {
	if _, err := tx.Exec(`INSERT INTO route_policy_events(policy_id, revision, kind, from_status, to_status, operation_id, created_at)
 VALUES(?,?,?,?,?,?,?)`, p.ID, p.Revision, kind, from, to, p.OperationID, p.UpdatedAt); err != nil {
		return errors.New(codePolicyWriteFailed + ": the audit event was not stored")
	}
	return nil
}

func (s *Store) CreateRoutePolicy(layer PolicyLayer, name string, payload, pins json.RawMessage, operationID string, now time.Time) (RoutePolicy, error) {
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
		return RoutePolicy{}, errors.New(codePolicyWriteFailed + ": the policy identity was not issued")
	}
	p := RoutePolicy{ID: id, Layer: layer, Name: name, Payload: append(json.RawMessage(nil), payload...), Pins: append(json.RawMessage(nil), pins...), Revision: 1, Status: PolicyDraft, OperationID: operationID, CreatedAt: now.Unix(), UpdatedAt: now.Unix()}
	tx, err := s.DB.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New(common.CodeDatabaseUnavailable)
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
	return s.GetRoutePolicy(id, 1)
}

// reviseRoutePolicy appends revision+1 and supersedes the revision it replaces.
// An active policy stays active (a deliberate replacement); a draft stays draft
// until activate. Revoked and superseded chains are history and cannot revive.
func (s *Store) ReviseRoutePolicy(id string, payload, pins json.RawMessage, operationID string, now time.Time) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil {
		return RoutePolicy{}, errors.New(CodePublishNoPolicy + ": unknown policy")
	}
	operationID, err := policyOperationID(operationID)
	if err != nil {
		return RoutePolicy{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	latest, err := latestRoutePolicy(tx, id)
	if err != nil {
		return RoutePolicy{}, err
	}
	if err := writablePolicyLayer(latest.Layer); err != nil {
		return RoutePolicy{}, err
	}
	if latest.Status != PolicyDraft && latest.Status != PolicyActive {
		return RoutePolicy{}, errors.New(codePolicyStateInvalid + ": only a draft or active policy can be revised")
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
	return s.GetRoutePolicy(id, next.Revision)
}

// transitionRoutePolicy activates one latest draft or revokes one latest draft
// or active revision. Activation supersedes the layer's previous active policy.
func (s *Store) transitionRoutePolicy(id string, revision int64, target PolicyStatus, operationID string, now time.Time) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil || revision < 1 {
		return RoutePolicy{}, errors.New(CodePublishNoPolicy + ": unknown policy revision")
	}
	operationID, err := policyOperationID(operationID)
	if err != nil {
		return RoutePolicy{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return RoutePolicy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	latest, err := latestRoutePolicy(tx, id)
	if err != nil {
		return RoutePolicy{}, err
	}
	if err := writablePolicyLayer(latest.Layer); err != nil {
		return RoutePolicy{}, err
	}
	if latest.Revision != revision || (target == PolicyActive && latest.Status != PolicyDraft) ||
		(target == PolicyRevoked && latest.Status != PolicyDraft && latest.Status != PolicyActive) {
		return RoutePolicy{}, errors.New(codePolicyStateInvalid + ": the transition needs the latest draft or active revision")
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
	return s.GetRoutePolicy(id, revision)
}

func (s *Store) ActivateRoutePolicy(id string, revision int64, operationID string, now time.Time) (RoutePolicy, error) {
	return s.transitionRoutePolicy(id, revision, PolicyActive, operationID, now)
}

func (s *Store) RevokeRoutePolicy(id string, revision int64, operationID string, now time.Time) (RoutePolicy, error) {
	return s.transitionRoutePolicy(id, revision, PolicyRevoked, operationID, now)
}

const routePolicySelect = `SELECT p.id, p.revision, p.layer, p.name, p.payload, p.pins, p.status, p.operation_id, p.created_at, p.updated_at FROM route_policies p`

func scanRoutePolicy(row interface{ Scan(...any) error }) (RoutePolicy, error) {
	var p RoutePolicy
	var layer, status string
	var payload, pins []byte
	err := row.Scan(&p.ID, &p.Revision, &layer, &p.Name, &payload, &pins, &status, &p.OperationID, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RoutePolicy{}, errors.New(CodePublishNoPolicy + ": unknown policy revision")
	}
	if err != nil {
		return RoutePolicy{}, errors.New(common.CodeDatabaseUnavailable)
	}
	p.Layer, p.Status, p.Payload, p.Pins = PolicyLayer(layer), PolicyStatus(status), payload, pins
	if !json.Valid(p.Payload) || !json.Valid(p.Pins) {
		return RoutePolicy{}, errors.New(codePolicyCorrupt + ": stored policy JSON is invalid")
	}
	return p, nil
}

func latestRoutePolicy(q common.RowQueryer, id string) (RoutePolicy, error) {
	return scanRoutePolicy(q.QueryRow(routePolicySelect+` WHERE p.id=? ORDER BY p.revision DESC LIMIT 1`, id))
}

func (s *Store) GetRoutePolicy(id string, revision int64) (RoutePolicy, error) {
	if err := subscription.ValidateID(id); err != nil {
		return RoutePolicy{}, errors.New(CodePublishNoPolicy + ": unknown policy")
	}
	if revision > 0 {
		return scanRoutePolicy(s.DB.QueryRow(routePolicySelect+` WHERE p.id=? AND p.revision=?`, id, revision))
	}
	return latestRoutePolicy(s.DB, id)
}

func (s *Store) ActiveRoutePolicy(layer PolicyLayer) (RoutePolicy, error) {
	if layer != PolicyLayerClient && layer != PolicyLayerServer {
		return RoutePolicy{}, errors.New(codePolicyLayerInvalid + ": layer must be client or server")
	}
	return scanRoutePolicy(s.DB.QueryRow(routePolicySelect+` WHERE p.layer=? AND p.status=?`, layer, PolicyActive))
}

// MigrateSchema8 creates the route-policy revision chain.
func MigrateSchema8(tx *sql.Tx) error {
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

// activePolicyIntent reads one layer's active revision and decodes its payload.
// It is the single reader of the active intent, so the page, the publish
// pipeline and an implicit route derivation can never disagree about which
// revision is live.
func (s *Store) ActivePolicyIntent(layer PolicyLayer) (RoutePolicy, RoutePolicyPayload, error) {
	record, err := s.ActiveRoutePolicy(layer)
	return activePolicyIntentOf(record, err)
}
