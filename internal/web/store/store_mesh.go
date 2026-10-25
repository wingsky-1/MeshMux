package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// Store-level codes for the mesh persistence boundary. Domain refusals keep
// their mesh.Code* value; these only describe a missing row, which the pure
// domain package does not model.
const (
	CodeMeshDeviceNotFound        = "MESH_DEVICE_NOT_FOUND"
	CodeMeshDeviceCorrupt         = "MESH_DEVICE_CORRUPT"
	CodeMeshEnrollmentKeyNotFound = "MESH_ENROLLMENT_KEY_NOT_FOUND"
)

// MeshDeviceRecord is one stored mesh device plus the audit fields the pure
// domain model does not carry: the first revocation intent and the last
// observation. The embedded MeshDevice stays the single source of the
// identity, purpose, binding, node-name and lifecycle rules.
type MeshDeviceRecord struct {
	mesh.MeshDevice
	RevokeReason      string `json:"revoke_reason,omitempty"`
	RevokeRequestedAt int64  `json:"revoke_requested_at,omitempty"`
	ObservedAt        int64  `json:"observed_at,omitempty"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
}

// MeshEnrollmentKeyRecord is the persisted view of one one-time enrollment key.
// It deliberately has no digest field: only the issue path writes the SHA-256
// digest, and a consumed key has cleared it, so no read path can hand out
// replay material.
type MeshEnrollmentKeyRecord struct {
	ID         string        `json:"id"`
	DeviceID   string        `json:"device_id"`
	State      mesh.KeyState `json:"state"`
	IssuedAt   int64         `json:"issued_at"`
	ExpiresAt  int64         `json:"expires_at"`
	ConsumedAt int64         `json:"consumed_at,omitempty"`
}

const meshDeviceSelect = `SELECT d.id, d.display_name, d.purpose, d.platform, COALESCE(d.subscriber_id,''),
 d.headscale_user, d.node_name, d.headscale_node_id, d.status,
 d.revoke_reason, d.revoke_requested_at, d.observed_at, d.created_at, d.updated_at
FROM mesh_devices d`

func MeshError(code, detail string) error {
	return errors.New(code + ": " + detail)
}

// errMeshDeviceCorrupt marks a stored row that no longer satisfies the domain
// rules, so a hand-edited database is never rendered as a valid device.
var errMeshDeviceCorrupt = errors.New(CodeMeshDeviceCorrupt)

// meshReadError separates a corrupt stored record from an unavailable database.
func meshReadError(err error) error {
	if errors.Is(err, errMeshDeviceCorrupt) {
		return MeshError(CodeMeshDeviceCorrupt, "the stored mesh device record is invalid")
	}
	return errors.New("DATABASE_UNAVAILABLE")
}

func scanMeshDevice(row rowScanner) (MeshDeviceRecord, error) {
	var (
		record   MeshDeviceRecord
		purpose  string
		platform string
		status   string
	)
	if err := row.Scan(&record.ID, &record.DisplayName, &purpose, &platform, &record.SubscriberID,
		&record.HeadscaleUser, &record.NodeName, &record.HeadscaleNodeID, &status,
		&record.RevokeReason, &record.RevokeRequestedAt, &record.ObservedAt, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return MeshDeviceRecord{}, err
	}
	record.Purpose = mesh.Purpose(purpose)
	record.Platform = mesh.Platform(platform)
	record.Status = mesh.Status(status)
	// A stored row has to satisfy the same domain rules the write path applied;
	// otherwise a hand-edited database would be rendered as a valid device.
	if err := record.MeshDevice.Validate(); err != nil {
		return MeshDeviceRecord{}, errMeshDeviceCorrupt
	}
	return record, nil
}

// meshDeviceTx loads one device inside the caller's transaction. A missing row
// is MESH_DEVICE_NOT_FOUND, not a generic database failure.
func meshDeviceTx(tx *sql.Tx, deviceID string) (MeshDeviceRecord, error) {
	record, err := scanMeshDevice(tx.QueryRow(meshDeviceSelect+` WHERE d.id=?`, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return MeshDeviceRecord{}, MeshError(CodeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return MeshDeviceRecord{}, meshReadError(err)
	}
	return record, nil
}

// createMeshDevice persists one pending device. The pure domain constructor
// validates the purpose×subscriber binding, the canonical node name and the
// pre-declared prefixes; the store adds the facts the domain cannot check
// without I/O: the subscriber row exists, the occupied node name is unique, and
// no other device already holds a declared prefix.
//
// A subnet_router may pre-declare its LAN prefixes. Each one becomes an
// advertised route with source=device in the same transaction, so a device never
// exists with a half-written declaration and the operator does not have to
// declare the same prefixes twice. Nothing is approved here: a pre-declaration is
// an intent awaiting explicit approval, exactly like a later declaration.
//
// Node-name uniqueness is a partial unique index over the statuses that still
// occupy the name, so revoked, expired and failed devices release it. A missing
// subscriber binding is stored as NULL, never as an empty string, so the
// foreign key and the purpose CHECK stay enforceable.
func (s *Store) CreateMeshDevice(spec mesh.DeviceSpec, now time.Time) (MeshDeviceRecord, error) {
	device, err := mesh.NewMeshDevice(spec)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	prefixes, err := mesh.NormalizeDeclaredPrefixes(device.Purpose, spec.DeclaredRoutes)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var subscriber any
	if device.SubscriberID != "" {
		var state string
		err = tx.QueryRow(`SELECT state FROM subscribers WHERE id=?`, device.SubscriberID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return MeshDeviceRecord{}, MeshError(mesh.CodeSubscriberBindingInvalid, "the subscriber does not exist")
		}
		if err != nil {
			return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if state == string(subscription.StateDeleting) || state == string(subscription.StateDeleted) {
			return MeshDeviceRecord{}, MeshError(mesh.CodeSubscriberBindingInvalid, "a deleting or deleted subscriber cannot own a mesh device")
		}
		subscriber = device.SubscriberID
	}
	if _, err = tx.Exec(`INSERT INTO mesh_devices(id, display_name, purpose, platform, subscriber_id, headscale_user,
 node_name, headscale_node_id, status, revoke_reason, revoke_requested_at, observed_at, created_at, updated_at)
 VALUES(?,?,?,?,?,?,?,0,'pending','',0,0,?,?)`,
		device.ID, device.DisplayName, string(device.Purpose), string(device.Platform), subscriber,
		device.HeadscaleUser, device.NodeName, now.Unix(), now.Unix()); err != nil {
		if meshNodeNameConflict(err) {
			return MeshDeviceRecord{}, MeshError(mesh.CodeNodeNameDuplicate, "the node name is already occupied for this headscale user")
		}
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	// Pre-declared prefixes land with the device in one transaction. They are
	// advertised intents only: approval stays an explicit, separately audited act.
	for _, prefix := range prefixes {
		if err = meshRouteConflictTx(tx, prefix, device.ID); err != nil {
			return MeshDeviceRecord{}, err
		}
		if _, err = tx.Exec(`INSERT INTO mesh_routes(device_id, prefix, desired, observed, source, operation_id, created_at, updated_at)
 VALUES(?,?,'advertised','','device','',?,?)`, device.ID, prefix, now.Unix(), now.Unix()); err != nil {
			if meshRoutePrefixConflict(err) {
				return MeshDeviceRecord{}, meshRouteError(CodeMeshRouteConflict, "the prefix is already declared by another device")
			}
			return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if err = recordMeshRouteEventTx(tx, device.ID, prefix, RouteEventDeclared,
			"", string(mesh.RouteDesiredAdvertised), "", "", "", now); err != nil {
			return MeshDeviceRecord{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.GetMeshDevice(device.ID)
}

func uniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// renameMeshDevice changes only the mutable display label. The id, purpose,
// binding, node name and lifecycle stay exactly as they were, so a label edit
// can never move a device or release an occupied name. A revoked device is a
// tombstone and keeps its last label.
func (s *Store) RenameMeshDevice(deviceID, displayName string, now time.Time) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, MeshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	name, err := subscription.NormalizeDisplayName(displayName)
	if err != nil {
		return MeshDeviceRecord{}, MeshError(mesh.CodeDisplayNameInvalid, "use 1-80 normalized printable characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	if record.Status == mesh.StatusRevoked {
		return MeshDeviceRecord{}, MeshError(mesh.CodeStatusTransitionInvalid, "a revoked device is a tombstone and cannot be renamed")
	}
	if record.DisplayName != name {
		if _, err = tx.Exec(`UPDATE mesh_devices SET display_name=?, updated_at=? WHERE id=?`, name, now.Unix(), deviceID); err != nil {
			return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	record.DisplayName = name
	record.UpdatedAt = now.Unix()
	return record, nil
}

// meshNodeNameConflict narrows a UNIQUE failure to the partial node-name index,
// so a name collision is reported as the domain duplicate instead of a generic
// storage failure.
func meshNodeNameConflict(err error) bool {
	return uniqueConstraint(err) && strings.Contains(err.Error(), "mesh_devices.headscale_user")
}

// meshKeySingleActiveConflict narrows a UNIQUE failure to the one-issued-key
// index.
func meshKeySingleActiveConflict(err error) bool {
	return uniqueConstraint(err) && strings.Contains(err.Error(), "mesh_enrollment_keys.device_id")
}

// getMeshDevice returns one stored device.
func (s *Store) GetMeshDevice(deviceID string) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, MeshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	record, err := scanMeshDevice(s.DB.QueryRow(meshDeviceSelect+` WHERE d.id=?`, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return MeshDeviceRecord{}, MeshError(CodeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return MeshDeviceRecord{}, meshReadError(err)
	}
	return record, nil
}

// listMeshDevices returns every device in creation order, revoked ones
// included: a revoked device is history, not a deleted record.
func (s *Store) ListMeshDevices() ([]MeshDeviceRecord, error) {
	rows, err := s.DB.Query(meshDeviceSelect + ` ORDER BY d.created_at ASC, d.id ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []MeshDeviceRecord{}
	for rows.Next() {
		record, err := scanMeshDevice(rows)
		if err != nil {
			return nil, meshReadError(err)
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// issueMeshEnrollmentKey mints one fixed 15-minute key for a pending device and
// returns the plaintext secret exactly once. Only the SHA-256 digest is stored.
//
// The single-active rule is enforced twice: a lapsed issued row is retired to
// expired in the same transaction, and the partial unique index refuses a
// second issued row for the same device. A device that is not pending cannot
// receive a key at all.
func (s *Store) IssueMeshEnrollmentKey(deviceID string, now time.Time) (mesh.EnrollmentKey, string, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return mesh.EnrollmentKey{}, "", MeshError(mesh.CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	key, secret, err := mesh.NewEnrollmentKey(deviceID, now.UTC().Truncate(time.Second))
	if err != nil {
		return mesh.EnrollmentKey{}, "", err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRow(`SELECT status FROM mesh_devices WHERE id=?`, deviceID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return mesh.EnrollmentKey{}, "", MeshError(CodeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if mesh.Status(status) != mesh.StatusPending {
		return mesh.EnrollmentKey{}, "", MeshError(mesh.CodeStatusTransitionInvalid, "only a pending device can receive an enrollment key")
	}
	// A lapsed key keeps the issued state until someone retires it. Retiring it
	// here keeps one unusable row from silently blocking a fresh key.
	if _, err = tx.Exec(`UPDATE mesh_enrollment_keys SET state='expired'
 WHERE device_id=? AND state='issued' AND expires_at<=?`, deviceID, key.IssuedAt.Unix()); err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if _, err = tx.Exec(`INSERT INTO mesh_enrollment_keys(id, device_id, secret_hash, state, issued_at, expires_at, consumed_at)
 VALUES(?,?,?,'issued',?,?,0)`, key.ID, key.DeviceID, key.Hash, key.IssuedAt.Unix(), key.ExpiresAt.Unix()); err != nil {
		if meshKeySingleActiveConflict(err) {
			return mesh.EnrollmentKey{}, "", MeshError(mesh.CodeKeyAlreadyActive, "the device already holds an issued enrollment key")
		}
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	return key, secret, nil
}

// meshRekeyApply reports what one atomic re-enrollment write changed.
type meshRekeyApply struct {
	// Reenrolled is true when the device was expired and moved back to pending
	// in the same transaction that installed the key.
	Reenrolled bool
	// Withdrawn is how many keys were live and are now revoked because the
	// new key replaced them.
	Withdrawn int64
	// Lapsed is how many rows were still marked issued but had already passed
	// their window; they are retired as expired, the same way the issue path
	// does, because their window ended on its own.
	Lapsed int64
}

// applyMeshRekey installs one staged key as the live one for a pending or
// expired device, and withdraws the key it replaces, in a single transaction.
// An expired device is moved back to pending here as well: re-enrollment is a
// fresh attempt with no observed node, so the status edge and the key swap
// either both happen or neither does.
//
// The caller mints the staged key in memory and every external secret (the
// Headscale pre-auth key and the rendered document) before calling this, so a
// refusal anywhere earlier leaves the device's live key and status untouched.
// This write is the point of no return: on success the device is pending and
// holds exactly the new key, on failure it keeps the state and key it had. A
// lapsed issued row is retired as expired rather than revoked, because revoking
// it would report an early withdrawal that never happened.
func (s *Store) ApplyMeshRekey(deviceID string, key mesh.EnrollmentKey, now time.Time) (meshRekeyApply, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return meshRekeyApply{}, MeshError(mesh.CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	if key.DeviceID != deviceID {
		return meshRekeyApply{}, MeshError(mesh.CodeKeyDeviceMismatch, "the staged key belongs to another device")
	}
	if key.State != mesh.KeyIssued {
		return meshRekeyApply{}, MeshError(mesh.CodeKeyTransitionInvalid, "only an issued key can be installed")
	}
	if err := key.Validate(); err != nil {
		return meshRekeyApply{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return meshRekeyApply{}, err
	}
	var apply meshRekeyApply
	switch record.Status {
	case mesh.StatusPending:
		// Already ready for a fresh attempt.
	case mesh.StatusExpired:
		next, err := record.MeshDevice.Transition(mesh.StatusPending)
		if err != nil {
			return meshRekeyApply{}, err
		}
		res, err := tx.Exec(`UPDATE mesh_devices SET status=?, headscale_node_id=?, updated_at=?
 WHERE id=? AND status='expired'`, string(next.Status), next.HeadscaleNodeID, now.Unix(), deviceID)
		if err != nil {
			if meshNodeNameConflict(err) {
				return meshRekeyApply{}, MeshError(mesh.CodeNodeNameDuplicate, "the node name was taken while the device was expired")
			}
			return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return meshRekeyApply{}, MeshError(mesh.CodeStatusTransitionInvalid, "the mesh device is no longer expired")
		}
		apply.Reenrolled = true
	default:
		return meshRekeyApply{}, MeshError(mesh.CodeStatusTransitionInvalid, "only a pending or expired device can receive an enrollment key")
	}
	res, err := tx.Exec(`UPDATE mesh_enrollment_keys SET state='expired'
 WHERE device_id=? AND state='issued' AND expires_at<=?`, deviceID, key.IssuedAt.Unix())
	if err != nil {
		return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
	}
	apply.Lapsed, _ = res.RowsAffected()
	res, err = tx.Exec(`UPDATE mesh_enrollment_keys SET state='revoked' WHERE device_id=? AND state='issued'`, deviceID)
	if err != nil {
		return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
	}
	apply.Withdrawn, _ = res.RowsAffected()
	if _, err = tx.Exec(`INSERT INTO mesh_enrollment_keys(id, device_id, secret_hash, state, issued_at, expires_at, consumed_at)
 VALUES(?,?,?,'issued',?,?,0)`, key.ID, key.DeviceID, key.Hash, key.IssuedAt.Unix(), key.ExpiresAt.Unix()); err != nil {
		if meshKeySingleActiveConflict(err) {
			return meshRekeyApply{}, MeshError(mesh.CodeKeyAlreadyActive, "the device already holds an issued enrollment key")
		}
		return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return meshRekeyApply{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return apply, nil
}

// spendMeshEnrollmentKeyTx retires the live one-time key of a device whose
// registration is proven, inside the transaction that records the evidence.
//
// This is what makes the key genuinely one-time (D1): there is no endpoint that
// accepts the secret, so the one-time semantic is "the registration the key
// authorized consumes it". A key still inside its 15-minute window becomes the
// terminal consumed state with its digest cleared — clearing the digest is what
// makes replay impossible even though the row is kept for audit. A key whose
// window already closed is retired as expired, because D1 forbids consuming a
// key outside its window. A key that is not valid yet (clock moved backwards) is
// left for the issue path, and a device with no issued row — never signed, or
// already consumed/expired/revoked — is untouched, so a repeat observation is a
// no-op.
func spendMeshEnrollmentKeyTx(tx *sql.Tx, deviceID string, now time.Time) error {
	var (
		keyID               string
		hash                []byte
		issuedAt, expiresAt int64
	)
	err := tx.QueryRow(`SELECT id, secret_hash, issued_at, expires_at FROM mesh_enrollment_keys
 WHERE device_id=? AND state='issued'`, deviceID).Scan(&keyID, &hash, &issuedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	key := mesh.EnrollmentKey{
		ID:        keyID,
		DeviceID:  deviceID,
		Hash:      hash,
		State:     mesh.KeyIssued,
		IssuedAt:  time.Unix(issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(expiresAt, 0).UTC(),
	}
	switch {
	case key.Active(now):
		consumed, err := key.Consume(deviceID, now)
		if err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE mesh_enrollment_keys SET state='consumed', secret_hash=NULL, consumed_at=?
 WHERE id=? AND state='issued'`, consumed.ConsumedAt.Unix(), keyID)
		if err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return MeshError(mesh.CodeKeyTransitionInvalid, "the enrollment key was no longer issued")
		}
	case key.Expired(now):
		if _, err = key.Expire(now); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE mesh_enrollment_keys SET state='expired' WHERE id=? AND state='issued'`, keyID); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
	}
	return nil
}

// recordMeshObservation stores what Headscale currently reports for one device.
// A non-zero node id proves registration (pending → registered) and must stay
// the same for an already registered device. A missing node id is the opposite
// evidence: a registered device becomes expired, and a device whose removal was
// requested becomes the terminal revoked state. Other statuses are unchanged by
// a missing node, because they either never had one or already settled.
//
// Registration also spends the device's live one-time key in the same
// transaction (see spendMeshEnrollmentKeyTx). Reconcile and claim are the only
// two callers and both record evidence here, so "the key is consumed once the
// registration is proven" holds for either path; a device that is already
// registered has a lingering issued row spent as well, which is the state an
// older database keeps.
func (s *Store) RecordMeshObservation(deviceID string, headscaleNodeID uint64, now time.Time) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, MeshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	next := record.MeshDevice
	if headscaleNodeID != 0 {
		switch record.Status {
		case mesh.StatusPending:
			next, err = record.MeshDevice.MarkRegistered(headscaleNodeID)
		case mesh.StatusRegistered:
			if record.HeadscaleNodeID != headscaleNodeID {
				return MeshDeviceRecord{}, MeshError(mesh.CodeHeadscaleNodeIDInvalid, "the observed node id does not match the registered node")
			}
		case mesh.StatusRevoking:
			// Headscale still reports the node, so the removal is not confirmed
			// yet. The device stays revoking; the observed reference is kept so
			// a retried removal names the same node. A contradiction is refused.
			if record.HeadscaleNodeID == 0 {
				next.HeadscaleNodeID = headscaleNodeID
			} else if record.HeadscaleNodeID != headscaleNodeID {
				return MeshDeviceRecord{}, MeshError(mesh.CodeHeadscaleNodeIDInvalid, "the observed node id does not match the node being removed")
			}
		default:
			return MeshDeviceRecord{}, MeshError(mesh.CodeStatusTransitionInvalid, "an observed node id cannot be attached to this status")
		}
	} else {
		switch record.Status {
		case mesh.StatusRegistered:
			next, err = record.MeshDevice.Transition(mesh.StatusExpired)
		case mesh.StatusRevoking:
			next, err = record.MeshDevice.Transition(mesh.StatusRevoked)
		case mesh.StatusPending, mesh.StatusExpired, mesh.StatusRevoked, mesh.StatusFailed:
			// No node was observed and the status already agrees.
		}
	}
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	// Proven registration spends the key that authorized this attempt, in the
	// same transaction as the evidence that proves it. A repeat observation of
	// an already registered device finds no issued row and changes nothing.
	if next.Status == mesh.StatusRegistered {
		if err = spendMeshEnrollmentKeyTx(tx, deviceID, now); err != nil {
			return MeshDeviceRecord{}, err
		}
	}
	if _, err = tx.Exec(`UPDATE mesh_devices SET status=?, headscale_node_id=?, observed_at=?, updated_at=? WHERE id=?`,
		string(next.Status), next.HeadscaleNodeID, now.Unix(), now.Unix(), deviceID); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.GetMeshDevice(deviceID)
}

// requestMeshDeviceRevocation records one explicit revocation intent through
// the domain state machine. It is idempotent: the first intent owns the reason
// and the timestamp, a repeat reports revocation_in_progress without rewriting
// them, and an already revoked device stays terminal. It never touches a
// subscriber, a proxy credential or a subscription token: revoking one mesh
// device must not disable the whole subscriber (ADR-0004).
func (s *Store) RequestMeshDeviceRevocation(deviceID, reason string, now time.Time) (MeshDeviceRecord, mesh.RevokeOutcome, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, "", MeshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshDeviceRecord{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, "", err
	}
	next, outcome, err := record.MeshDevice.ApplyRevoke(mesh.RevokeIntent{DeviceID: deviceID, Reason: reason})
	if err != nil {
		return MeshDeviceRecord{}, "", err
	}
	if outcome == mesh.RevokeRequested {
		res, err := tx.Exec(`UPDATE mesh_devices SET status=?, revoke_reason=?, revoke_requested_at=?, updated_at=?
 WHERE id=? AND status=?`, string(next.Status), reason, now.Unix(), now.Unix(), deviceID, string(record.Status))
		if err != nil {
			return MeshDeviceRecord{}, "", errors.New("DATABASE_UNAVAILABLE")
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return MeshDeviceRecord{}, "", MeshError(mesh.CodeStatusTransitionInvalid, "the mesh device status changed concurrently")
		}
	}
	// The device and every one of its live prefixes settle in one transaction:
	// a revoked device must never keep an approved route, and a withdrawn route
	// keeps its audit event. A repeat intent finds nothing live and changes
	// nothing.
	if err = revokeDeviceRoutesTx(tx, deviceID, "", now); err != nil {
		return MeshDeviceRecord{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	stored, err := s.GetMeshDevice(deviceID)
	if err != nil {
		return MeshDeviceRecord{}, "", err
	}
	return stored, outcome, nil
}

// revokeMeshEnrollmentKey withdraws one issued key before use. Revoking an
// already revoked key is a terminal no-op; a consumed key is refused because it
// is spent; an expired key is refused because its window already ended on its
// own and reporting it as revoked would misstate the audit trail.
func (s *Store) RevokeMeshEnrollmentKey(keyID string) (MeshEnrollmentKeyRecord, error) {
	if err := subscription.ValidateID(keyID); err != nil {
		return MeshEnrollmentKeyRecord{}, MeshError(mesh.CodeKeyIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshEnrollmentKeyTx(tx, keyID)
	if err != nil {
		return MeshEnrollmentKeyRecord{}, err
	}
	switch record.State {
	case mesh.KeyRevoked:
		if err = tx.Commit(); err != nil {
			return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		return record, nil
	case mesh.KeyConsumed:
		return MeshEnrollmentKeyRecord{}, MeshError(mesh.CodeKeyTransitionInvalid, "a consumed key cannot be revoked")
	case mesh.KeyExpired:
		return MeshEnrollmentKeyRecord{}, MeshError(mesh.CodeKeyTransitionInvalid, "an expired key cannot be revoked")
	}
	var hash []byte
	var issuedAt, expiresAt int64
	if err = tx.QueryRow(`SELECT secret_hash, issued_at, expires_at FROM mesh_enrollment_keys WHERE id=?`, keyID).
		Scan(&hash, &issuedAt, &expiresAt); err != nil {
		return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	key := mesh.EnrollmentKey{
		ID:        record.ID,
		DeviceID:  record.DeviceID,
		Hash:      hash,
		State:     record.State,
		IssuedAt:  time.Unix(issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(expiresAt, 0).UTC(),
	}
	if _, err = key.Revoke(); err != nil {
		return MeshEnrollmentKeyRecord{}, err
	}
	if _, err = tx.Exec(`UPDATE mesh_enrollment_keys SET state='revoked' WHERE id=? AND state='issued'`, keyID); err != nil {
		return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	record.State = mesh.KeyRevoked
	return record, nil
}

// listMeshEnrollmentKeys returns the key history of one device, oldest first.
// It exposes no digest, so the plaintext secret has no read path at all: the
// only way a key leaves the issued state is the registration transaction that
// proves the enrollment, or an explicit revoke/expire.
func (s *Store) ListMeshEnrollmentKeys(deviceID string) ([]MeshEnrollmentKeyRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return nil, MeshError(mesh.CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	rows, err := s.DB.Query(`SELECT id, device_id, state, issued_at, expires_at, consumed_at
 FROM mesh_enrollment_keys WHERE device_id=? ORDER BY issued_at ASC, id ASC`, deviceID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []MeshEnrollmentKeyRecord{}
	for rows.Next() {
		var (
			record MeshEnrollmentKeyRecord
			state  string
		)
		if err := rows.Scan(&record.ID, &record.DeviceID, &state, &record.IssuedAt, &record.ExpiresAt, &record.ConsumedAt); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		record.State = mesh.KeyState(state)
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// meshEnrollmentKeyTx loads one key record without its digest.
func meshEnrollmentKeyTx(tx *sql.Tx, keyID string) (MeshEnrollmentKeyRecord, error) {
	var (
		record MeshEnrollmentKeyRecord
		state  string
	)
	err := tx.QueryRow(`SELECT id, device_id, state, issued_at, expires_at, consumed_at
 FROM mesh_enrollment_keys WHERE id=?`, keyID).
		Scan(&record.ID, &record.DeviceID, &state, &record.IssuedAt, &record.ExpiresAt, &record.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MeshEnrollmentKeyRecord{}, MeshError(CodeMeshEnrollmentKeyNotFound, "unknown enrollment key")
	}
	if err != nil {
		return MeshEnrollmentKeyRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	record.State = mesh.KeyState(state)
	if err := record.State.Validate(); err != nil {
		return MeshEnrollmentKeyRecord{}, err
	}
	return record, nil
}

// migrateSchema6 adds the mesh device and one-time enrollment key tables. It is
// purely additive: no schema-5 table or row is rewritten. The new tables hold
// only mesh data, so dropping them returns the file to the previous schema-5
// shape without losing any node, subscriber, credential or task history.
//
// The two partial unique indexes are the database form of the domain rules:
// one device holds at most one issued key, and a node name is unique per
// Headscale user only while the device still occupies it (pending, registered
// or revoking). The trigger makes consumed, expired and revoked keys terminal at
// the storage boundary, so a stray UPDATE cannot revive a spent key.
func migrateSchema6(tx *sql.Tx) error {
	if _, err := tx.Exec(fmt.Sprintf(`
CREATE TABLE mesh_devices (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('proxy_mesh','mesh_only','subnet_router')),
  platform TEXT NOT NULL CHECK(platform IN ('ios','android','linux','nas','other')),
  subscriber_id TEXT REFERENCES subscribers(id),
  headscale_user TEXT NOT NULL,
  node_name TEXT NOT NULL,
  headscale_node_id INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('pending','registered','expired','revoking','revoked','failed')),
  revoke_reason TEXT NOT NULL DEFAULT '',
  revoke_requested_at INTEGER NOT NULL DEFAULT 0,
  observed_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(purpose<>'proxy_mesh' OR subscriber_id IS NOT NULL),
  CHECK(purpose<>'mesh_only' OR subscriber_id IS NULL),
  CHECK(status NOT IN ('pending','failed') OR headscale_node_id=0),
  CHECK(status<>'registered' OR headscale_node_id<>0)
);
CREATE UNIQUE INDEX mesh_devices_node_name_occupied
  ON mesh_devices(headscale_user, node_name)
  WHERE status IN ('pending','registered','revoking');
CREATE INDEX mesh_devices_subscriber ON mesh_devices(subscriber_id);
CREATE TABLE mesh_enrollment_keys (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES mesh_devices(id) ON DELETE CASCADE,
  secret_hash BLOB,
  state TEXT NOT NULL CHECK(state IN ('issued','consumed','expired','revoked')),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL DEFAULT 0,
  CHECK(expires_at=issued_at+%d),
  CHECK((state='consumed' AND secret_hash IS NULL) OR (state<>'consumed' AND secret_hash IS NOT NULL AND length(secret_hash)=32)),
  CHECK(state<>'consumed' OR (consumed_at>=issued_at AND consumed_at<=expires_at))
);
CREATE UNIQUE INDEX mesh_enrollment_keys_single_active
  ON mesh_enrollment_keys(device_id)
  WHERE state='issued';
CREATE UNIQUE INDEX mesh_enrollment_keys_digest
  ON mesh_enrollment_keys(secret_hash)
  WHERE secret_hash IS NOT NULL;
CREATE INDEX mesh_enrollment_keys_device ON mesh_enrollment_keys(device_id, issued_at);
CREATE TRIGGER mesh_key_consumed_terminal
  BEFORE UPDATE ON mesh_enrollment_keys
  WHEN OLD.state IN ('consumed','expired','revoked')
BEGIN
  SELECT RAISE(ABORT, 'MESH_ENROLLMENT_KEY_TERMINAL');
END;
PRAGMA user_version=6;
`, int64(mesh.KeyTTL/time.Second))); err != nil {
		return err
	}
	return nil
}

// Store-level codes for the subnet route persistence boundary. Domain refusals
// keep their mesh.Code* value; these describe the storage-only facts the pure
// domain package does not model: a missing row, a prefix another device already
// holds, a corrupt row and a prefix Headscale reports without a declaration.
const (
	CodeMeshRouteConflict  = "MESH_ROUTE_CONFLICT"
	CodeMeshRouteNotFound  = "MESH_ROUTE_NOT_FOUND"
	CodeMeshRouteCorrupt   = "MESH_ROUTE_CORRUPT"
	CodeMeshRouteUntracked = "MESH_ROUTE_UNTRACKED"
)

// The event kinds of mesh_route_events. Each value is the stable code the audit
// trail records; MESH_ROUTE_UNTRACKED is the one reconcile appends when
// Headscale reports a prefix that no device declared. None of them is a state a
// route row can hold: the row keeps desired and observed, the events keep how
// they changed.
const (
	RouteEventDeclared  = "MESH_ROUTE_DECLARED"
	RouteEventApproved  = "MESH_ROUTE_APPROVED"
	RouteEventWithdrawn = "MESH_ROUTE_WITHDRAWN"
	RouteEventRevoked   = "MESH_ROUTE_REVOKED"
	routeEventObserved  = "MESH_ROUTE_OBSERVED"
	routeEventUntracked = CodeMeshRouteUntracked
)

// MeshRouteRecord is one stored subnet route declaration plus the last reported
// evidence. Desired is MeshMux's intent and Observed is what Headscale last
// reported; the two are stored apart so an observation can never approve a
// prefix and an approval never claims the prefix is actually served.
type MeshRouteRecord struct {
	DeviceID    string             `json:"device_id"`
	Prefix      string             `json:"prefix"`
	Desired     mesh.RouteDesired  `json:"desired"`
	Observed    mesh.RouteObserved `json:"observed,omitempty"`
	Source      mesh.RouteSource   `json:"source"`
	OperationID string             `json:"operation_id,omitempty"`
	CreatedAt   int64              `json:"created_at"`
	UpdatedAt   int64              `json:"updated_at"`
}

// meshRouteSelect is the single read projection of one route row. No column is
// derived: the route state is what was stored.
const meshRouteSelect = `SELECT device_id, prefix, desired, observed, source, operation_id, created_at, updated_at
FROM mesh_routes`

// errMeshRouteCorrupt marks a stored row that no longer satisfies the domain
// rules, so a hand-edited database is never rendered as a valid declaration.
var errMeshRouteCorrupt = errors.New(CodeMeshRouteCorrupt)

func meshRouteError(code, detail string) error {
	return errors.New(code + ": " + detail)
}

// meshRouteReadError separates a corrupt stored row from an unavailable
// database.
func meshRouteReadError(err error) error {
	if errors.Is(err, errMeshRouteCorrupt) {
		return meshRouteError(CodeMeshRouteCorrupt, "the stored subnet route record is invalid")
	}
	return errors.New("DATABASE_UNAVAILABLE")
}

func scanMeshRoute(row rowScanner) (MeshRouteRecord, error) {
	var (
		record   MeshRouteRecord
		desired  string
		observed string
		source   string
	)
	if err := row.Scan(&record.DeviceID, &record.Prefix, &desired, &observed, &source,
		&record.OperationID, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return MeshRouteRecord{}, err
	}
	record.Desired = mesh.RouteDesired(desired)
	record.Observed = mesh.RouteObserved(observed)
	record.Source = mesh.RouteSource(source)
	// A stored row has to satisfy the same rules the write path applied, so a
	// hand-edited prefix or state is reported instead of rendered.
	if err := (mesh.MeshRoute{
		DeviceID: record.DeviceID,
		Prefix:   record.Prefix,
		Desired:  record.Desired,
		Observed: record.Observed,
		Source:   record.Source,
	}).Validate(); err != nil {
		return MeshRouteRecord{}, errMeshRouteCorrupt
	}
	return record, nil
}

// meshRouteTx loads one route inside the caller's transaction. A missing row is
// returned as sql.ErrNoRows, because the declaration path treats "not declared
// yet" as an ordinary case rather than a failure.
func meshRouteTx(tx *sql.Tx, deviceID, prefix string) (MeshRouteRecord, error) {
	return scanMeshRoute(tx.QueryRow(meshRouteSelect+` WHERE device_id=? AND prefix=?`, deviceID, prefix))
}

// getMeshRoute returns one stored declaration.
func (s *Store) GetMeshRoute(deviceID, prefix string) (MeshRouteRecord, error) {
	record, err := scanMeshRoute(s.DB.QueryRow(meshRouteSelect+` WHERE device_id=? AND prefix=?`, deviceID, prefix))
	if errors.Is(err, sql.ErrNoRows) {
		return MeshRouteRecord{}, meshRouteError(CodeMeshRouteNotFound, "the device does not declare this prefix")
	}
	if err != nil {
		return MeshRouteRecord{}, meshRouteReadError(err)
	}
	return record, nil
}

// upsertMeshRoute declares one prefix for one device with desired=advertised.
// It is the only path that creates a route row, and the only path that revives
// a revoked one, because reviving a withdrawn prefix is a new declaration and
// not an ordinary state transition.
//
// The declaration is idempotent: declaring an already advertised or approved
// prefix changes nothing and appends no event. A revoked route is revived to
// advertised and requires an audit operation id, which the database trigger
// also enforces.
//
// A prefix belongs to one device at a time: another device holding the same
// prefix in a non-revoked state is MESH_ROUTE_CONFLICT, and the partial unique
// index refuses it even if the pre-check were bypassed. A revoked device is a
// tombstone and cannot declare anything.
func (s *Store) UpsertMeshRoute(deviceID, rawPrefix string, source mesh.RouteSource, operationID string, now time.Time) (MeshRouteRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	prefix, err := mesh.NormalizeRoutePrefix(rawPrefix)
	if err != nil {
		return MeshRouteRecord{}, err
	}
	if err = source.Validate(); err != nil {
		return MeshRouteRecord{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if err = meshRouteDeviceWritableTx(tx, deviceID); err != nil {
		return MeshRouteRecord{}, err
	}
	if err = meshRouteConflictTx(tx, prefix, deviceID); err != nil {
		return MeshRouteRecord{}, err
	}

	existing, err := meshRouteTx(tx, deviceID, prefix)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.Exec(`INSERT INTO mesh_routes(device_id, prefix, desired, observed, source, operation_id, created_at, updated_at)
 VALUES(?,?,'advertised','',?,?,?,?)`,
			deviceID, prefix, string(source), operationID, now.Unix(), now.Unix()); err != nil {
			if meshRoutePrefixConflict(err) {
				return MeshRouteRecord{}, meshRouteError(CodeMeshRouteConflict, "the prefix is already declared by another device")
			}
			return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if err = recordMeshRouteEventTx(tx, deviceID, prefix, RouteEventDeclared,
			"", string(mesh.RouteDesiredAdvertised), "", "", operationID, now); err != nil {
			return MeshRouteRecord{}, err
		}
	case err != nil:
		return MeshRouteRecord{}, meshRouteReadError(err)
	case existing.Desired == mesh.RouteDesiredRevoked:
		if operationID == "" {
			return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "reviving a revoked prefix needs an audit operation id")
		}
		if operationID == existing.OperationID {
			return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "reviving a revoked prefix needs a new audit operation id")
		}
		// The audit event is written first, because the revival trigger only
		// accepts a DECLARED event carrying this exact operation id. A failed
		// update rolls the event back with the transaction.
		if err = recordMeshRouteEventTx(tx, deviceID, prefix, RouteEventDeclared,
			string(mesh.RouteDesiredRevoked), string(mesh.RouteDesiredAdvertised), "", "", operationID, now); err != nil {
			return MeshRouteRecord{}, err
		}
		res, execErr := tx.Exec(`UPDATE mesh_routes SET desired='advertised', operation_id=?, updated_at=?
 WHERE device_id=? AND prefix=? AND desired='revoked'`, operationID, now.Unix(), deviceID, prefix)
		if execErr != nil {
			return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "the subnet route state changed concurrently")
		}
	default:
		// advertised or approved: the declaration already stands. The first
		// declaration owns the provenance, so source is not rewritten.
		if err = tx.Commit(); err != nil {
			return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		return existing, nil
	}
	if err = tx.Commit(); err != nil {
		return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.GetMeshRoute(deviceID, prefix)
}

// setMeshRouteDesired applies one explicit desired-state change: approval, a
// withdrawn approval, or a revocation. It is idempotent for a repeated state and
// refuses to revive a revoked route, which upsertMeshRoute owns as a new
// declaration.
//
// Every real change needs an audit operation id; the row's operation_id becomes
// that key and one append-only event records the edge. An empty id is refused
// here and by the database trigger, so no path can change intent unaudited.
func (s *Store) SetMeshRouteDesired(deviceID, rawPrefix string, desired mesh.RouteDesired, operationID string, now time.Time) (MeshRouteRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	prefix, err := mesh.NormalizeRoutePrefix(rawPrefix)
	if err != nil {
		return MeshRouteRecord{}, err
	}
	if err = desired.Validate(); err != nil {
		return MeshRouteRecord{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	existing, err := meshRouteTx(tx, deviceID, prefix)
	if errors.Is(err, sql.ErrNoRows) {
		return MeshRouteRecord{}, meshRouteError(CodeMeshRouteNotFound, "the device does not declare this prefix")
	}
	if err != nil {
		return MeshRouteRecord{}, meshRouteReadError(err)
	}
	if existing.Desired == desired {
		// Idempotent repeat: the first transition owns the audit event.
		if err = tx.Commit(); err != nil {
			return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		return existing, nil
	}
	if existing.Desired == mesh.RouteDesiredRevoked {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "a revoked prefix is revived by declaring it again")
	}
	if !mesh.RouteTransitionAllowed(existing.Desired, desired) {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "the requested route desired-state transition is not allowed")
	}
	if operationID == "" {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "changing the desired route state needs an audit operation id")
	}
	res, err := tx.Exec(`UPDATE mesh_routes SET desired=?, operation_id=?, updated_at=?
 WHERE device_id=? AND prefix=? AND desired=?`,
		string(desired), operationID, now.Unix(), deviceID, prefix, string(existing.Desired))
	if err != nil {
		return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return MeshRouteRecord{}, meshRouteError(mesh.CodeRouteTransitionInvalid, "the subnet route state changed concurrently")
	}
	kind := RouteEventWithdrawn
	switch desired {
	case mesh.RouteDesiredApproved:
		kind = RouteEventApproved
	case mesh.RouteDesiredRevoked:
		kind = RouteEventRevoked
	}
	if err = recordMeshRouteEventTx(tx, deviceID, prefix, kind,
		string(existing.Desired), string(desired), "", "", operationID, now); err != nil {
		return MeshRouteRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return MeshRouteRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.GetMeshRoute(deviceID, prefix)
}

// recordMeshRouteObservation stores what one Headscale read reported for one
// prefix. It never touches desired or the source: an observation is evidence,
// and evidence never approves a prefix. The row's operation_id becomes the
// observation's audit key (mesh_routes keeps the most recent audit key), while
// the intent itself is untouched.
//
// A prefix Headscale reports for a device that never declared it is not stored
// as a route at all. Only a MESH_ROUTE_UNTRACKED audit event is appended, so the
// operator sees the advertisement without MeshMux silently adopting (or
// approving) it. The boolean result reports whether the prefix was declared.
// That path accepts any aligned prefix, including an exit route or the tailnet
// range: refusing to *record* that a device advertises 0.0.0.0/0 would hide
// exactly the advertisement an operator has to see. Nothing routable is created.
//
// An empty observed value means "Headscale reported nothing". It is stored as
// such and never reverts desired: a prefix that stops being advertised stays
// approved in MeshMux's intent until an operator revokes it.
func (s *Store) RecordMeshRouteObservation(deviceID, rawPrefix string, observed mesh.RouteObserved, operationID string, now time.Time) (MeshRouteRecord, bool, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshRouteRecord{}, false, meshRouteError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	parsed, err := mesh.ParseRoutePrefix(rawPrefix)
	if err != nil {
		return MeshRouteRecord{}, false, err
	}
	prefix := parsed.String()
	if err = observed.Validate(); err != nil {
		return MeshRouteRecord{}, false, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return MeshRouteRecord{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if err = meshRouteDeviceExists(tx, deviceID); err != nil {
		return MeshRouteRecord{}, false, err
	}
	existing, err := meshRouteTx(tx, deviceID, prefix)
	if errors.Is(err, sql.ErrNoRows) {
		if err = recordUntrackedObservationTx(tx, deviceID, prefix, observed, operationID, now); err != nil {
			return MeshRouteRecord{}, false, err
		}
		if err = tx.Commit(); err != nil {
			return MeshRouteRecord{}, false, errors.New("DATABASE_UNAVAILABLE")
		}
		return MeshRouteRecord{}, false, nil
	}
	if err != nil {
		return MeshRouteRecord{}, false, meshRouteReadError(err)
	}
	if existing.Observed == observed {
		// Nothing changed: a repeated read appends no event, so the audit trail
		// stays a record of changes rather than of polls.
		if err = tx.Commit(); err != nil {
			return MeshRouteRecord{}, false, errors.New("DATABASE_UNAVAILABLE")
		}
		return existing, true, nil
	}
	if _, err = tx.Exec(`UPDATE mesh_routes SET observed=?, operation_id=?, updated_at=? WHERE device_id=? AND prefix=?`,
		string(observed), operationID, now.Unix(), deviceID, prefix); err != nil {
		return MeshRouteRecord{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = recordMeshRouteEventTx(tx, deviceID, prefix, routeEventObserved,
		string(existing.Desired), string(existing.Desired), string(existing.Observed), string(observed), operationID, now); err != nil {
		return MeshRouteRecord{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return MeshRouteRecord{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	record, err := s.GetMeshRoute(deviceID, prefix)
	if err != nil {
		return MeshRouteRecord{}, false, err
	}
	return record, true, nil
}

// MeshRouteObservation is one prefix as a Headscale read reported it. A caller
// that reads a node's routes builds these from the advertised, approved and
// served lists; the store never derives one list from another.
type MeshRouteObservation struct {
	Prefix   string
	Observed mesh.RouteObserved
}

// MeshRouteReconcileResult summarises one reconcile pass over a device's
// reported prefixes. It carries counts, never prefixes, so a log line built from
// it stays free of network detail.
type MeshRouteReconcileResult struct {
	Tracked   int
	Untracked int
	Changed   int
}

// reconcileMeshRoutes records what one Headscale read reported for one device.
// It is the store half of the reconcile chain: the caller supplies the prefixes
// and their observed state, and this method decides nothing about intent.
//
// The rule it enforces is the one ADR-0004 states: a prefix the device
// advertises but never declared is only recorded as MESH_ROUTE_UNTRACKED. It is
// never inserted as a route, never approved, and never promoted to a pending
// declaration, so a compromised or misconfigured client cannot widen the
// approved LAN by advertising something new. Approval stays an explicit,
// separately audited operator act.
func (s *Store) ReconcileMeshRoutes(deviceID string, observations []MeshRouteObservation, operationID string, now time.Time) (MeshRouteReconcileResult, error) {
	var result MeshRouteReconcileResult
	if err := subscription.ValidateID(deviceID); err != nil {
		return result, meshRouteError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	if err := meshRouteDeviceExists(s.DB, deviceID); err != nil {
		return result, err
	}
	before, err := s.ListMeshRoutes(deviceID)
	if err != nil {
		return result, err
	}
	previous := make(map[string]mesh.RouteObserved, len(before))
	for _, route := range before {
		previous[route.Prefix] = route.Observed
	}
	for _, observation := range observations {
		record, declared, err := s.RecordMeshRouteObservation(deviceID, observation.Prefix, observation.Observed, operationID, now)
		if err != nil {
			return result, err
		}
		if !declared {
			result.Untracked++
			continue
		}
		result.Tracked++
		if was, ok := previous[record.Prefix]; !ok || was != record.Observed {
			result.Changed++
		}
		previous[record.Prefix] = record.Observed
	}
	return result, nil
}

// listMeshRoutes returns every declaration of one device in prefix order,
// revoked ones included: a withdrawn prefix is history, not a deleted row.
func (s *Store) ListMeshRoutes(deviceID string) ([]MeshRouteRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return nil, meshRouteError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	rows, err := s.DB.Query(meshRouteSelect+` WHERE device_id=? ORDER BY prefix ASC`, deviceID)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	return collectMeshRoutes(rows)
}

// listMeshRoutesPending returns every declaration still awaiting an explicit
// approval (desired=advertised) across all devices. It is the read model of the
// approval queue and performs no Headscale call.
func (s *Store) ListMeshRoutesPending() ([]MeshRouteRecord, error) {
	rows, err := s.DB.Query(meshRouteSelect + ` WHERE desired='advertised' ORDER BY device_id ASC, prefix ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	return collectMeshRoutes(rows)
}

func collectMeshRoutes(rows *sql.Rows) ([]MeshRouteRecord, error) {
	out := []MeshRouteRecord{}
	for rows.Next() {
		record, err := scanMeshRoute(rows)
		if err != nil {
			return nil, meshRouteReadError(err)
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// rowQueryer is the single-row read a store or a transaction both provide, so
// one helper can run inside or outside an explicit transaction.
type rowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

// meshRouteDeviceExists reports MESH_DEVICE_NOT_FOUND for an unknown device.
func meshRouteDeviceExists(q rowQueryer, deviceID string) error {
	var status string
	err := q.QueryRow(`SELECT status FROM mesh_devices WHERE id=?`, deviceID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return meshRouteError(CodeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// meshRouteDeviceWritableTx refuses a device that is on its way out and any
// purpose other than subnet_router. A revoking device already has every live
// prefix withdrawn in the revocation transaction, so accepting a new
// declaration would re-approve a LAN on a device Headscale is removing; a
// revoked device is a tombstone. A proxy_mesh or mesh_only device is not the
// router of a LAN, so it cannot declare either.
func meshRouteDeviceWritableTx(tx *sql.Tx, deviceID string) error {
	var status, purpose string
	err := tx.QueryRow(`SELECT status, purpose FROM mesh_devices WHERE id=?`, deviceID).Scan(&status, &purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return meshRouteError(CodeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	switch mesh.Status(status) {
	case mesh.StatusRevoking:
		return meshRouteError(mesh.CodeRouteTransitionInvalid, "a device being revoked cannot declare subnet routes")
	case mesh.StatusRevoked:
		return meshRouteError(mesh.CodeRouteTransitionInvalid, "a revoked device cannot declare subnet routes")
	}
	if mesh.Purpose(purpose) != mesh.PurposeSubnetRouter {
		return meshRouteError(mesh.CodeRouteDeclarationInvalid, "only a subnet_router device can declare subnet routes")
	}
	return nil
}

// meshRouteConflictTx reports a prefix another device still holds. Revoked rows
// do not conflict: a withdrawn prefix is free for a new declaration.
func meshRouteConflictTx(tx *sql.Tx, prefix, deviceID string) error {
	var other string
	err := tx.QueryRow(`SELECT device_id FROM mesh_routes
 WHERE prefix=? AND desired<>'revoked' AND device_id<>?`, prefix, deviceID).Scan(&other)
	if err == nil {
		return meshRouteError(CodeMeshRouteConflict, "the prefix is already declared by another device")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// meshRoutePrefixConflict narrows a UNIQUE failure to the active-prefix index,
// so a race between two declarations is reported as the domain conflict instead
// of a generic storage failure.
func meshRoutePrefixConflict(err error) bool {
	return uniqueConstraint(err) && strings.Contains(err.Error(), "mesh_routes.prefix")
}

// recordUntrackedObservationTx appends one MESH_ROUTE_UNTRACKED event for a
// prefix Headscale reports but no device declared. A repeated read of the same
// evidence appends nothing, so the audit trail records changes rather than
// polls. No route row is created: an untracked advertisement is evidence for the
// operator, never an implicit declaration or approval.
func recordUntrackedObservationTx(tx *sql.Tx, deviceID, prefix string, observed mesh.RouteObserved, operationID string, now time.Time) error {
	var last string
	err := tx.QueryRow(`SELECT to_observed FROM mesh_route_events
 WHERE device_id=? AND prefix=? AND kind=? ORDER BY id DESC LIMIT 1`,
		deviceID, prefix, routeEventUntracked).Scan(&last)
	if err == nil && last == string(observed) {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return recordMeshRouteEventTx(tx, deviceID, prefix, routeEventUntracked,
		"", "", "", string(observed), operationID, now)
}

// recordMeshRouteEventTx appends one audit row. The table is append-only at the
// storage boundary (two triggers refuse UPDATE and DELETE), so this helper is
// the only writer.
func recordMeshRouteEventTx(tx *sql.Tx, deviceID, prefix, kind, fromDesired, toDesired, fromObserved, toObserved, operationID string, now time.Time) error {
	if _, err := tx.Exec(`INSERT INTO mesh_route_events(device_id, prefix, kind, from_desired, to_desired, from_observed, to_observed, operation_id, created_at)
 VALUES(?,?,?,?,?,?,?,?,?)`,
		deviceID, prefix, kind, fromDesired, toDesired, fromObserved, toObserved, operationID, now.Unix()); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// revokeDeviceRoutesTx withdraws every live route of one device in the caller's
// transaction. It is the route half of device revocation: the device row, its
// routes and one audit event per route settle together, so a device can never be
// revoked while its prefixes stay approved.
//
// The operation id is the audit key of the revocation act. The caller passes the
// one it already logged; when it has none, the store mints one, so the trigger's
// "no desired change without an audit key" rule always holds.
func revokeDeviceRoutesTx(tx *sql.Tx, deviceID, operationID string, now time.Time) error {
	rows, err := tx.Query(`SELECT prefix, desired FROM mesh_routes
 WHERE device_id=? AND desired<>'revoked' ORDER BY prefix`, deviceID)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	type liveRoute struct {
		prefix  string
		desired string
	}
	var live []liveRoute
	for rows.Next() {
		var route liveRoute
		if err := rows.Scan(&route.prefix, &route.desired); err != nil {
			rows.Close()
			return errors.New("DATABASE_UNAVAILABLE")
		}
		live = append(live, route)
	}
	if err := rows.Close(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err := rows.Err(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if len(live) == 0 {
		return nil
	}
	if operationID == "" {
		// The revocation act still needs one stable audit key even when the
		// caller only has a device id; the minted value is returned to the
		// caller's log line by the handler's own operation id, not this one.
		minted, err := protocol.NewID()
		if err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		operationID = minted
	}
	for _, route := range live {
		res, err := tx.Exec(`UPDATE mesh_routes SET desired='revoked', operation_id=?, updated_at=?
 WHERE device_id=? AND prefix=? AND desired=?`, operationID, now.Unix(), deviceID, route.prefix, route.desired)
		if err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return meshRouteError(mesh.CodeRouteTransitionInvalid, "the subnet route state changed concurrently")
		}
		if err := recordMeshRouteEventTx(tx, deviceID, route.prefix, RouteEventRevoked,
			route.desired, string(mesh.RouteDesiredRevoked), "", "", operationID, now); err != nil {
			return err
		}
	}
	return nil
}

// migrateSchema7 adds the subnet route declaration and its append-only audit
// trail. It is purely additive: no schema-6 table or row is rewritten, and
// dropping the two new tables returns the file to the schema-6 shape without
// losing a device or key.
//
// The database expresses the rules the store also checks:
//   - one prefix belongs to at most one device while it is not revoked, via the
//     partial unique index over prefix;
//   - a desired-state change needs an audit operation id, and a revoked row can
//     only come back with a different one, so no unaudited path can approve or
//     revive a prefix;
//   - a route is never born revoked: revocation is an audited transition, not an
//     initial state;
//   - the audit table is append-only, so the history of an approval cannot be
//     rewritten after the fact.
func migrateSchema7(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE mesh_routes (
  device_id TEXT NOT NULL REFERENCES mesh_devices(id) ON DELETE CASCADE,
  prefix TEXT NOT NULL,
  desired TEXT NOT NULL CHECK(desired IN ('advertised','approved','revoked')),
  observed TEXT NOT NULL DEFAULT '' CHECK(observed IN ('','advertised','approved','served')),
  source TEXT NOT NULL CHECK(source IN ('device','operator')),
  operation_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(device_id, prefix)
);
CREATE UNIQUE INDEX mesh_routes_prefix_active
  ON mesh_routes(prefix)
  WHERE desired<>'revoked';
CREATE INDEX mesh_routes_desired ON mesh_routes(desired, device_id);
CREATE TABLE mesh_route_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  prefix TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('MESH_ROUTE_DECLARED','MESH_ROUTE_APPROVED','MESH_ROUTE_WITHDRAWN','MESH_ROUTE_REVOKED','MESH_ROUTE_OBSERVED','MESH_ROUTE_UNTRACKED')),
  from_desired TEXT NOT NULL DEFAULT '',
  to_desired TEXT NOT NULL DEFAULT '',
  from_observed TEXT NOT NULL DEFAULT '',
  to_observed TEXT NOT NULL DEFAULT '',
  operation_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX mesh_route_events_device ON mesh_route_events(device_id, id);
CREATE TRIGGER mesh_route_events_append_only_update
  BEFORE UPDATE ON mesh_route_events
BEGIN
  SELECT RAISE(ABORT, 'MESH_ROUTE_EVENT_IMMUTABLE');
END;
CREATE TRIGGER mesh_route_events_append_only_delete
  BEFORE DELETE ON mesh_route_events
BEGIN
  SELECT RAISE(ABORT, 'MESH_ROUTE_EVENT_IMMUTABLE');
END;
CREATE TRIGGER mesh_route_insert_not_revoked
  BEFORE INSERT ON mesh_routes
  WHEN NEW.desired='revoked'
BEGIN
  SELECT RAISE(ABORT, 'MESH_ROUTE_TRANSITION_UNAUDITED');
END;
CREATE TRIGGER mesh_route_transition_audited
  BEFORE UPDATE OF desired ON mesh_routes
  WHEN NEW.desired<>OLD.desired
   AND (NEW.operation_id='' OR (OLD.desired='revoked' AND NEW.operation_id=OLD.operation_id))
BEGIN
  SELECT RAISE(ABORT, 'MESH_ROUTE_TRANSITION_UNAUDITED');
END;
CREATE TRIGGER mesh_route_revoked_revival_audited
  BEFORE UPDATE OF desired ON mesh_routes
  WHEN OLD.desired='revoked' AND NEW.desired<>'revoked'
   AND NOT EXISTS (
     SELECT 1 FROM mesh_route_events
     WHERE device_id=OLD.device_id AND prefix=OLD.prefix
       AND kind='MESH_ROUTE_DECLARED' AND operation_id=NEW.operation_id)
BEGIN
  SELECT RAISE(ABORT, 'MESH_ROUTE_REVIVAL_UNTRACKED');
END;
PRAGMA user_version=7;
`); err != nil {
		return err
	}
	return nil
}
