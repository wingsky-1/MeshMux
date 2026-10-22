package web

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// Store-level codes for the mesh persistence boundary. Domain refusals keep
// their mesh.Code* value; these only describe a missing row, which the pure
// domain package does not model.
const (
	codeMeshDeviceNotFound        = "MESH_DEVICE_NOT_FOUND"
	codeMeshDeviceCorrupt         = "MESH_DEVICE_CORRUPT"
	codeMeshEnrollmentKeyNotFound = "MESH_ENROLLMENT_KEY_NOT_FOUND"
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

func meshError(code, detail string) error {
	return errors.New(code + ": " + detail)
}

// errMeshDeviceCorrupt marks a stored row that no longer satisfies the domain
// rules, so a hand-edited database is never rendered as a valid device.
var errMeshDeviceCorrupt = errors.New(codeMeshDeviceCorrupt)

// meshReadError separates a corrupt stored record from an unavailable database.
func meshReadError(err error) error {
	if errors.Is(err, errMeshDeviceCorrupt) {
		return meshError(codeMeshDeviceCorrupt, "the stored mesh device record is invalid")
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
		return MeshDeviceRecord{}, meshError(codeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return MeshDeviceRecord{}, meshReadError(err)
	}
	return record, nil
}

// createMeshDevice persists one pending device. The pure domain constructor
// validates the purpose×subscriber binding and the canonical node name; the
// store adds the two facts the domain cannot check without I/O: the subscriber
// row exists, and the occupied node name is unique.
//
// Node-name uniqueness is a partial unique index over the statuses that still
// occupy the name, so revoked, expired and failed devices release it. A missing
// subscriber binding is stored as NULL, never as an empty string, so the
// foreign key and the purpose CHECK stay enforceable.
func (s *store) createMeshDevice(spec mesh.DeviceSpec, now time.Time) (MeshDeviceRecord, error) {
	device, err := mesh.NewMeshDevice(spec)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var subscriber any
	if device.SubscriberID != "" {
		var state string
		err = tx.QueryRow(`SELECT state FROM subscribers WHERE id=?`, device.SubscriberID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return MeshDeviceRecord{}, meshError(mesh.CodeSubscriberBindingInvalid, "the subscriber does not exist")
		}
		if err != nil {
			return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if state == string(subscription.StateDeleting) || state == string(subscription.StateDeleted) {
			return MeshDeviceRecord{}, meshError(mesh.CodeSubscriberBindingInvalid, "a deleting or deleted subscriber cannot own a mesh device")
		}
		subscriber = device.SubscriberID
	}
	if _, err = tx.Exec(`INSERT INTO mesh_devices(id, display_name, purpose, platform, subscriber_id, headscale_user,
 node_name, headscale_node_id, status, revoke_reason, revoke_requested_at, observed_at, created_at, updated_at)
 VALUES(?,?,?,?,?,?,?,0,'pending','',0,0,?,?)`,
		device.ID, device.DisplayName, string(device.Purpose), string(device.Platform), subscriber,
		device.HeadscaleUser, device.NodeName, now.Unix(), now.Unix()); err != nil {
		if meshNodeNameConflict(err) {
			return MeshDeviceRecord{}, meshError(mesh.CodeNodeNameDuplicate, "the node name is already occupied for this headscale user")
		}
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.getMeshDevice(device.ID)
}

func uniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// renameMeshDevice changes only the mutable display label. The id, purpose,
// binding, node name and lifecycle stay exactly as they were, so a label edit
// can never move a device or release an occupied name. A revoked device is a
// tombstone and keeps its last label.
func (s *store) renameMeshDevice(deviceID, displayName string, now time.Time) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, meshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	name, err := subscription.NormalizeDisplayName(displayName)
	if err != nil {
		return MeshDeviceRecord{}, meshError(mesh.CodeDisplayNameInvalid, "use 1-80 normalized printable characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	if record.Status == mesh.StatusRevoked {
		return MeshDeviceRecord{}, meshError(mesh.CodeStatusTransitionInvalid, "a revoked device is a tombstone and cannot be renamed")
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
func (s *store) getMeshDevice(deviceID string) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, meshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	record, err := scanMeshDevice(s.db.QueryRow(meshDeviceSelect+` WHERE d.id=?`, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return MeshDeviceRecord{}, meshError(codeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return MeshDeviceRecord{}, meshReadError(err)
	}
	return record, nil
}

// listMeshDevices returns every device in creation order, revoked ones
// included: a revoked device is history, not a deleted record.
func (s *store) listMeshDevices() ([]MeshDeviceRecord, error) {
	rows, err := s.db.Query(meshDeviceSelect + ` ORDER BY d.created_at ASC, d.id ASC`)
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
func (s *store) issueMeshEnrollmentKey(deviceID string, now time.Time) (mesh.EnrollmentKey, string, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return mesh.EnrollmentKey{}, "", meshError(mesh.CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	key, secret, err := mesh.NewEnrollmentKey(deviceID, now.UTC().Truncate(time.Second))
	if err != nil {
		return mesh.EnrollmentKey{}, "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRow(`SELECT status FROM mesh_devices WHERE id=?`, deviceID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return mesh.EnrollmentKey{}, "", meshError(codeMeshDeviceNotFound, "unknown mesh device")
	}
	if err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if mesh.Status(status) != mesh.StatusPending {
		return mesh.EnrollmentKey{}, "", meshError(mesh.CodeStatusTransitionInvalid, "only a pending device can receive an enrollment key")
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
			return mesh.EnrollmentKey{}, "", meshError(mesh.CodeKeyAlreadyActive, "the device already holds an issued enrollment key")
		}
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return mesh.EnrollmentKey{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	return key, secret, nil
}

// confirmMeshEnrollment spends one key and records the proven registration in
// one transaction (D1): the device becomes registered with the observed
// Headscale node id, and the key becomes the terminal consumed state with its
// digest cleared. Clearing the digest is what makes replay impossible even
// though the row is retained for audit; a spent secret matches no row and is
// rejected like an unknown one.
func (s *store) confirmMeshEnrollment(secret string, headscaleNodeID uint64, now time.Time) (MeshDeviceRecord, error) {
	if err := mesh.ValidateEnrollmentSecret(secret); err != nil {
		return MeshDeviceRecord{}, err
	}
	if headscaleNodeID == 0 {
		return MeshDeviceRecord{}, meshError(mesh.CodeHeadscaleNodeIDInvalid, "registration needs the observed headscale node id")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var (
		keyID, deviceID, state string
		issuedAt, expiresAt    int64
		consumedAt             int64
		hash                   []byte
	)
	err = tx.QueryRow(`SELECT id, device_id, secret_hash, state, issued_at, expires_at, consumed_at
 FROM mesh_enrollment_keys WHERE secret_hash=?`, mesh.EnrollmentKeyHash(secret)).
		Scan(&keyID, &deviceID, &hash, &state, &issuedAt, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MeshDeviceRecord{}, meshError(mesh.CodeKeySecretInvalid, "unknown or already spent enrollment key")
	}
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	key := mesh.EnrollmentKey{
		ID:        keyID,
		DeviceID:  deviceID,
		Hash:      hash,
		State:     mesh.KeyState(state),
		IssuedAt:  time.Unix(issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(expiresAt, 0).UTC(),
	}
	consumed, err := key.Consume(deviceID, now)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	registered, err := record.MeshDevice.MarkRegistered(headscaleNodeID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	res, err := tx.Exec(`UPDATE mesh_enrollment_keys SET state='consumed', secret_hash=NULL, consumed_at=?
 WHERE id=? AND state='issued'`, consumed.ConsumedAt.Unix(), consumed.ID)
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return MeshDeviceRecord{}, meshError(mesh.CodeKeyTransitionInvalid, "the enrollment key was no longer issued")
	}
	res, err = tx.Exec(`UPDATE mesh_devices SET status=?, headscale_node_id=?, observed_at=?, updated_at=?
 WHERE id=? AND status='pending'`,
		string(registered.Status), registered.HeadscaleNodeID, now.Unix(), now.Unix(), deviceID)
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return MeshDeviceRecord{}, meshError(mesh.CodeStatusTransitionInvalid, "only a pending device can be registered")
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.getMeshDevice(deviceID)
}

// recordMeshObservation stores what Headscale currently reports for one device.
// A non-zero node id proves registration (pending → registered) and must stay
// the same for an already registered device. A missing node id is the opposite
// evidence: a registered device becomes expired, and a device whose removal was
// requested becomes the terminal revoked state. Other statuses are unchanged by
// a missing node, because they either never had one or already settled.
func (s *store) recordMeshObservation(deviceID string, headscaleNodeID uint64, now time.Time) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, meshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
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
				return MeshDeviceRecord{}, meshError(mesh.CodeHeadscaleNodeIDInvalid, "the observed node id does not match the registered node")
			}
		case mesh.StatusRevoking:
			// Headscale still reports the node, so the removal is not confirmed
			// yet. The device stays revoking; the observed reference is kept so
			// a retried removal names the same node. A contradiction is refused.
			if record.HeadscaleNodeID == 0 {
				next.HeadscaleNodeID = headscaleNodeID
			} else if record.HeadscaleNodeID != headscaleNodeID {
				return MeshDeviceRecord{}, meshError(mesh.CodeHeadscaleNodeIDInvalid, "the observed node id does not match the node being removed")
			}
		default:
			return MeshDeviceRecord{}, meshError(mesh.CodeStatusTransitionInvalid, "an observed node id cannot be attached to this status")
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
	if _, err = tx.Exec(`UPDATE mesh_devices SET status=?, headscale_node_id=?, observed_at=?, updated_at=? WHERE id=?`,
		string(next.Status), next.HeadscaleNodeID, now.Unix(), now.Unix(), deviceID); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.getMeshDevice(deviceID)
}

// requestMeshDeviceRevocation records one explicit revocation intent through
// the domain state machine. It is idempotent: the first intent owns the reason
// and the timestamp, a repeat reports revocation_in_progress without rewriting
// them, and an already revoked device stays terminal. It never touches a
// subscriber, a proxy credential or a subscription token: revoking one mesh
// device must not disable the whole subscriber (ADR-0004).
func (s *store) requestMeshDeviceRevocation(deviceID, reason string, now time.Time) (MeshDeviceRecord, mesh.RevokeOutcome, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, "", meshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
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
			return MeshDeviceRecord{}, "", meshError(mesh.CodeStatusTransitionInvalid, "the mesh device status changed concurrently")
		}
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, "", errors.New("DATABASE_UNAVAILABLE")
	}
	stored, err := s.getMeshDevice(deviceID)
	if err != nil {
		return MeshDeviceRecord{}, "", err
	}
	return stored, outcome, nil
}

// reenrollMeshDevice starts a fresh enrollment attempt for an expired device:
// the lifecycle goes expired → pending and the observed node reference is
// cleared, because pending means "no node is bound to this attempt yet". The
// node name is re-checked by the partial unique index in the same transaction,
// since an expired device released it and another device may have taken it in
// the meantime.
func (s *store) reenrollMeshDevice(deviceID string, now time.Time) (MeshDeviceRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return MeshDeviceRecord{}, meshError(mesh.CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	record, err := meshDeviceTx(tx, deviceID)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	next, err := record.MeshDevice.Transition(mesh.StatusPending)
	if err != nil {
		return MeshDeviceRecord{}, err
	}
	res, err := tx.Exec(`UPDATE mesh_devices SET status=?, headscale_node_id=?, updated_at=?
 WHERE id=? AND status='expired'`, string(next.Status), next.HeadscaleNodeID, now.Unix(), deviceID)
	if err != nil {
		if meshNodeNameConflict(err) {
			return MeshDeviceRecord{}, meshError(mesh.CodeNodeNameDuplicate, "the node name was taken while the device was expired")
		}
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if affected, _ := res.RowsAffected(); affected != 1 {
		return MeshDeviceRecord{}, meshError(mesh.CodeStatusTransitionInvalid, "the mesh device is no longer expired")
	}
	if err = tx.Commit(); err != nil {
		return MeshDeviceRecord{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return s.getMeshDevice(deviceID)
}

// revokeMeshEnrollmentKey withdraws one issued key before use. Revoking an
// already revoked key is a terminal no-op; a consumed key is refused because it
// is spent; an expired key is refused because its window already ended on its
// own and reporting it as revoked would misstate the audit trail.
func (s *store) revokeMeshEnrollmentKey(keyID string) (MeshEnrollmentKeyRecord, error) {
	if err := subscription.ValidateID(keyID); err != nil {
		return MeshEnrollmentKeyRecord{}, meshError(mesh.CodeKeyIDInvalid, "need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
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
		return MeshEnrollmentKeyRecord{}, meshError(mesh.CodeKeyTransitionInvalid, "a consumed key cannot be revoked")
	case mesh.KeyExpired:
		return MeshEnrollmentKeyRecord{}, meshError(mesh.CodeKeyTransitionInvalid, "an expired key cannot be revoked")
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
// It exposes no digest, so an issued key can only be spent through its one-time
// plaintext secret.
func (s *store) listMeshEnrollmentKeys(deviceID string) ([]MeshEnrollmentKeyRecord, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return nil, meshError(mesh.CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	rows, err := s.db.Query(`SELECT id, device_id, state, issued_at, expires_at, consumed_at
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
		return MeshEnrollmentKeyRecord{}, meshError(codeMeshEnrollmentKeyNotFound, "unknown enrollment key")
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
