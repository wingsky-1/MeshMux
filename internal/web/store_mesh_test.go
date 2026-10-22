package web

import (
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// meshSpec returns a valid device specification. The caller decides the purpose
// and the subscriber binding; everything else stays canonical.
func meshSpec(name string, purpose mesh.Purpose, subscriberID string) mesh.DeviceSpec {
	return mesh.DeviceSpec{
		DisplayName:  name,
		Purpose:      purpose,
		Platform:     mesh.PlatformIOS,
		NodeName:     strings.ToLower(name),
		SubscriberID: subscriberID,
	}
}

// meshSubscriberFixture creates one configured Line and one active subscriber,
// then returns the subscriber id.
func meshSubscriberFixture(t *testing.T, s *store, now time.Time) string {
	t.Helper()
	line := createEdgeNode(t, s, now)
	configureLine(t, s, line, "line-a", now)
	sub, _, err := s.createSubscriber("alice", []string{line}, now)
	if err != nil {
		t.Fatal(err)
	}
	return sub.ID
}

// TestSchemaV6MigrationAddsMeshTablesAndPreservesV5 upgrades a v5 database and
// checks that the mesh tables appear, the pre-existing rows survive and the
// future-schema guard moved to 7. The migration must stay additive: a rollback
// to the previous binary still reads every schema-5 table.
func TestSchemaV6MigrationAddsMeshTablesAndPreservesV5(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	device, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.issueMeshEnrollmentKey(device.ID, now); err != nil {
		t.Fatal(err)
	}

	// Rebuild the database in its schema-5 shape: the mesh tables do not exist
	// and the version is 5. All earlier data stays exactly as it was.
	if _, err = s.db.Exec(`DROP TABLE mesh_enrollment_keys; DROP TABLE mesh_devices; PRAGMA user_version=5;`); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("user_version=%d err=%v, want 5", version, err)
	}
	if err = s.migrate(); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 6 {
		t.Fatalf("user_version=%d err=%v, want 6", version, err)
	}
	for _, table := range []string{"mesh_devices", "mesh_enrollment_keys"} {
		var count int
		if err = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s table missing: %d err=%v", table, count, err)
		}
	}

	// The schema-5 rows and every schema-5 capability survive the upgrade.
	if _, err = s.getSubscriber(subscriberID); err != nil {
		t.Fatalf("subscriber lost by migration: %v", err)
	}
	// A mesh device is not a Line/Out node: the v6 tables never write `nodes`.
	var nodes int
	if err = s.db.QueryRow(`SELECT count(*) FROM nodes WHERE id=?`, device.ID).Scan(&nodes); err != nil || nodes != 0 {
		t.Fatalf("mesh device leaked into nodes: %d err=%v", nodes, err)
	}
	if _, err = s.createMeshDevice(meshSpec("tablet", mesh.PurposeMeshOnly, ""), now); err != nil {
		t.Fatalf("mesh creation after migration failed: %v", err)
	}

	// The guard moved with the migration.
	if _, err = s.db.Exec(`PRAGMA user_version=7`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}

// TestSchemaV6MigrationRollsBackWithoutDestroyingV5 proves the upgrade is one
// transaction: when the mesh tables cannot be created, the database stays at
// version 5 and every schema-5 table and row is still there.
func TestSchemaV6MigrationRollsBackWithoutDestroyingV5(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	line, err := s.listLines()
	if err != nil || len(line) != 1 {
		t.Fatalf("line fixture: %d %v", len(line), err)
	}

	// Simulate a v5 database with a leftover table that collides with the new
	// schema, so migrateSchema6 must fail after dropping nothing.
	if _, err = s.db.Exec(`DROP TABLE mesh_enrollment_keys; DROP TABLE mesh_devices; PRAGMA user_version=5;`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TABLE mesh_devices (stale TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrate(); err == nil || !hasErrorCode(err, "SCHEMA_MIGRATION_FAILED") {
		t.Fatalf("colliding migration reported as success: %v", err)
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("user_version=%d err=%v after failed migration, want 5", version, err)
	}
	// No partial key table survived, and the schema-5 data is untouched.
	var keys int
	if err = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mesh_enrollment_keys'`).Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("partial key table survived: %d err=%v", keys, err)
	}
	if _, err = s.getSubscriber(subscriberID); err != nil {
		t.Fatalf("subscriber lost by failed migration: %v", err)
	}
	if _, err = s.listLines(); err != nil {
		t.Fatalf("line settings lost by failed migration: %v", err)
	}
}

// TestMeshDevicePurposeBinding proves the domain binding rule is also the
// storage rule: mesh_only needs no subscriber at all, proxy_mesh needs a real
// one, and a missing subscriber cannot be smuggled in as a dangling reference.
func TestMeshDevicePurposeBinding(t *testing.T) {
	s, now := subscriberStoreFixture(t)

	// A mesh_only device is valid without any subscriber and without a Line.
	device, err := s.createMeshDevice(meshSpec("nas", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatalf("mesh_only without subscriber rejected: %v", err)
	}
	if device.Status != mesh.StatusPending || device.HeadscaleNodeID != 0 || device.SubscriberID != "" {
		t.Fatalf("unexpected stored device: %+v", device)
	}
	var subscriberColumn *string
	if err = s.db.QueryRow(`SELECT subscriber_id FROM mesh_devices WHERE id=?`, device.ID).Scan(&subscriberColumn); err != nil {
		t.Fatal(err)
	}
	if subscriberColumn != nil {
		t.Fatalf("absent subscriber stored as %q, want NULL", *subscriberColumn)
	}

	// A mesh_only device that names a subscriber is refused by the domain.
	if _, err = s.createMeshDevice(meshSpec("nas2", mesh.PurposeMeshOnly, "ffffffffffffffffffffffffffffffff"), now); err == nil || !hasErrorCode(err, mesh.CodeSubscriberBindingInvalid) {
		t.Fatalf("mesh_only with subscriber accepted: %v", err)
	}
	// proxy_mesh requires an existing subscriber row.
	if _, err = s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, ""), now); err == nil || !hasErrorCode(err, mesh.CodeSubscriberBindingInvalid) {
		t.Fatalf("proxy_mesh without subscriber accepted: %v", err)
	}
	if _, err = s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, "ffffffffffffffffffffffffffffffff"), now); err == nil || !hasErrorCode(err, mesh.CodeSubscriberBindingInvalid) {
		t.Fatalf("proxy_mesh with unknown subscriber accepted: %v", err)
	}

	subscriberID := meshSubscriberFixture(t, s, now)
	bound, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	if bound.SubscriberID != subscriberID {
		t.Fatalf("subscriber binding = %q, want %q", bound.SubscriberID, subscriberID)
	}
}

// TestMeshDeviceNodeNameUniqueWhileOccupied exercises the partial unique index:
// a name is refused only while another device still occupies it, so a revoked
// device releases its name for a fresh attempt.
func TestMeshDeviceNodeNameUniqueWhileOccupied(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.createMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now); err == nil || !hasErrorCode(err, mesh.CodeNodeNameDuplicate) {
		t.Fatalf("duplicate occupied node name accepted: %v", err)
	}
	// Another Headscale user may use the same name: uniqueness is per user.
	other := meshSpec("phone", mesh.PurposeMeshOnly, "")
	other.HeadscaleUser = "second"
	if _, err = s.createMeshDevice(other, now); err != nil {
		t.Fatalf("name of another headscale user rejected: %v", err)
	}

	revoked, outcome, err := s.requestMeshDeviceRevocation(first.ID, "USER_DELETE", now)
	if err != nil || outcome != mesh.RevokeRequested {
		t.Fatalf("revoke: %+v %v %v", revoked, outcome, err)
	}
	if _, err = s.recordMeshObservation(first.ID, 0, now.Add(time.Minute)); err != nil {
		t.Fatalf("confirm removal: %v", err)
	}
	if revoked, err = s.getMeshDevice(first.ID); err != nil || revoked.Status != mesh.StatusRevoked {
		t.Fatalf("device not revoked: %+v err=%v", revoked, err)
	}
	// The terminal device released the name.
	if _, err = s.createMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("name not released after revoke: %v", err)
	}
}

// TestMeshEnrollmentKeySingleActive enforces D1's one-issued-key rule at the
// storage boundary and retires a lapsed key instead of blocking a fresh one.
func TestMeshEnrollmentKeySingleActive(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	device, err := s.createMeshDevice(meshSpec("nas", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	key, secret, err := s.issueMeshEnrollmentKey(device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.ValidateEnrollmentSecret(secret); err != nil {
		t.Fatalf("issued secret is not canonical: %v", err)
	}
	if key.State != mesh.KeyIssued || !key.ExpiresAt.Equal(now.Add(mesh.KeyTTL)) {
		t.Fatalf("key window wrong: %+v", key)
	}
	// The plaintext secret is never persisted: only its digest is.
	var storedHash []byte
	if err = s.db.QueryRow(`SELECT secret_hash FROM mesh_enrollment_keys WHERE id=?`, key.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if string(storedHash) == secret {
		t.Fatal("plaintext secret stored")
	}
	if _, _, err = s.issueMeshEnrollmentKey(device.ID, now.Add(time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeKeyAlreadyActive) {
		t.Fatalf("second issued key accepted: %v", err)
	}
	// The rule is a partial unique index, not only a code path: a direct insert
	// of a second issued row is refused by the database itself.
	if _, err = s.db.Exec(`INSERT INTO mesh_enrollment_keys(id, device_id, secret_hash, state, issued_at, expires_at, consumed_at)
 VALUES('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',?,x'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20','issued',?,?,0)`,
		device.ID, now.Unix(), now.Add(mesh.KeyTTL).Unix()); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Fatalf("single-active index missing: %v", err)
	}

	// The lapsed key is retired, not reused: a new window starts from now.
	later := now.Add(mesh.KeyTTL + time.Minute)
	fresh, freshSecret, err := s.issueMeshEnrollmentKey(device.ID, later)
	if err != nil {
		t.Fatalf("fresh key after lapse rejected: %v", err)
	}
	keys, err := s.listMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("key history = %d rows, want 2", len(keys))
	}
	states := map[string]mesh.KeyState{keys[0].ID: keys[0].State, keys[1].ID: keys[1].State}
	if states[key.ID] != mesh.KeyExpired || states[fresh.ID] != mesh.KeyIssued {
		t.Fatalf("key states = %+v, want the old one expired and the new one issued", states)
	}
	// A lapsed key ended on its own: withdrawing it is not a revocation.
	if _, err = s.revokeMeshEnrollmentKey(key.ID); err == nil || !hasErrorCode(err, mesh.CodeKeyTransitionInvalid) {
		t.Fatalf("expired key revoked: %v", err)
	}

	// Only a pending device may hold a key, and the lapsed secret is spent
	// evidence: it can never register the device.
	if _, err = s.confirmMeshEnrollment(secret, 7, later); err == nil || !hasErrorCode(err, mesh.CodeKeyExpired) {
		t.Fatalf("lapsed secret accepted: %v", err)
	}
	if _, err = s.confirmMeshEnrollment(freshSecret, 7, later); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.issueMeshEnrollmentKey(device.ID, later); err == nil || !hasErrorCode(err, mesh.CodeStatusTransitionInvalid) {
		t.Fatalf("key issued for a registered device: %v", err)
	}
}

// TestMeshEnrollmentConsumeIsTerminal follows one key through D1: the device
// becomes registered, the key is consumed, the digest is cleared and the spent
// secret can never be replayed. The row itself survives for audit and the
// trigger refuses any later state change.
func TestMeshEnrollmentConsumeIsTerminal(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	device, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	key, secret, err := s.issueMeshEnrollmentKey(device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.confirmMeshEnrollment(secret, 42, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if registered.Status != mesh.StatusRegistered || registered.HeadscaleNodeID != 42 {
		t.Fatalf("device not registered: %+v", registered)
	}
	var state string
	var hash []byte
	var consumedAt int64
	if err = s.db.QueryRow(`SELECT state, secret_hash, consumed_at FROM mesh_enrollment_keys WHERE id=?`, key.ID).
		Scan(&state, &hash, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if state != string(mesh.KeyConsumed) || hash != nil || consumedAt != now.Add(time.Minute).Unix() {
		t.Fatalf("consumed row = state %q hash %v consumed_at %d, want consumed/NULL/%d",
			state, hash, consumedAt, now.Add(time.Minute).Unix())
	}

	// The spent secret is rejected exactly like an unknown one.
	if _, err = s.confirmMeshEnrollment(secret, 42, now.Add(2*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeKeySecretInvalid) {
		t.Fatalf("spent secret replayed: %v", err)
	}
	// consumed is terminal at the storage boundary, not only in the domain.
	if _, err = s.db.Exec(`UPDATE mesh_enrollment_keys SET state='issued', secret_hash=x'01' WHERE id=?`, key.ID); err == nil || !strings.Contains(err.Error(), "MESH_ENROLLMENT_KEY_TERMINAL") {
		t.Fatalf("terminal key row was mutable: %v", err)
	}
	// A consumed key stays as the audit row; only the digest is gone, so the
	// spent secret can never match again.
}

// TestMeshRevokeLeavesSubscriberAndCredentialUntouched proves ADR-0004's
// isolation rule: revoking one mesh device never disables the subscriber, its
// VLESS credentials or its subscription token.
func TestMeshRevokeLeavesSubscriberAndCredentialUntouched(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	device, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	var tokenHash []byte
	if err = s.db.QueryRow(`SELECT token_hash FROM subscription_tokens WHERE subscriber_id=? AND revoked=0`, subscriberID).Scan(&tokenHash); err != nil {
		t.Fatal(err)
	}

	// A first intent requests the revocation; a repeat is in-progress and
	// keeps the original reason and timestamp.
	if _, outcome, err := s.requestMeshDeviceRevocation(device.ID, "USER_DELETE", now); err != nil || outcome != mesh.RevokeRequested {
		t.Fatalf("first intent: %v %v", outcome, err)
	}
	repeated, outcome, err := s.requestMeshDeviceRevocation(device.ID, "OTHER_REASON", now.Add(time.Minute))
	if err != nil || outcome != mesh.RevokeInProgress {
		t.Fatalf("repeat intent: %v %v", outcome, err)
	}
	if repeated.RevokeReason != "USER_DELETE" || repeated.RevokeRequestedAt != now.Unix() {
		t.Fatalf("repeat rewrote the audit intent: %+v", repeated)
	}
	// A lowercase reason is refused: it could not be logged as a stable code.
	if _, _, err = s.requestMeshDeviceRevocation(device.ID, "user_delete", now); err == nil || !hasErrorCode(err, mesh.CodeRevokeReasonInvalid) {
		t.Fatalf("lowercase reason accepted: %v", err)
	}

	var subscriberState string
	if err = s.db.QueryRow(`SELECT state FROM subscribers WHERE id=?`, subscriberID).Scan(&subscriberState); err != nil {
		t.Fatal(err)
	}
	if subscriberState != string(subscription.StateActive) {
		t.Fatalf("subscriber state = %q after mesh revoke, want active", subscriberState)
	}
	var credentials int
	if err = s.db.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND active=1`, subscriberID).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if credentials != 1 {
		t.Fatalf("active credentials = %d after mesh revoke, want 1", credentials)
	}
	var stillRevoked int
	var sameHash []byte
	if err = s.db.QueryRow(`SELECT revoked, token_hash FROM subscription_tokens WHERE subscriber_id=?`, subscriberID).Scan(&stillRevoked, &sameHash); err != nil {
		t.Fatal(err)
	}
	if stillRevoked != 0 || string(sameHash) != string(tokenHash) {
		t.Fatalf("subscription token changed by mesh revoke: revoked=%d", stillRevoked)
	}

	// Headscale confirming the removal settles the terminal state.
	settled, err := s.recordMeshObservation(device.ID, 0, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if settled.Status != mesh.StatusRevoked {
		t.Fatalf("status = %s after confirmed removal, want revoked", settled.Status)
	}
	again, outcome, err := s.requestMeshDeviceRevocation(device.ID, "USER_DELETE", now.Add(3*time.Minute))
	if err != nil || outcome != mesh.RevokeAlreadyRevoked || again.Status != mesh.StatusRevoked {
		t.Fatalf("terminal device changed: %+v %v %v", again, outcome, err)
	}
}

// TestMeshObservationRecordsRegistrationAndDisappearance covers the two
// observation edges the store owns: a pending device with an observed node id is
// registered, and a registered device whose node disappeared becomes expired
// while keeping the last observed id for display.
func TestMeshObservationRecordsRegistrationAndDisappearance(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	device, err := s.createMeshDevice(meshSpec("nas", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.recordMeshObservation(device.ID, 11, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if registered.Status != mesh.StatusRegistered || registered.HeadscaleNodeID != 11 || registered.ObservedAt != now.Add(time.Minute).Unix() {
		t.Fatalf("registration not recorded: %+v", registered)
	}
	// A contradicting node id is refused instead of overwriting the reference.
	if _, err = s.recordMeshObservation(device.ID, 12, now.Add(2*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeHeadscaleNodeIDInvalid) {
		t.Fatalf("contradicting node id accepted: %v", err)
	}
	expired, err := s.recordMeshObservation(device.ID, 0, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if expired.Status != mesh.StatusExpired || expired.HeadscaleNodeID != 11 {
		t.Fatalf("disappearance not recorded: %+v", expired)
	}
	// An expired device must re-enroll through pending first: the store never
	// revives it implicitly just because a key was requested.
	if _, _, err = s.issueMeshEnrollmentKey(device.ID, now.Add(4*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeStatusTransitionInvalid) {
		t.Fatalf("expired device accepted an enrollment key without re-enrolling: %v", err)
	}
	// The explicit re-enrollment clears the observed reference and returns the
	// device to pending, which is what "registration not proven yet" means.
	reenrolled, err := s.reenrollMeshDevice(device.ID, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reenrolled.Status != mesh.StatusPending || reenrolled.HeadscaleNodeID != 0 {
		t.Fatalf("re-enrollment wrong: %+v", reenrolled)
	}
	if _, _, err = s.issueMeshEnrollmentKey(device.ID, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("re-enrolled device refused a key: %v", err)
	}
	// Only expired is a legal re-enrollment source.
	if _, err = s.reenrollMeshDevice(device.ID, now.Add(6*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeStatusTransitionInvalid) {
		t.Fatalf("pending device re-enrolled: %v", err)
	}
}

// TestMeshEnrollmentKeyRevokeTerminal checks the revoke path: issued → revoked,
// a repeat is a no-op, and a revoked key can never be spent.
func TestMeshEnrollmentKeyRevokeTerminal(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	device, err := s.createMeshDevice(meshSpec("nas", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	key, secret, err := s.issueMeshEnrollmentKey(device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := s.revokeMeshEnrollmentKey(key.ID)
	if err != nil || revoked.State != mesh.KeyRevoked {
		t.Fatalf("revoke key: %+v %v", revoked, err)
	}
	if again, err := s.revokeMeshEnrollmentKey(key.ID); err != nil || again.State != mesh.KeyRevoked {
		t.Fatalf("repeat revoke: %+v %v", again, err)
	}
	if _, err = s.confirmMeshEnrollment(secret, 5, now.Add(time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeKeyTransitionInvalid) {
		t.Fatalf("revoked key consumed: %v", err)
	}
	if _, err = s.revokeMeshEnrollmentKey("ffffffffffffffffffffffffffffffff"); err == nil || !hasErrorCode(err, codeMeshEnrollmentKeyNotFound) {
		t.Fatalf("unknown key reported as revoked: %v", err)
	}
}

// TestMeshDeviceRenameKeepsIdentity checks that editing the label cannot move a
// device: the id, binding, node name and lifecycle stay as they were, and a
// revoked tombstone refuses the edit.
func TestMeshDeviceRenameKeepsIdentity(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	device, err := s.createMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := s.renameMeshDevice(device.ID, "  Living Room Phone  ", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.DisplayName != "Living Room Phone" || renamed.ID != device.ID ||
		renamed.NodeName != device.NodeName || renamed.SubscriberID != subscriberID ||
		renamed.Status != mesh.StatusPending || renamed.UpdatedAt != now.Add(time.Minute).Unix() {
		t.Fatalf("rename changed more than the label: %+v", renamed)
	}
	// The node name stays occupied, so another device still cannot take it.
	if _, err = s.createMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), now.Add(2*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeNodeNameDuplicate) {
		t.Fatalf("rename released the node name: %v", err)
	}
	if _, err = s.renameMeshDevice(device.ID, "", now); err == nil || !hasErrorCode(err, mesh.CodeDisplayNameInvalid) {
		t.Fatalf("empty label accepted: %v", err)
	}
	if _, _, err = s.requestMeshDeviceRevocation(device.ID, "USER_DELETE", now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.recordMeshObservation(device.ID, 0, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.renameMeshDevice(device.ID, "retired", now.Add(4*time.Minute)); err == nil || !hasErrorCode(err, mesh.CodeStatusTransitionInvalid) {
		t.Fatalf("revoked tombstone renamed: %v", err)
	}
}

// TestMeshMissingDeviceRejected keeps every entry point honest about unknown
// devices instead of creating orphan rows or a generic database failure.
func TestMeshMissingDeviceRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	unknown := "ffffffffffffffffffffffffffffffff"
	if _, err := s.getMeshDevice(unknown); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device read: %v", err)
	}
	if _, _, err := s.issueMeshEnrollmentKey(unknown, now); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device key: %v", err)
	}
	if _, _, err := s.requestMeshDeviceRevocation(unknown, "USER_DELETE", now); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device revoke: %v", err)
	}
	if _, err := s.recordMeshObservation(unknown, 1, now); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device observation: %v", err)
	}
	if _, err := s.renameMeshDevice(unknown, "other", now); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device rename: %v", err)
	}
	if _, err := s.reenrollMeshDevice(unknown, now); err == nil || !hasErrorCode(err, codeMeshDeviceNotFound) {
		t.Fatalf("unknown device reenroll: %v", err)
	}
	devices, err := s.listMeshDevices()
	if err != nil || len(devices) != 0 {
		t.Fatalf("empty store lists %d devices err=%v", len(devices), err)
	}
}
