package handler

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/mesh"
)

// subnetRouterSpec returns a subnet_router device spec with the given declared
// prefixes. The caller keeps control of the name so two devices can differ.
func subnetRouterSpec(name string, declared ...string) mesh.DeviceSpec {
	return mesh.DeviceSpec{
		DisplayName:    name,
		Purpose:        mesh.PurposeSubnetRouter,
		Platform:       mesh.PlatformNAS,
		NodeName:       strings.ToLower(name),
		DeclaredRoutes: declared,
	}
}

// createSubnetRouter creates one subnet_router device and fails the test when it
// is refused.
func createSubnetRouter(t *testing.T, s *store.Store, name string, declared []string, now time.Time) store.MeshDeviceRecord {
	t.Helper()
	record, err := s.CreateMeshDevice(subnetRouterSpec(name, declared...), now)
	if err != nil {
		t.Fatalf("create subnet router %q: %v", name, err)
	}
	return record
}

// routeEventKinds returns the audit kinds recorded for one prefix, oldest
// first. The table is append-only, so this is the whole history.
func routeEventKinds(t *testing.T, s *store.Store, deviceID, prefix string) []string {
	t.Helper()
	rows, err := s.DB.Query(`SELECT kind FROM mesh_route_events WHERE device_id=? AND prefix=? ORDER BY id`, deviceID, prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			t.Fatal(err)
		}
		out = append(out, kind)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSchemaV7MigrationAddsRouteTablesAndPreservesV6 upgrades a schema-6
// database and checks that the route tables appear, the pre-existing device and
// key rows survive and the future-schema guard moved to 9. The migration must
// stay additive: dropping the two new tables returns the file to the schema-6
// shape.
func TestSchemaV7MigrationAddsRouteTablesAndPreservesV6(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	device, err := s.CreateMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.IssueMeshEnrollmentKey(device.ID, now); err != nil {
		t.Fatal(err)
	}

	// Rebuild the database in its schema-6 shape: the route tables do not exist
	// and the version is 6. The device and key rows stay exactly as they were.
	if _, err = s.DB.Exec(`DROP TABLE route_policy_events; DROP TABLE route_policies; DROP TABLE mesh_route_events; DROP TABLE mesh_routes; PRAGMA user_version=6;`); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 6 {
		t.Fatalf("user_version=%d err=%v, want 6", version, err)
	}
	if err = s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 10 {
		t.Fatalf("user_version=%d err=%v, want 10", version, err)
	}
	for _, table := range []string{"mesh_routes", "mesh_route_events"} {
		var count int
		if err = s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s table missing: %d err=%v", table, count, err)
		}
	}

	// The schema-6 rows and every schema-6 capability survive the upgrade.
	if _, err = s.GetSubscriber(subscriberID); err != nil {
		t.Fatalf("subscriber lost by migration: %v", err)
	}
	if stored, err := s.GetMeshDevice(device.ID); err != nil || stored.Status != mesh.StatusPending {
		t.Fatalf("mesh device lost by migration: %+v err=%v", stored, err)
	}
	if keys, err := s.ListMeshEnrollmentKeys(device.ID); err != nil || len(keys) != 1 {
		t.Fatalf("enrollment key lost by migration: %d err=%v", len(keys), err)
	}
	// A route can be declared after the upgrade.
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	if routes, err := s.ListMeshRoutes(router.ID); err != nil || len(routes) != 1 {
		t.Fatalf("route declaration after migration: %d err=%v", len(routes), err)
	}

	// The guard moved with the migration.
	if _, err = s.DB.Exec(`PRAGMA user_version=11`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}

// TestSchemaV7MigrationRollsBackWithoutDestroyingV6 proves the upgrade is one
// transaction: when the route tables cannot be created, the database stays at
// version 6 and every schema-6 table and row is still there.
func TestSchemaV7MigrationRollsBackWithoutDestroyingV6(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	device, err := s.CreateMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = s.DB.Exec(`DROP TABLE mesh_route_events; DROP TABLE mesh_routes; PRAGMA user_version=6;`); err != nil {
		t.Fatal(err)
	}
	// A leftover table collides with the new schema, so migrateSchema7 must fail
	// after dropping nothing.
	if _, err = s.DB.Exec(`CREATE TABLE mesh_routes (stale TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(); err == nil || !hasErrorCode(err, "SCHEMA_MIGRATION_FAILED") {
		t.Fatalf("colliding migration reported as success: %v", err)
	}
	var version int
	if err = s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 6 {
		t.Fatalf("user_version=%d err=%v after failed migration, want 6", version, err)
	}
	var events int
	if err = s.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mesh_route_events'`).Scan(&events); err != nil || events != 0 {
		t.Fatalf("partial event table survived: %d err=%v", events, err)
	}
	if _, err = s.GetMeshDevice(device.ID); err != nil {
		t.Fatalf("mesh device lost by failed migration: %v", err)
	}
	if _, err = s.GetSubscriber(subscriberID); err != nil {
		t.Fatalf("subscriber lost by failed migration: %v", err)
	}
}

// TestMeshRouteDeclarationIsAdditiveAndIdempotent covers the declaration path:
// one canonical row per prefix, source=device when pre-declared, and a repeat
// that changes nothing and appends no second event.
func TestMeshRouteDeclarationIsAdditiveAndIdempotent(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{" 192.168.1.0/24 ", "10.0.0.0/8", "192.168.1.0/24"}, now)

	routes, err := s.ListMeshRoutes(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("pre-declared routes = %d, want the deduplicated two", len(routes))
	}
	for _, route := range routes {
		if route.Desired != mesh.RouteDesiredAdvertised {
			t.Fatalf("%s desired = %q, want advertised", route.Prefix, route.Desired)
		}
		if route.Observed != mesh.RouteObservedNone {
			t.Fatalf("%s observed = %q, want empty", route.Prefix, route.Observed)
		}
		if route.Source != mesh.RouteSourceDevice {
			t.Fatalf("%s source = %q, want device", route.Prefix, route.Source)
		}
	}
	if got := routeEventKinds(t, s, router.ID, "192.168.1.0/24"); len(got) != 1 || got[0] != store.RouteEventDeclared {
		t.Fatalf("pre-declaration events = %v, want one DECLARED", got)
	}

	// A later declaration of the same prefix is idempotent: the row keeps its
	// source and no second DECLARED event is appended.
	again, err := s.UpsertMeshRoute(router.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-repeat", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if again.Source != mesh.RouteSourceDevice || again.Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("repeat declaration rewrote the row: %+v", again)
	}
	if got := routeEventKinds(t, s, router.ID, "192.168.1.0/24"); len(got) != 1 {
		t.Fatalf("repeat declaration appended an event: %v", got)
	}
	// The canonical spelling is stored, and a second spelling of the same
	// network resolves to the same row.
	stored, err := s.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil || stored.Prefix != "192.168.1.0/24" {
		t.Fatalf("stored prefix = %+v err=%v", stored, err)
	}
	if _, err = s.UpsertMeshRoute(router.ID, " 192.168.001.0/24 ", mesh.RouteSourceOperator, "op-other", now); err == nil {
		t.Fatal("a non-canonical spelling was accepted")
	}
}

// TestMeshRouteRejectsUnroutableDeclarations proves the domain admission rule
// reaches the storage boundary: an exit route, the tailnet range and a prefix
// with host bits are refused before a row exists.
func TestMeshRouteRejectsUnroutableDeclarations(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", nil, now)
	for _, raw := range []string{"0.0.0.0/0", "::/0", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "192.168.1.5/24", "127.0.0.0/8"} {
		if _, err := s.UpsertMeshRoute(router.ID, raw, mesh.RouteSourceOperator, "op", now); err == nil {
			t.Fatalf("%q accepted as a subnet route", raw)
		}
	}
	if routes, err := s.ListMeshRoutes(router.ID); err != nil || len(routes) != 0 {
		t.Fatalf("refused declarations left %d rows err=%v", len(routes), err)
	}
	// A pre-declared exit route refuses the whole device creation, so a device
	// never exists with a half-written declaration.
	if _, err := s.CreateMeshDevice(subnetRouterSpec("bad-nas", "192.168.1.0/24", "0.0.0.0/0"), now); err == nil {
		t.Fatal("device created with an exit route")
	}
	var devices int
	if err := s.DB.QueryRow(`SELECT count(*) FROM mesh_devices WHERE node_name='bad-nas'`).Scan(&devices); err != nil || devices != 0 {
		t.Fatalf("refused creation left %d devices err=%v", devices, err)
	}
	var routes int
	if err := s.DB.QueryRow(`SELECT count(*) FROM mesh_routes`).Scan(&routes); err != nil || routes != 0 {
		t.Fatalf("refused creation left %d routes err=%v", routes, err)
	}
}

// TestMeshRoutePrefixConflictAcrossDevices keeps one prefix with one device: a
// second device cannot claim it, and a withdrawn prefix becomes available again.
func TestMeshRoutePrefixConflictAcrossDevices(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first := createSubnetRouter(t, s, "nas-a", []string{"192.168.1.0/24"}, now)
	second := createSubnetRouter(t, s, "nas-b", nil, now)

	if _, err := s.UpsertMeshRoute(second.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op", now); err == nil || !hasErrorCode(err, store.CodeMeshRouteConflict) {
		t.Fatalf("cross-device duplicate accepted: %v", err)
	}
	// The partial unique index is the real guard, not only the pre-check.
	if _, err := s.DB.Exec(`INSERT INTO mesh_routes(device_id, prefix, desired, observed, source, operation_id, created_at, updated_at)
 VALUES(?,?,'advertised','','operator','',?,?)`, second.ID, "192.168.1.0/24", now.Unix(), now.Unix()); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Fatalf("active-prefix index missing: %v", err)
	}
	// A pre-declaration collision refuses the whole second device creation.
	if _, err := s.CreateMeshDevice(subnetRouterSpec("nas-c", "192.168.1.0/24"), now); err == nil || !hasErrorCode(err, store.CodeMeshRouteConflict) {
		t.Fatalf("pre-declaration collision accepted: %v", err)
	}
	// Withdrawing the prefix frees it for another device.
	if _, err := s.SetMeshRouteDesired(first.ID, "192.168.1.0/24", mesh.RouteDesiredRevoked, "op-revoke", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertMeshRoute(second.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-take", now); err != nil {
		t.Fatalf("withdrawn prefix not reusable: %v", err)
	}
}

// TestMeshRouteDesiredNeedsAuditKey proves the trigger, not only the store, is
// the last line of defence: no desired change and no revival happens without an
// audit key, and a revoked row cannot come back with the same key.
func TestMeshRouteDesiredNeedsAuditKey(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)

	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "", now); err == nil || !hasErrorCode(err, mesh.CodeRouteTransitionInvalid) {
		t.Fatalf("approval without an audit key accepted: %v", err)
	}
	// The database refuses the same change even when the store check is bypassed.
	if _, err := s.DB.Exec(`UPDATE mesh_routes SET desired='approved' WHERE device_id=?`, router.ID); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_TRANSITION_UNAUDITED") {
		t.Fatalf("trigger allowed an unaudited desired change: %v", err)
	}
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-approve", now); err != nil {
		t.Fatal(err)
	}
	// A repeated approval is idempotent: no second event, no rewritten key.
	repeated, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-approve-again", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if repeated.OperationID != "op-approve" {
		t.Fatalf("repeated approval rewrote the audit key: %+v", repeated)
	}
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredRevoked, "op-revoke", now); err != nil {
		t.Fatal(err)
	}
	// A revoked row is terminal for the desired-state path; it is revived only by
	// declaring it again, which is a new audited act.
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredAdvertised, "op-revive", now); err == nil || !hasErrorCode(err, mesh.CodeRouteTransitionInvalid) {
		t.Fatalf("revoked route revived through setMeshRouteDesired: %v", err)
	}
	// A revival with the same audit key as the revocation is refused, so a
	// withdrawn prefix cannot be flipped back under one operation id.
	if _, err := s.UpsertMeshRoute(router.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-revoke", now); err == nil || !hasErrorCode(err, mesh.CodeRouteTransitionInvalid) {
		t.Fatalf("revival reused the revocation audit key: %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE mesh_routes SET desired='advertised', operation_id='op-revoke' WHERE device_id=?`, router.ID); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_REVIVAL_UNTRACKED") {
		t.Fatalf("trigger allowed a revival with the old audit key: %v", err)
	}
	// A fresh key alone is not enough: the revival must be backed by the DECLARED
	// audit event that names that key, so a bare SQL update cannot resurrect a
	// withdrawn prefix.
	if _, err := s.DB.Exec(`UPDATE mesh_routes SET desired='advertised', operation_id='op-untracked-revive' WHERE device_id=?`, router.ID); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_REVIVAL_UNTRACKED") {
		t.Fatalf("trigger allowed an unaudited revival with a fresh key: %v", err)
	}
	// The store's own revival path works and records the new declaration.
	revived, err := s.UpsertMeshRoute(router.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-revive", now)
	if err != nil {
		t.Fatalf("audited revival refused: %v", err)
	}
	if revived.Desired != mesh.RouteDesiredAdvertised || revived.OperationID != "op-revive" {
		t.Fatalf("revived route = %+v", revived)
	}
	// A route is never born revoked, and a direct insert cannot fake it.
	if _, err := s.DB.Exec(`INSERT INTO mesh_routes(device_id, prefix, desired, observed, source, operation_id, created_at, updated_at)
 VALUES(?,?,'revoked','','operator','op',?,?)`, router.ID, "10.9.0.0/16", now.Unix(), now.Unix()); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_TRANSITION_UNAUDITED") {
		t.Fatalf("route born revoked accepted: %v", err)
	}
	if got := routeEventKinds(t, s, router.ID, "192.168.1.0/24"); strings.Join(got, ",") !=
		strings.Join([]string{store.RouteEventDeclared, store.RouteEventApproved, store.RouteEventRevoked, store.RouteEventDeclared}, ",") {
		t.Fatalf("route history = %v", got)
	}
}

// TestMeshRouteEventsAreAppendOnly proves the audit trail cannot be rewritten:
// an UPDATE or DELETE of a recorded event is refused by the database itself.
func TestMeshRouteEventsAreAppendOnly(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	if _, err := s.DB.Exec(`UPDATE mesh_route_events SET kind='MESH_ROUTE_APPROVED' WHERE device_id=?`, router.ID); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_EVENT_IMMUTABLE") {
		t.Fatalf("audit event updated: %v", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM mesh_route_events WHERE device_id=?`, router.ID); err == nil || !strings.Contains(err.Error(), "MESH_ROUTE_EVENT_IMMUTABLE") {
		t.Fatalf("audit event deleted: %v", err)
	}
}

// TestMeshRouteObservationNeverApproves keeps intent and evidence apart: an
// observation stores what Headscale reported, appends one event per change, and
// never approves a prefix.
func TestMeshRouteObservationNeverApproves(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)

	observed, declared, err := s.RecordMeshRouteObservation(router.ID, "192.168.1.0/24", mesh.RouteObservedAdvertised, "op-observe", now)
	if err != nil || !declared {
		t.Fatalf("observation of a declared prefix: %+v %v %v", observed, declared, err)
	}
	if observed.Desired != mesh.RouteDesiredAdvertised || observed.Observed != mesh.RouteObservedAdvertised {
		t.Fatalf("observation rewrote the row: %+v", observed)
	}
	// A repeated identical read appends no event.
	if _, _, err = s.RecordMeshRouteObservation(router.ID, "192.168.1.0/24", mesh.RouteObservedAdvertised, "op-observe", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := routeEventKinds(t, s, router.ID, "192.168.1.0/24"); len(got) != 2 {
		t.Fatalf("repeated observation appended events: %v", got)
	}

	// A prefix Headscale reports but no device declared is only an audit event:
	// no row is created, so nothing can be approved by accident.
	record, declared, err := s.RecordMeshRouteObservation(router.ID, "10.5.0.0/16", mesh.RouteObservedAdvertised, "op-untracked", now)
	if err != nil || declared {
		t.Fatalf("untracked observation: %+v %v %v", record, declared, err)
	}
	var rows int
	if err := s.DB.QueryRow(`SELECT count(*) FROM mesh_routes WHERE prefix='10.5.0.0/16'`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("untracked prefix became a route row: %d err=%v", rows, err)
	}
	got := routeEventKinds(t, s, router.ID, "10.5.0.0/16")
	if len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
		t.Fatalf("untracked events = %v", got)
	}
	// Even an exit route is reportable as an untracked advertisement: refusing
	// to record it would hide the very advertisement an operator must see.
	if _, declared, err = s.RecordMeshRouteObservation(router.ID, "0.0.0.0/0", mesh.RouteObservedAdvertised, "op-exit", now); err != nil || declared {
		t.Fatalf("exit advertisement not recorded as untracked: %v %v", declared, err)
	}
	if got = routeEventKinds(t, s, router.ID, "0.0.0.0/0"); len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
		t.Fatalf("exit advertisement events = %v", got)
	}
	if routes, err := s.ListMeshRoutes(router.ID); err != nil || len(routes) != 1 {
		t.Fatalf("untracked advertisements created rows: %d err=%v", len(routes), err)
	}
}

// TestMeshRouteObservedEmptyDoesNotRevertDesired is the "served 空不回退 desired"
// rule: losing the evidence leaves the approved intent in place, so a transient
// Headscale read cannot silently un-approve a working LAN.
func TestMeshRouteObservedEmptyDoesNotRevertDesired(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-approve", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordMeshRouteObservation(router.ID, "192.168.1.0/24", mesh.RouteObservedServed, "op-served", now); err != nil {
		t.Fatal(err)
	}
	cleared, declared, err := s.RecordMeshRouteObservation(router.ID, "192.168.1.0/24", mesh.RouteObservedNone, "op-cleared", now.Add(time.Minute))
	if err != nil || !declared {
		t.Fatalf("clearing the observation: %+v %v %v", cleared, declared, err)
	}
	if cleared.Observed != mesh.RouteObservedNone {
		t.Fatalf("observed = %q, want empty", cleared.Observed)
	}
	if cleared.Desired != mesh.RouteDesiredApproved {
		t.Fatalf("desired reverted to %q by an observation, want approved", cleared.Desired)
	}
	if got := routeEventKinds(t, s, router.ID, "192.168.1.0/24"); len(got) != 4 {
		t.Fatalf("observation history = %v", got)
	}
	// A pending-approval queue never contains the approved route.
	pending, err := s.ListMeshRoutesPending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("approved route still pending: %d err=%v", len(pending), err)
	}
}

// TestMeshRoutePendingListsOnlyAwaitingApproval checks the read model of the
// approval queue: advertised routes only, across devices, with the canonical
// prefix order.
func TestMeshRoutePendingListsOnlyAwaitingApproval(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first := createSubnetRouter(t, s, "nas-a", []string{"192.168.2.0/24", "10.0.0.0/8"}, now)
	second := createSubnetRouter(t, s, "nas-b", []string{"192.168.3.0/24"}, now)
	if _, err := s.SetMeshRouteDesired(second.ID, "192.168.3.0/24", mesh.RouteDesiredApproved, "op", now); err != nil {
		t.Fatal(err)
	}
	pending, err := s.ListMeshRoutesPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	for _, route := range pending {
		if route.DeviceID != first.ID {
			t.Fatalf("pending route of an approved device: %+v", route)
		}
	}
	if pending[0].Prefix != "10.0.0.0/8" || pending[1].Prefix != "192.168.2.0/24" {
		t.Fatalf("pending order = %q, %q", pending[0].Prefix, pending[1].Prefix)
	}
	// An unknown but well-formed device lists no routes; a malformed id is still
	// refused, so a caller cannot silently list the wrong device.
	if routes, err := s.ListMeshRoutes("ffffffffffffffffffffffffffffffff"); err != nil || len(routes) != 0 {
		t.Fatalf("unknown device listed %d routes err=%v", len(routes), err)
	}
	if _, err = s.ListMeshRoutes("bad-id"); err == nil || !hasErrorCode(err, mesh.CodeDeviceIDInvalid) {
		t.Fatalf("malformed device id accepted: %v", err)
	}
}

// TestMeshRouteDeviceRevocationSettlesEveryRoute proves the device and its
// routes settle in one transaction, and that the subscriber, credential and
// token of a bound subscriber stay untouched.
func TestMeshRouteDeviceRevocationSettlesEveryRoute(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	spec := subnetRouterSpec("nas", "192.168.1.0/24", "10.0.0.0/8")
	spec.SubscriberID = subscriberID
	router, err := s.CreateMeshDevice(spec, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetMeshRouteDesired(router.ID, "10.0.0.0/8", mesh.RouteDesiredApproved, "op-approve", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.RecordMeshRouteObservation(router.ID, "10.0.0.0/8", mesh.RouteObservedServed, "op-served", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.RequestMeshDeviceRevocation(router.ID, "USER_DELETE", now); err != nil {
		t.Fatal(err)
	}
	routes, err := s.ListMeshRoutes(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes after revocation = %d, want 2 history rows", len(routes))
	}
	for _, route := range routes {
		if route.Desired != mesh.RouteDesiredRevoked {
			t.Fatalf("%s desired = %q after device revocation, want revoked", route.Prefix, route.Desired)
		}
	}
	// The prefix is free again because the device no longer holds it.
	if _, err = s.UpsertMeshRoute(router.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-late", now); err == nil || !hasErrorCode(err, mesh.CodeRouteTransitionInvalid) {
		t.Fatalf("revoked device declared a prefix: %v", err)
	}
	other := createSubnetRouter(t, s, "nas-b", nil, now)
	if _, err = s.UpsertMeshRoute(other.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-take", now); err != nil {
		t.Fatalf("prefix not released by device revocation: %v", err)
	}

	// The subscriber, its credential and its token are untouched.
	var state string
	if err = s.DB.QueryRow(`SELECT state FROM subscribers WHERE id=?`, subscriberID).Scan(&state); err != nil || state != "active" {
		t.Fatalf("subscriber state = %q err=%v after mesh revocation", state, err)
	}
	var credentials int
	if err = s.DB.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND active=1`, subscriberID).Scan(&credentials); err != nil || credentials != 1 {
		t.Fatalf("active credentials = %d err=%v after mesh revocation", credentials, err)
	}
	var tokens int
	if err = s.DB.QueryRow(`SELECT count(*) FROM subscription_tokens WHERE subscriber_id=? AND revoked=0`, subscriberID).Scan(&tokens); err != nil || tokens != 1 {
		t.Fatalf("live tokens = %d err=%v after mesh revocation", tokens, err)
	}
}

// TestMeshRouteOnlySubnetRouterDeclares keeps the purpose rule at the storage
// boundary: a proxy_mesh or mesh_only device is not the router of a LAN, and a
// revoked device is a tombstone.
func TestMeshRouteOnlySubnetRouterDeclares(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	subscriberID := meshSubscriberFixture(t, s, now)
	proxy, err := s.CreateMeshDevice(meshSpec("phone", mesh.PurposeProxyMesh, subscriberID), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertMeshRoute(proxy.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op", now); err == nil || !hasErrorCode(err, mesh.CodeRouteDeclarationInvalid) {
		t.Fatalf("proxy_mesh declared a subnet route: %v", err)
	}
	meshOnly, err := s.CreateMeshDevice(meshSpec("tablet", mesh.PurposeMeshOnly, ""), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpsertMeshRoute(meshOnly.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op", now); err == nil || !hasErrorCode(err, mesh.CodeRouteDeclarationInvalid) {
		t.Fatalf("mesh_only declared a subnet route: %v", err)
	}
	// The pre-declaration form is refused before the device row exists.
	if _, err = s.CreateMeshDevice(meshSpec("tablet2", mesh.PurposeMeshOnly, ""), now); err != nil {
		t.Fatal(err)
	}
	spec := subnetRouterSpec("nas", "192.168.1.0/24")
	spec.Purpose = mesh.PurposeMeshOnly
	if _, err = s.CreateMeshDevice(spec, now); err == nil || !hasErrorCode(err, mesh.CodeRouteDeclarationInvalid) {
		t.Fatalf("mesh_only pre-declared a route: %v", err)
	}
	// An unknown device is reported as missing, not as a purpose failure.
	if _, err = s.UpsertMeshRoute("ffffffffffffffffffffffffffffffff", "192.168.1.0/24", mesh.RouteSourceOperator, "op", now); err == nil || !hasErrorCode(err, store.CodeMeshDeviceNotFound) {
		t.Fatalf("unknown device declared a route: %v", err)
	}
}

// TestMeshRouteMissingRowRejected keeps every read and transition honest about
// a prefix the device never declared.
func TestMeshRouteMissingRowRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", nil, now)
	if _, err := s.GetMeshRoute(router.ID, "192.168.1.0/24"); err == nil || !hasErrorCode(err, store.CodeMeshRouteNotFound) {
		t.Fatalf("unknown route read: %v", err)
	}
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op", now); err == nil || !hasErrorCode(err, store.CodeMeshRouteNotFound) {
		t.Fatalf("unknown route approved: %v", err)
	}
	if routes, err := s.ListMeshRoutes(router.ID); err != nil || len(routes) != 0 {
		t.Fatalf("empty device lists %d routes err=%v", len(routes), err)
	}
	if pending, err := s.ListMeshRoutesPending(); err != nil || len(pending) != 0 {
		t.Fatalf("empty store lists %d pending routes err=%v", len(pending), err)
	}
}

// TestMeshRouteCorruptRowRejected proves a hand-edited row is reported instead
// of being rendered as a valid declaration.
func TestMeshRouteCorruptRowRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	// The CHECK constraint refuses an undefined desired value outright, so the
	// corrupt-row path is exercised through a non-canonical prefix, which the
	// domain refuses on read.
	if _, err := s.DB.Exec(`UPDATE mesh_routes SET prefix='192.168.001.0/24' WHERE device_id=?`, router.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMeshRoute(router.ID, "192.168.001.0/24"); err == nil || !hasErrorCode(err, store.CodeMeshRouteCorrupt) {
		t.Fatalf("non-canonical stored prefix rendered: %v", err)
	}
	if _, err := s.ListMeshRoutes(router.ID); err == nil || !hasErrorCode(err, store.CodeMeshRouteCorrupt) {
		t.Fatalf("corrupt row listed: %v", err)
	}
}

// TestMeshRouteUntrackedObservationIsIdempotent keeps the audit trail a record
// of changes: polling the same untracked advertisement appends one event, and a
// different observation appends a second.
func TestMeshRouteUntrackedObservationIsIdempotent(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", nil, now)
	for i := 0; i < 3; i++ {
		if _, declared, err := s.RecordMeshRouteObservation(router.ID, "10.5.0.0/16", mesh.RouteObservedAdvertised, "op", now.Add(time.Duration(i)*time.Minute)); err != nil || declared {
			t.Fatalf("untracked observation %d: %v %v", i, declared, err)
		}
	}
	if got := routeEventKinds(t, s, router.ID, "10.5.0.0/16"); len(got) != 1 {
		t.Fatalf("repeated untracked observation appended events: %v", got)
	}
	if _, _, err := s.RecordMeshRouteObservation(router.ID, "10.5.0.0/16", mesh.RouteObservedServed, "op", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := routeEventKinds(t, s, router.ID, "10.5.0.0/16"); len(got) != 2 {
		t.Fatalf("changed untracked observation not recorded: %v", got)
	}
	// The row keeps the latest audit key of the intent change.
	if _, err := s.UpsertMeshRoute(router.ID, "192.168.1.0/24", mesh.RouteSourceOperator, "op-declare", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-approve", now); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetMeshRoute(router.ID, "192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if stored.OperationID != "op-approve" {
		t.Fatalf("audit key = %q, want the latest transition key", stored.OperationID)
	}
}

// TestMeshRouteReenrollmentKeepsRoutesRevoked proves a re-enrolled device does
// not silently regain its old prefixes: re-declaring them is a new, audited act.
func TestMeshRouteReenrollmentKeepsRoutesRevoked(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	if _, err := s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredApproved, "op-approve", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordMeshObservation(router.ID, 7, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordMeshObservation(router.ID, 0, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Re-enrollment and the key swap are one write, so the route assertions run
	// against the state that produced the usable key, not an empty intermediate.
	key, _, err := mesh.NewEnrollmentKey(router.ID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyMeshRekey(router.ID, key, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	routes, err := s.ListMeshRoutes(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Desired != mesh.RouteDesiredApproved {
		t.Fatalf("re-enrollment changed the route intent: %+v", routes)
	}
	// An explicit revocation survives re-enrollment too.
	if _, err = s.SetMeshRouteDesired(router.ID, "192.168.1.0/24", mesh.RouteDesiredRevoked, "op-revoke", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if routes, err = s.ListMeshRoutes(router.ID); err != nil || len(routes) != 1 || routes[0].Desired != mesh.RouteDesiredRevoked {
		t.Fatalf("route revocation lost: %+v err=%v", routes, err)
	}
}

// TestReconcileMeshRoutesNeverApprovesUntracked is the ADR-0004 admission rule
// over one read: declared prefixes get their evidence recorded, an advertised
// prefix nobody declared becomes a MESH_ROUTE_UNTRACKED event only, and no
// prefix is ever approved by the pass.
func TestReconcileMeshRoutesNeverApprovesUntracked(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	router := createSubnetRouter(t, s, "nas", []string{"192.168.1.0/24"}, now)
	result, err := s.ReconcileMeshRoutes(router.ID, []store.MeshRouteObservation{
		{Prefix: "192.168.1.0/24", Observed: mesh.RouteObservedAdvertised},
		{Prefix: "10.5.0.0/16", Observed: mesh.RouteObservedAdvertised},
		{Prefix: "0.0.0.0/0", Observed: mesh.RouteObservedAdvertised},
	}, "op-reconcile", now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Tracked != 1 || result.Untracked != 2 || result.Changed != 1 {
		t.Fatalf("reconcile result = %+v", result)
	}
	routes, err := s.ListMeshRoutes(router.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Prefix != "192.168.1.0/24" {
		t.Fatalf("reconcile created route rows: %+v", routes)
	}
	if routes[0].Desired != mesh.RouteDesiredAdvertised {
		t.Fatalf("reconcile approved a prefix: %+v", routes[0])
	}
	if got := routeEventKinds(t, s, router.ID, "10.5.0.0/16"); len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
		t.Fatalf("untracked advertisement events = %v", got)
	}
	if got := routeEventKinds(t, s, router.ID, "0.0.0.0/0"); len(got) != 1 || got[0] != store.CodeMeshRouteUntracked {
		t.Fatalf("exit advertisement events = %v", got)
	}
	// A second identical pass changes nothing.
	again, err := s.ReconcileMeshRoutes(router.ID, []store.MeshRouteObservation{
		{Prefix: "192.168.1.0/24", Observed: mesh.RouteObservedAdvertised},
		{Prefix: "10.5.0.0/16", Observed: mesh.RouteObservedAdvertised},
	}, "op-reconcile", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed != 0 || again.Untracked != 1 {
		t.Fatalf("repeated reconcile result = %+v", again)
	}
	if _, err = s.ReconcileMeshRoutes("ffffffffffffffffffffffffffffffff", nil, "op", now); err == nil || !hasErrorCode(err, store.CodeMeshDeviceNotFound) {
		t.Fatalf("unknown device reconciled: %v", err)
	}
}
