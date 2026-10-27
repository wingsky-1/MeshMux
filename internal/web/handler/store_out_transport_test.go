package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// configureOut stores the dial address of one Out node for tests. The port
// always matches the node's VLESS port, mirroring the production port-match
// rule, and the server is a documentation address.
func configureOut(t *testing.T, s *store.Store, outID string, now time.Time) store.OutTransport {
	t.Helper()
	node, err := s.GetNodeAt(outID, now)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := s.SetOutTransport(outID, "out.example.invalid", node.VlessPort, now)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

// TestSetOutTransportIssuesAndPreservesCredential pins the Ruling R7
// issuance: the first set mints a Hub-issued SS link key (16 random bytes,
// base64-std, the length the 2022-blake3-aes-128-gcm dial side requires),
// an address update keeps it, and no read path exposes it.
func TestSetOutTransportIssuesAndPreservesCredential(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)

	first, err := s.SetOutTransport(out, "out.example.invalid", 8443, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.OutID != out || first.Server != "out.example.invalid" || first.Port != 8443 || first.UpdatedAt != now.Unix() {
		t.Fatalf("stored transport wrong: %+v", first)
	}

	// The link key must be issued and stay stable across address updates.
	// It lives only in the private table: the test reads it back directly,
	// the same way the candidate builder does.
	var firstKey, secondKey string
	if err := s.DB.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, out).Scan(&firstKey); err != nil {
		t.Fatal(err)
	}
	if err := nodedomain.ValidateOutLinkKey(firstKey); err != nil {
		t.Fatalf("issued link key has the wrong shape: %v", err)
	}

	second, err := s.SetOutTransport(out, "out2.example.invalid", 8443, now)
	if err != nil {
		t.Fatal(err)
	}
	if second.Server != "out2.example.invalid" {
		t.Fatalf("transport update did not store the new address: %+v", second)
	}
	if err := s.DB.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, out).Scan(&secondKey); err != nil {
		t.Fatal(err)
	}
	if secondKey != firstKey {
		t.Fatal("address update rotated the link key: a rename must never invalidate the egress")
	}
	// The void Task-2 UUID column is gone: no row may still carry it.
	var uuidColumn int
	if err := s.DB.QueryRow(`SELECT count(*) FROM pragma_table_info('out_settings') WHERE name='link_uuid'`).Scan(&uuidColumn); err != nil || uuidColumn != 0 {
		t.Fatalf("legacy link_uuid column survived: count=%d err=%v", uuidColumn, err)
	}

	// Role, port-match and shape refusals never create a row.
	if _, err := s.SetOutTransport(line, "out.example.invalid", 8443, now); err == nil || !hasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge transport error = %v, want OUT_ROLE_INVALID", err)
	}
	if _, err := s.SetOutTransport(out, "out.example.invalid", 9999, now); err == nil || !hasErrorCode(err, "OUT_PORT_MISMATCH") {
		t.Fatalf("port mismatch error = %v, want OUT_PORT_MISMATCH", err)
	}
	if _, err := s.SetOutTransport(out, "https://out.example.invalid", 8443, now); err == nil || !hasErrorCode(err, "OUT_TRANSPORT_INVALID") {
		t.Fatalf("bad server error = %v, want OUT_TRANSPORT_INVALID", err)
	}
	if _, err := s.SetOutTransport(strings.Repeat("c", 32), "out.example.invalid", 8443, now); err == nil || !hasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("unknown out error = %v, want OUT_NOT_FOUND", err)
	}
	if _, err := s.SetOutTransport("nope", "out.example.invalid", 8443, now); err == nil || !hasErrorCode(err, "OUT_BINDING_INVALID") {
		t.Fatalf("malformed id error = %v, want OUT_BINDING_INVALID", err)
	}

	// List and get projections never carry the credential.
	transports, err := s.OutPool(time.Now())
	if err != nil || len(transports) != 1 || transports[0].Server != "out2.example.invalid" {
		t.Fatalf("list transports = %v err=%v", transports, err)
	}
	got := transports[0]
	if got.Server != "out2.example.invalid" || got.Port != 8443 {
		t.Fatalf("get transport wrong: %+v", got)
	}
}

// TestOutTransportMigrationVoidsUUIDAndReissuesKey pins the Ruling R7
// migration: a pre-SS database whose out_settings still carries the void
// link_uuid column converges to link_key with a freshly issued key per Out.
// Old UUIDs are void, not carried over; 1.0 is unreleased so no backward
// compat is owed beyond keeping stored candidates verifiable (the node
// package keeps decoding the legacy shape).
func TestOutTransportMigrationVoidsUUIDAndReissuesKey(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-migrated", now)

	// Simulate the pre-SS table shape with one Task-2 UUID row.
	if _, err := s.DB.Exec(`DROP TABLE out_settings`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE out_settings(
	 node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
	 server TEXT NOT NULL, port INTEGER NOT NULL, link_uuid TEXT NOT NULL,
	 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO out_settings VALUES(?,?,?,?,?,?)`,
		out, "out.example.invalid", 8443, "123e4567-e89b-42d3-a456-426614174001", now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	var legacy int
	if err := s.DB.QueryRow(`SELECT count(*) FROM pragma_table_info('out_settings') WHERE name='link_uuid'`).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatalf("legacy link_uuid column survived: count=%d err=%v", legacy, err)
	}
	var key string
	if err := s.DB.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, out).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if err := nodedomain.ValidateOutLinkKey(key); err != nil {
		t.Fatalf("reissued link key has the wrong shape: %v", err)
	}
	if key == "123e4567-e89b-42d3-a456-426614174001" {
		t.Fatal("migration carried the void UUID over as the key")
	}

	// End to end: the migrated key reaches the Out's published candidate, which
	// is the document the Agent renders as the SS guard listener.
	markLineOnline(t, s, out, now)
	configureOut(t, s, out, now)
	latest, err := s.LatestCandidate(out)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Document.Role != nodedomain.RoleOut || latest.Document.Out == nil {
		t.Fatalf("out candidate carries no dial body: %+v", latest.Document)
	}
	if latest.Document.Out.Key != key || latest.Document.Out.Server != "out.example.invalid" ||
		latest.Document.Out.Port != 8443 {
		t.Fatalf("migrated out candidate = %+v, want the reissued key and stored dial address", latest.Document.Out)
	}
}

// TestOutPoolListsTransportAndSelection is the pool datasource: every enrolled Out
// appears with its dial address and the Lines a subscription selects it for, and an
// Out pool of several Outs is allowed (no singleton limit).
//
// The selection is read from the subscription edges, so a pool entry and the ACL
// derivation cannot disagree about which Lines an Out serves.
func TestOutPoolListsTransportAndSelection(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-pool", now)
	outA := pairedStoreNode(t, s, "out", now)
	outB := pairedStoreNode(t, s, "out", now)
	configureOut(t, s, outA, now)
	markLineOnline(t, s, line, now)
	markLineOnline(t, s, outA, now)

	enableOutForLine(t, s, outA, line, now)

	pool, err := s.OutPool(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 2 {
		t.Fatalf("out pool = %d entries, want 2 (the pool is not limited to one Out)", len(pool))
	}
	byID := map[string]store.OutPoolEntry{}
	for _, entry := range pool {
		byID[entry.OutID] = entry
	}
	selected := byID[outA]
	if !selected.TransportConfigured || len(selected.LineIDs) != 1 || selected.LineIDs[0] != line || !selected.Enabled {
		t.Fatalf("selected out entry wrong: %+v", selected)
	}
	if selected.Server != "out.example.invalid" || selected.Port == 0 {
		t.Fatalf("selected out entry has no dial address: %+v", selected)
	}
	unselected := byID[outB]
	if unselected.TransportConfigured || len(unselected.LineIDs) != 0 || unselected.Enabled {
		t.Fatalf("unselected out entry wrong: %+v", unselected)
	}
}

// TestSetOutTransportBeforePairingPublishesTheLinkKeyCandidate pins the Node
// L3 regression: the Web-first order is create the Out, save its dial address,
// then install. SetOutTransport cannot publish while the node is pending, so
// pairing has to commit the v4 link-key candidate before it seeds the initial
// chain. Otherwise the only candidate a fresh install knows about is the
// transport-free baseline, and the Out boots without its SS guard.
func TestSetOutTransportBeforePairingPublishesTheLinkKeyCandidate(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	created, code, err := s.CreateNode("out", "out-pending", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetOutTransport(created.ID, "out.example.invalid", created.VlessPort, now); err != nil {
		t.Fatal(err)
	}
	// The pending host cannot receive a state-changing chain yet: revision 1 is
	// still the frozen baseline the node was created with.
	baseline, err := s.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Document.Out != nil {
		t.Fatalf("a pending out published %s before pairing", baseline.Document.Schema)
	}

	if _, err := s.ConsumePairing(created.ID, "out", code, "meshmux-agent test", "6.1-test", now); err != nil {
		t.Fatal(err)
	}
	var linkKey string
	if err := s.DB.QueryRow(`SELECT link_key FROM out_settings WHERE node_id=?`, created.ID).Scan(&linkKey); err != nil {
		t.Fatal(err)
	}
	latest, err := s.LatestCandidate(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The pairing published a new revision: the baseline is immutable history,
	// not a document anyone may rewrite.
	if latest.Revision != baseline.Revision+1 {
		t.Fatalf("pairing published revision %d, want %d", latest.Revision, baseline.Revision+1)
	}
	if latest.Document.Out == nil || latest.Document.Out.Key != linkKey {
		t.Fatal("Out candidate carries no Hub-issued SS link key")
	}
	// The seeded chain targets that exact revision, so the first apply an
	// installing Agent receives is the v4 guard, not the baseline.
	rows, err := s.DB.Query(`SELECT params FROM agent_tasks WHERE node_id=? ORDER BY revision`, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var targets []int64
	for rows.Next() {
		var params []byte
		if err := rows.Scan(&params); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal(params, &envelope); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, envelope.Revision)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(targets) != len(protocol.PublicationKinds) {
		t.Fatalf("pairing seeded %d tasks, want %d", len(targets), len(protocol.PublicationKinds))
	}
	for _, target := range targets {
		if target != latest.Revision {
			t.Fatalf("pairing seeded candidate revisions %v, want only %d", targets, latest.Revision)
		}
	}
}

// TestOutSelectionRequiresOutTransport closes the endpoint gap: an Out without a
// dial address cannot be selected, because the Line would otherwise render a block
// stub while the Out gate reports healthy. The refusal happens at the subscription
// edge, which is the only authorization source now.
func TestOutSelectionRequiresOutTransport(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-egress", now)
	subscriberID := testSubscriberForLine(t, s, line, now)

	_, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{line}, OutID: out,
	}, now)
	if err == nil || !hasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("select an out without transport = %v, want OUT_NOT_CONFIGURED", err)
	}
	// The refused save wrote nothing: no subscription selects the Out.
	if subscribers, selErr := s.OutAuthorizedSubscribers(out); selErr != nil || len(subscribers) != 0 {
		t.Fatalf("a refused selection was recorded: %v err=%v", subscribers, selErr)
	}
	configureOut(t, s, out, now)
	if _, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{line}, OutID: out,
	}, now); err != nil {
		t.Fatalf("select an out with transport rejected: %v", err)
	}
	preview, err := s.PreviewOutAuthorizationAt(out, line, now)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != store.OutPoolBound && preview.Mode != store.OutPoolLineDirect {
		t.Fatalf("proposal preview after transport = %+v", preview)
	}
}
