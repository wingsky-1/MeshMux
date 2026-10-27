package node_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestSetOutTransportIssuesAndPreservesCredential pins the Ruling R7
// issuance: the first set mints a Hub-issued SS link key (16 random bytes,
// base64-std, the length the 2022-blake3-aes-128-gcm dial side requires),
// an address update keeps it, and no read path exposes it.
func TestSetOutTransportIssuesAndPreservesCredential(t *testing.T) {
	s, now := storetest.SubscriberStore(t)
	out := storetest.PairedStoreNode(t, s, "out", now)
	line := storetest.PairedStoreNode(t, s, "edge", now)

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
	if _, err := s.SetOutTransport(line, "out.example.invalid", 8443, now); err == nil || !storetest.HasErrorCode(err, "OUT_ROLE_INVALID") {
		t.Fatalf("edge transport error = %v, want OUT_ROLE_INVALID", err)
	}
	if _, err := s.SetOutTransport(out, "out.example.invalid", 9999, now); err == nil || !storetest.HasErrorCode(err, "OUT_PORT_MISMATCH") {
		t.Fatalf("port mismatch error = %v, want OUT_PORT_MISMATCH", err)
	}
	if _, err := s.SetOutTransport(out, "https://out.example.invalid", 8443, now); err == nil || !storetest.HasErrorCode(err, "OUT_TRANSPORT_INVALID") {
		t.Fatalf("bad server error = %v, want OUT_TRANSPORT_INVALID", err)
	}
	if _, err := s.SetOutTransport(strings.Repeat("c", 32), "out.example.invalid", 8443, now); err == nil || !storetest.HasErrorCode(err, "OUT_NOT_FOUND") {
		t.Fatalf("unknown out error = %v, want OUT_NOT_FOUND", err)
	}
	if _, err := s.SetOutTransport("nope", "out.example.invalid", 8443, now); err == nil || !storetest.HasErrorCode(err, "OUT_BINDING_INVALID") {
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
	s, now := storetest.SubscriberStore(t)
	out := storetest.PairedStoreNode(t, s, "out", now)
	line := storetest.PairedStoreNode(t, s, "edge", now)
	storetest.ConfigureLine(t, s, line, "line-migrated", now)

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

	// End to end: the migrated key reaches the published Line candidate and
	// renders the SS out body (migration -> store -> kernel bytes).
	storetest.ConfigureOut(t, s, out, now)
	storetest.EnableOutForLine(t, s, out, line, now)
	target, err := s.PublishTarget(line,
		json.RawMessage(`{"rules":[{"domain":["chat.example.invalid"],"outbound":"out"}],"final":"direct"}`),
		true, "healthy", "")
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server,omitempty"`
			ServerPort int    `json:"server_port,omitempty"`
			Method     string `json:"method,omitempty"`
			Password   string `json:"password,omitempty"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(target.Config, &rendered); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range rendered.Outbounds {
		if outbound.Tag != "out" {
			continue
		}
		if outbound.Type != "shadowsocks" || outbound.Method != "2022-blake3-aes-128-gcm" ||
			outbound.Server != "out.example.invalid" || outbound.ServerPort != 8443 || outbound.Password != key {
			t.Fatalf("migrated out body = %+v, want the SS egress with the reissued key", outbound)
		}
		return
	}
	t.Fatal("published Line candidate declares no out outbound")
}

// TestOutPoolListsTransportAndSelection is the pool datasource: every enrolled Out
// appears with its dial address and the Lines a subscription selects it for, and an
// Out pool of several Outs is allowed (no singleton limit).
//
// The selection is read from the subscription edges, so a pool entry and the ACL
// derivation cannot disagree about which Lines an Out serves.
func TestOutPoolListsTransportAndSelection(t *testing.T) {
	s, now := storetest.SubscriberStore(t)
	line := storetest.PairedStoreNode(t, s, "edge", now)
	storetest.ConfigureLine(t, s, line, "line-pool", now)
	outA := storetest.PairedStoreNode(t, s, "out", now)
	outB := storetest.PairedStoreNode(t, s, "out", now)
	storetest.ConfigureOut(t, s, outA, now)
	storetest.MarkLineOnline(t, s, line, now)
	storetest.MarkLineOnline(t, s, outA, now)

	storetest.EnableOutForLine(t, s, outA, line, now)

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

// TestOutSelectionRequiresOutTransport closes the endpoint gap: an Out without a
// dial address cannot be selected, because the Line would otherwise render a block
// stub while the Out gate reports healthy. The refusal happens at the subscription
// edge, which is the only authorization source now.
func TestOutSelectionRequiresOutTransport(t *testing.T) {
	s, now := storetest.SubscriberStore(t)
	out := storetest.PairedStoreNode(t, s, "out", now)
	line := storetest.PairedStoreNode(t, s, "edge", now)
	storetest.ConfigureLine(t, s, line, "line-egress", now)
	subscriberID := storetest.TestSubscriberForLine(t, s, line, now)

	_, err := s.SaveSubscriptionSelection(subscriberID, store.SelectionSpec{
		LineIDs: []string{line}, OutID: out,
	}, now)
	if err == nil || !storetest.HasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("select an out without transport = %v, want OUT_NOT_CONFIGURED", err)
	}
	// The refused save wrote nothing: no subscription selects the Out.
	if subscribers, selErr := s.OutAuthorizedSubscribers(out); selErr != nil || len(subscribers) != 0 {
		t.Fatalf("a refused selection was recorded: %v err=%v", subscribers, selErr)
	}
	storetest.ConfigureOut(t, s, out, now)
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
