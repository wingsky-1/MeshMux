package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
)

func policyFixtures() (json.RawMessage, json.RawMessage, json.RawMessage) {
	// The client payload is a legacy read fixture: Task 6 closed the client
	// layer to writes, so it is inserted directly where a preview needs one.
	// It deliberately has no exceptions/ssids (both refused since schema 17).
	client := json.RawMessage(`{"default":"proxy","rules":[{"priority":1000,"match":{"ipcidrs":["100.64.0.0/10"]},"action":"tailscale"}]}`)
	server := json.RawMessage(`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"out"}]}`)
	pins := json.RawMessage(`{"geosite":{"ai":{"source":"https://example.invalid/ai.srs","version":"v1","sha256":"` + strings.Repeat("a", 64) + `"}}}`)
	return client, server, pins
}

func TestRoutePolicyCreateReadAndGuards(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	_, serverPayload, pins := policyFixtures()
	p, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", serverPayload, pins, "op-create", now)
	if err != nil || p.Revision != 1 || p.Status != store.PolicyDraft || p.Layer != store.PolicyLayerServer {
		t.Fatalf("create: %+v err=%v", p, err)
	}
	got, err := s.GetRoutePolicy(p.ID, 0)
	if err != nil || got.ID != p.ID || got.Name != p.Name || string(got.Payload) != string(serverPayload) || string(got.Pins) != string(pins) {
		t.Fatalf("get latest: %+v err=%v", got, err)
	}
	if exact, err := s.GetRoutePolicy(p.ID, 1); err != nil || exact.Revision != 1 {
		t.Fatalf("get revision: %+v err=%v", exact, err)
	}
	if _, err = s.ActiveRoutePolicy(store.PolicyLayerServer); err == nil || !strings.Contains(err.Error(), "POLICY_NOT_FOUND") {
		t.Fatalf("draft reported active: %v", err)
	}
	for _, bad := range []struct {
		name, operationID, want string
		payload                 json.RawMessage
	}{
		{"draft", " ", "POLICY_OPERATION_REQUIRED", serverPayload},
		{"my secret key", "op", "POLICY_SECRET_REFUSED", serverPayload},
		{"draft", "op", "POLICY_PAYLOAD_INVALID", json.RawMessage(`{"default":"direct","rules":[],"api_key":"x"}`)},
		{"draft", "op", "POLICY_INVALID", json.RawMessage(`{"default":"bogus","rules":[]}`)},
	} {
		if _, err := s.CreateRoutePolicy(store.PolicyLayerServer, bad.name, bad.payload, pins, bad.operationID, now); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Fatalf("unsafe create %q accepted: %v", bad.name, err)
		}
	}
	var events int
	if err = s.DB.QueryRow(`SELECT count(*) FROM route_policy_events WHERE policy_id=? AND kind='create' AND operation_id=?`, p.ID, "op-create").Scan(&events); err != nil || events != 1 {
		t.Fatalf("create audit: %d err=%v", events, err)
	}
}

// TestClientLayerWritesAreRetired pins the Task 6 one-way door: the client
// layer keeps its rows and reads (legacy preview), but no store write path may
// create, revise, activate or revoke one. The refusal is the store's, not only
// the HTTP handler's, so every internal caller sees the same rule.
func TestClientLayerWritesAreRetired(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	_, serverPayload, pins := policyFixtures()
	_, clientPayload, _ := policyFixtures()
	if _, err := s.CreateRoutePolicy(store.PolicyLayerClient, "客户端默认策略", clientPayload, nil, "op-create", now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePolicyLayerRetired) {
		t.Fatalf("client create = %v, want %s", err, store.CodePolicyLayerRetired)
	}
	server, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", serverPayload, pins, "op-server", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviseRoutePolicy(server.ID, serverPayload, pins, "op-revise", now); err != nil {
		t.Fatalf("server revise must stay writable: %v", err)
	}
	// A legacy client row still reads, but cannot be activated or revoked.
	clientID := seedLegacyClientPolicyStore(t, s, clientPayload, now)
	if _, _, err := s.ActivePolicyIntent(store.PolicyLayerClient); err != nil {
		t.Fatalf("legacy client read: %v", err)
	}
	if _, err := s.ReviseRoutePolicy(clientID, clientPayload, nil, "op-revise-client", now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePolicyLayerRetired) {
		t.Fatalf("client revise = %v, want %s", err, store.CodePolicyLayerRetired)
	}
	if _, err := s.RevokeRoutePolicy(clientID, 1, "op-revoke-client", now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodePolicyLayerRetired) {
		t.Fatalf("client revoke = %v, want %s", err, store.CodePolicyLayerRetired)
	}
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("schema = %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
}

// TestRetiredPolicyFieldsAreRejected proves exceptions/ssids no longer look
// applied: the write fails explicitly, even when the value is empty or null.
func TestRetiredPolicyFieldsAreRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	for _, payload := range []string{
		`{"default":"direct","rules":[],"exceptions":["news.example.invalid"]}`,
		`{"default":"direct","rules":[],"ssids":["home-wifi"]}`,
		`{"default":"direct","rules":[],"exceptions":[]}`,
		`{"default":"direct","rules":[],"ssids":null}`,
	} {
		_, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", json.RawMessage(payload), nil, "op-create", now)
		if err == nil || !strings.HasPrefix(err.Error(), store.CodePolicyPayloadRetired) {
			t.Fatalf("payload %s = %v, want %s", payload, err, store.CodePolicyPayloadRetired)
		}
	}
	if _, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略",
		json.RawMessage(`{"default":"direct","rules":[]}`), nil, "op-clean", now); err != nil {
		t.Fatalf("clean payload refused: %v", err)
	}
}

func TestSchemaV8MigrationReplays(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("schema version %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	_, serverPayload, pins := policyFixtures()
	if _, err := s.CreateRoutePolicy(store.PolicyLayerServer, "迁移前策略", serverPayload, pins, "op-before", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE route_policy_events; DROP TABLE route_policies; PRAGMA user_version=7;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("replay schema 8: %v", err)
	}
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("replayed version %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	var policies int
	if err := s.DB.QueryRow(`SELECT count(*) FROM route_policies`).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("replayed tables not empty: %d err=%v", policies, err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=18`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}
