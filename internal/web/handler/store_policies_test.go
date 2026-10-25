package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
)

func policyFixtures() (json.RawMessage, json.RawMessage, json.RawMessage) {
	client := json.RawMessage(`{"default":"proxy","rules":[{"priority":1000,"match":{"ipcidrs":["100.64.0.0/10"]},"action":"tailscale"}],"ssids":["home-wifi"]}`)
	server := json.RawMessage(`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"out"}]}`)
	pins := json.RawMessage(`{"geosite":{"ai":{"source":"https://example.invalid/ai.srs","version":"v1","sha256":"` + strings.Repeat("a", 64) + `"}}}`)
	return client, server, pins
}

func TestRoutePolicyCreateReadAndGuards(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	clientPayload, serverPayload, pins := policyFixtures()
	p, err := s.CreateRoutePolicy(store.PolicyLayerClient, "客户端默认策略", clientPayload, nil, "op-create", now)
	if err != nil || p.Revision != 1 || p.Status != store.PolicyDraft || p.Layer != store.PolicyLayerClient {
		t.Fatalf("create: %+v err=%v", p, err)
	}
	got, err := s.GetRoutePolicy(p.ID, 0)
	if err != nil || got.ID != p.ID || got.Name != p.Name || string(got.Payload) != string(clientPayload) || string(got.Pins) != "{}" {
		t.Fatalf("get latest: %+v err=%v", got, err)
	}
	if exact, err := s.GetRoutePolicy(p.ID, 1); err != nil || exact.Revision != 1 {
		t.Fatalf("get revision: %+v err=%v", exact, err)
	}
	if list, err := s.ListRoutePolicies(store.PolicyLayerClient); err != nil || len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("list: %+v err=%v", list, err)
	}
	if _, err = s.ActiveRoutePolicy(store.PolicyLayerClient); err == nil || !strings.Contains(err.Error(), "POLICY_NOT_FOUND") {
		t.Fatalf("draft reported active: %v", err)
	}
	for _, bad := range []struct {
		name, operationID, want string
		payload                 json.RawMessage
	}{
		{"draft", " ", "POLICY_OPERATION_REQUIRED", clientPayload},
		{"my secret key", "op", "POLICY_SECRET_REFUSED", clientPayload},
		{"draft", "op", "POLICY_PAYLOAD_INVALID", json.RawMessage(`{"default":"proxy","rules":[],"api_key":"x"}`)},
		{"draft", "op", "POLICY_INVALID", json.RawMessage(`{"default":"bogus","rules":[]}`)},
	} {
		if _, err := s.CreateRoutePolicy(store.PolicyLayerClient, bad.name, bad.payload, nil, bad.operationID, now); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Fatalf("unsafe create %q accepted: %v", bad.name, err)
		}
	}
	server, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", serverPayload, pins, "op-server", now)
	if err != nil || server.Layer != store.PolicyLayerServer {
		t.Fatalf("server create: %+v err=%v", server, err)
	}
	var events int
	if err = s.DB.QueryRow(`SELECT count(*) FROM route_policy_events WHERE policy_id=? AND kind='create' AND operation_id=?`, p.ID, "op-create").Scan(&events); err != nil || events != 1 {
		t.Fatalf("create audit: %d err=%v", events, err)
	}
}

func TestSchemaV8MigrationReplays(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("schema version %d err=%v, want %d", version, err, store.DatabaseSchemaVersion)
	}
	clientPayload, _, _ := policyFixtures()
	if _, err := s.CreateRoutePolicy(store.PolicyLayerClient, "迁移前策略", clientPayload, nil, "op-before", now); err != nil {
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
	if policies, err := s.ListRoutePolicies(""); err != nil || len(policies) != 0 {
		t.Fatalf("replayed tables not empty: %d err=%v", len(policies), err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=17`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err == nil || !hasErrorCode(err, "SCHEMA_TOO_NEW") {
		t.Fatalf("future schema accepted: %v", err)
	}
}
