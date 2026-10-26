package handler

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"strings"
	"testing"
	"time"
)

func TestRoutePolicyRevisionStateMachine(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	_, serverPayload, pins := policyFixtures()
	p, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", serverPayload, pins, "op-create", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReviseRoutePolicy(p.ID, serverPayload, pins, "", now); err == nil || !strings.Contains(err.Error(), "POLICY_OPERATION_REQUIRED") {
		t.Fatalf("anonymous revise accepted: %v", err)
	}
	r2, err := s.ReviseRoutePolicy(p.ID, serverPayload, pins, "op-revise", now.Add(time.Second))
	if err != nil || r2.Revision != 2 || r2.Status != store.PolicyDraft {
		t.Fatalf("revise draft: %+v err=%v", r2, err)
	}
	if old, err := s.GetRoutePolicy(p.ID, 1); err != nil || old.Status != store.PolicySuperseded {
		t.Fatalf("old draft not superseded: %+v err=%v", old, err)
	}
	if _, err = s.ActiveRoutePolicy(store.PolicyLayerServer); err == nil || !strings.Contains(err.Error(), "POLICY_NOT_FOUND") {
		t.Fatalf("draft reported active: %v", err)
	}
	if _, err = s.ActivateRoutePolicy(p.ID, 2, " ", now); err == nil || !strings.Contains(err.Error(), "POLICY_OPERATION_REQUIRED") {
		t.Fatalf("anonymous activate accepted: %v", err)
	}
	active, err := s.ActivateRoutePolicy(p.ID, 2, "op-activate", now.Add(2*time.Second))
	if err != nil || active.Status != store.PolicyActive {
		t.Fatalf("activate: %+v err=%v", active, err)
	}
	r3, err := s.ReviseRoutePolicy(p.ID, serverPayload, pins, "op-revise-active", now.Add(3*time.Second))
	if err != nil || r3.Revision != 3 || r3.Status != store.PolicyActive {
		t.Fatalf("revise active: %+v err=%v", r3, err)
	}
	if active, err = s.ActiveRoutePolicy(store.PolicyLayerServer); err != nil || active.Revision != 3 {
		t.Fatalf("revised active not live: %+v err=%v", active, err)
	}
	if old, err := s.GetRoutePolicy(p.ID, 2); err != nil || old.Status != store.PolicySuperseded {
		t.Fatalf("active predecessor not superseded: %+v err=%v", old, err)
	}
	if _, err = s.RevokeRoutePolicy(p.ID, 3, "", now); err == nil || !strings.Contains(err.Error(), "POLICY_OPERATION_REQUIRED") {
		t.Fatalf("anonymous revoke accepted: %v", err)
	}
	revoked, err := s.RevokeRoutePolicy(p.ID, 3, "op-revoke", now.Add(4*time.Second))
	if err != nil || revoked.Status != store.PolicyRevoked {
		t.Fatalf("revoke: %+v err=%v", revoked, err)
	}
	if _, err = s.ActiveRoutePolicy(store.PolicyLayerServer); err == nil {
		t.Fatal("revoked policy still active")
	}
	if _, err = s.ReviseRoutePolicy(p.ID, serverPayload, pins, "op-too-late", now); err == nil || !strings.Contains(err.Error(), "POLICY_STATE_INVALID") {
		t.Fatalf("revoked chain revived: %v", err)
	}
	server, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端默认策略", serverPayload, pins, "op-server", now)
	if err != nil {
		t.Fatal(err)
	}
	if server, err = s.ActivateRoutePolicy(server.ID, 1, "op-server-active", now); err != nil || server.Status != store.PolicyActive {
		t.Fatalf("server activate: %+v err=%v", server, err)
	}
	other, err := s.CreateRoutePolicy(store.PolicyLayerServer, "服务端备用策略", serverPayload, pins, "op-other", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ActivateRoutePolicy(other.ID, 1, "op-other-active", now); err != nil {
		t.Fatal(err)
	}
	if superseded, err := s.GetRoutePolicy(server.ID, 1); err != nil || superseded.Status != store.PolicySuperseded {
		t.Fatalf("previous layer active not superseded: %+v err=%v", superseded, err)
	}
	rows, err := s.DB.Query(`SELECT kind, operation_id FROM route_policy_events WHERE policy_id=? ORDER BY id`, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := []string{"create", "revise", "activate", "revise", "revoke"}
	index := 0
	for rows.Next() {
		var kind, operationID string
		if err := rows.Scan(&kind, &operationID); err != nil {
			t.Fatal(err)
		}
		if index >= len(want) || kind != want[index] || operationID == "" {
			t.Fatalf("event %d = %q/%q, want %v", index, kind, operationID, want)
		}
		index++
	}
	if index != len(want) {
		t.Fatalf("audit has %d events, want %d", index, len(want))
	}
	for _, statement := range []string{
		`UPDATE route_policy_events SET kind='create' WHERE policy_id=?`,
		`DELETE FROM route_policy_events WHERE policy_id=?`,
	} {
		if _, err := s.DB.Exec(statement, p.ID); err == nil || !strings.Contains(err.Error(), "ROUTE_POLICY_EVENT_IMMUTABLE") {
			t.Fatalf("append-only audit accepted %q: %v", statement, err)
		}
	}
}
