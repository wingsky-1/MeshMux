package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/store"
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

// TestSetOutTransportIssuesAndPreservesCredential pins the Task 2 issuance:
// the first set mints a Hub-issued link UUID, an address update keeps it, and
// no read path exposes it.
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

	// The credential must be issued and stay stable across address updates.
	// It lives only in the private table: the test reads it back directly,
	// the same way the candidate builder does.
	var firstUUID, secondUUID string
	if err := s.DB.QueryRow(`SELECT link_uuid FROM out_settings WHERE node_id=?`, out).Scan(&firstUUID); err != nil {
		t.Fatal(err)
	}
	if err := subscription.ValidateUUID(firstUUID); err != nil {
		t.Fatalf("issued link credential is not a Hub-issued UUIDv4: %v", err)
	}

	second, err := s.SetOutTransport(out, "out2.example.invalid", 8443, now)
	if err != nil {
		t.Fatal(err)
	}
	if second.Server != "out2.example.invalid" {
		t.Fatalf("transport update did not store the new address: %+v", second)
	}
	if err := s.DB.QueryRow(`SELECT link_uuid FROM out_settings WHERE node_id=?`, out).Scan(&secondUUID); err != nil {
		t.Fatal(err)
	}
	if secondUUID != firstUUID {
		t.Fatal("address update rotated the link credential: a rename must never invalidate the egress")
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
	transports, err := s.ListOutTransports()
	if err != nil || len(transports) != 1 || transports[0].Server != "out2.example.invalid" {
		t.Fatalf("list transports = %v err=%v", transports, err)
	}
	got, err := s.GetOutTransport(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "out2.example.invalid" || got.Port != 8443 {
		t.Fatalf("get transport wrong: %+v", got)
	}
}

// TestOutPoolListsTransportAndBinding is the Task 2 pool datasource: every
// enrolled Out appears with its transport and binding state, and an Out pool
// of several Outs is allowed (no singleton limit).
func TestOutPoolListsTransportAndBinding(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-pool", now)
	outA := pairedStoreNode(t, s, "out", now)
	outB := pairedStoreNode(t, s, "out", now)
	configureOut(t, s, outA, now)
	markLineOnline(t, s, line, now)
	markLineOnline(t, s, outA, now)

	if err := s.SetOutBinding(store.OutBinding{OutID: outA, LineID: line, Enabled: true}); err != nil {
		t.Fatal(err)
	}

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
	bound := byID[outA]
	if !bound.TransportConfigured || bound.LineID != line || !bound.Enabled {
		t.Fatalf("bound out entry wrong: %+v", bound)
	}
	if bound.Server != "out.example.invalid" || bound.Port == 0 {
		t.Fatalf("bound out entry has no dial address: %+v", bound)
	}
	unbound := byID[outB]
	if unbound.TransportConfigured || unbound.LineID != "" || unbound.Enabled {
		t.Fatalf("unbound out entry wrong: %+v", unbound)
	}
}

// TestOutBindingEnableRequiresOutTransport closes the endpoint gap: enabling
// a binding whose Out has no dial address is refused, because the Line would
// otherwise render a block stub while the Out gate reports healthy.
func TestOutBindingEnableRequiresOutTransport(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := pairedStoreNode(t, s, "out", now)
	line := pairedStoreNode(t, s, "edge", now)
	configureLine(t, s, line, "line-egress", now)

	err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true})
	if err == nil || !hasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("enable without out transport = %v, want OUT_NOT_CONFIGURED", err)
	}
	if _, err := s.PreviewOutBinding(out, line); err == nil || !hasErrorCode(err, "OUT_NOT_CONFIGURED") {
		t.Fatalf("proposal preview error = %v, want OUT_NOT_CONFIGURED", err)
	}
	configureOut(t, s, out, now)
	if err := s.SetOutBinding(store.OutBinding{OutID: out, LineID: line, Enabled: true}); err != nil {
		t.Fatalf("enable with out transport rejected: %v", err)
	}
	preview, err := s.PreviewOutBinding(out, line)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Mode != "out-bound" {
		t.Fatalf("proposal preview after transport = %+v, want out-bound", preview)
	}
}
