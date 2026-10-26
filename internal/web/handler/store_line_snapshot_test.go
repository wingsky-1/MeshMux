package handler

import (
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// buildLineCandidateFixture starts one transaction for the read-only builder.
// The test owns the transaction and always rolls it back.
func buildLineCandidateFixture(t *testing.T, s *store.Store, nodeID string) node.Candidate {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate, err := store.BuildLineCandidateTx(tx, nodeID, 7)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestBuildLineCandidateIncludesTwoSubscribersAndSkipsPaused(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	line := configureLine(t, s, edge, "line-a", now)

	alice, _, err := s.CreateSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := s.CreateSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	paused, _, err := s.CreateSubscriber("carol", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetSubscriberState(paused.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}

	candidate := buildLineCandidateFixture(t, s, edge)
	if candidate.NodeID != edge || candidate.Role != node.RoleEdge ||
		candidate.Revision != 7 || candidate.VLESSPort != 8443 ||
		candidate.KernelVersion != node.KernelVersion {
		t.Fatalf("baseline fields changed: %+v", candidate)
	}
	if candidate.Reality == nil ||
		candidate.Reality.ServerName != line.ServerName ||
		candidate.Reality.HandshakeServer != line.HandshakeServer ||
		candidate.Reality.HandshakePort != line.HandshakePort ||
		candidate.Reality.PrivateKey != line.PrivateKey ||
		candidate.Reality.ShortID != line.ShortID {
		t.Fatalf("reality does not match stored line: %+v", candidate.Reality)
	}
	if len(candidate.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(candidate.Users))
	}
	want := map[string]string{}
	for _, sub := range []subscription.Subscriber{alice, bob} {
		credentials, err := s.ListSubscriberCredentials(sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(credentials) != 1 {
			t.Fatalf("credentials of %s = %d", sub.ID, len(credentials))
		}
		want[credentials[0].ID] = credentials[0].UUID
	}
	pausedCredentials, err := s.ListSubscriberCredentials(paused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pausedCredentials) != 1 {
		t.Fatalf("paused credentials = %d", len(pausedCredentials))
	}
	var pausedActive int
	if err := s.DB.QueryRow(`SELECT active FROM proxy_credentials WHERE subscriber_id=?`, paused.ID).Scan(&pausedActive); err != nil {
		t.Fatal(err)
	}
	if pausedActive != 1 {
		t.Fatal("pausing must not release the credential")
	}
	for _, user := range candidate.Users {
		if user.CredentialID == pausedCredentials[0].ID {
			t.Fatal("paused subscriber was counted as active")
		}
	}
	for i, user := range candidate.Users {
		if uuid, ok := want[user.CredentialID]; !ok || uuid != user.UUID {
			t.Fatalf("unexpected user %d: %+v", i, user)
		}
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("candidate does not validate: %v", err)
	}
	// The paused subscriber is not part of the snapshot but stays untouched.
	stored, err := s.GetSubscriber(paused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != subscription.StatePaused {
		t.Fatalf("builder changed subscriber state to %s", stored.State)
	}
}

func TestBuildLineCandidateKeepsEmptyUserArray(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	candidate := buildLineCandidateFixture(t, s, edge)
	if candidate.Users == nil {
		t.Fatal("users is nil; a configured line without users must carry an empty array")
	}
	if len(candidate.Users) != 0 {
		t.Fatalf("users = %d, want 0", len(candidate.Users))
	}
	if candidate.Reality == nil {
		t.Fatal("configured line lost its reality block")
	}
	if _, err := node.NewCandidateDocument(candidate).MarshalJSON(); err != nil {
		t.Fatalf("empty user array does not serialize: %v", err)
	}
}

func TestBuildLineCandidateOutStaysBaseline(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := createOutNode(t, s, now)

	candidate := buildLineCandidateFixture(t, s, out)
	if candidate.NodeID != out || candidate.Role != node.RoleOut ||
		candidate.Revision != 7 || candidate.VLESSPort != 8444 ||
		candidate.KernelVersion != node.KernelVersion {
		t.Fatalf("out baseline fields wrong: %+v", candidate)
	}
	if candidate.Users != nil || candidate.Reality != nil {
		t.Fatalf("out candidate carried v2 blocks: users=%v reality=%v", candidate.Users, candidate.Reality)
	}
	if candidate.Out != nil {
		t.Fatalf("transport-free out candidate carried an egress: %+v", candidate.Out)
	}
}

// TestBuildLineCandidateOutWithTransportCarriesLinkKey pins the Ruling R7
// Out side: an Out with configured transport carries the link key in a v4
// document, so its Agent renders the SS guard instead of the VLESS baseline.
func TestBuildLineCandidateOutWithTransportCarriesLinkKey(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	out := createOutNode(t, s, now)
	configureOut(t, s, out, now)

	candidate := buildLineCandidateFixture(t, s, out)
	if candidate.Out == nil || candidate.Out.Key == "" {
		t.Fatalf("configured out candidate carries no link key: %+v", candidate.Out)
	}
	if candidate.Users != nil || candidate.Reality != nil || len(candidate.Route) != 0 {
		t.Fatalf("out candidate carried non-v4 blocks: %+v", candidate)
	}
	document := node.NewCandidateDocument(candidate)
	if document.Schema != node.CandidateSchemaV4 {
		t.Fatalf("out document schema = %q, want meshmux-node/v4", document.Schema)
	}
}

func TestBuildLineCandidateWithoutLineSettingsStaysBaseline(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	candidate := buildLineCandidateFixture(t, s, edge)
	if candidate.NodeID != edge || candidate.Role != node.RoleEdge ||
		candidate.Revision != 7 || candidate.VLESSPort != 8443 ||
		candidate.KernelVersion != node.KernelVersion {
		t.Fatalf("edge baseline fields wrong: %+v", candidate)
	}
	if candidate.Users != nil || candidate.Reality != nil {
		t.Fatalf("unconfigured edge carried v2 blocks: users=%v reality=%v", candidate.Users, candidate.Reality)
	}
}

func TestBuildLineCandidateRejectsPortMismatchWithoutSecrets(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	if _, err := s.DB.Exec(`UPDATE line_settings SET port=9443 WHERE node_id=?`, edge); err != nil {
		t.Fatal(err)
	}

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = store.BuildLineCandidateTx(tx, edge, 7)
	if err == nil {
		t.Fatal("port mismatch accepted")
	}
	if !strings.Contains(err.Error(), "LINE_PORT_MISMATCH") {
		t.Fatalf("error %q does not carry LINE_PORT_MISMATCH", err)
	}
	var privateKey string
	if err := tx.QueryRow(`SELECT private_key FROM line_settings WHERE node_id=?`, edge).Scan(&privateKey); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), privateKey) {
		t.Fatal("error leaked the reality private key")
	}
}
