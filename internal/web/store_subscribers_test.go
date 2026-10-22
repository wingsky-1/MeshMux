package web

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// subscriberStoreFixture opens a private store and returns it with the fixed
// test clock. Every test works on its own temporary directory.
func subscriberStoreFixture(t *testing.T) (*store, time.Time) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, time.Unix(1_700_000_000, 0)
}

// createEdgeNode inserts one edge node so it can be used as a proxy Line.
// The display name is a fixed short label: it must fit the node name policy.
func createEdgeNode(t *testing.T, s *store, now time.Time) string {
	t.Helper()
	node, _, err := s.createNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// createOutNode inserts one out node; it can never serve a proxy Line.
func createOutNode(t *testing.T, s *store, now time.Time) string {
	t.Helper()
	node, _, err := s.createNode("out", "out", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// testLine returns a valid Line transport for one node. The port matches the
// VLESS port of the fixture nodes.
func testLine(nodeID, name string) subscription.Line {
	pair, err := subscription.NewRealityKeyPair()
	if err != nil {
		panic(err)
	}
	shortID, err := subscription.NewShortID()
	if err != nil {
		panic(err)
	}
	return subscription.Line{
		NodeID:          nodeID,
		DisplayName:     name,
		Server:          "line.example.invalid",
		Port:            8443,
		SortOrder:       1,
		ServerName:      "line.example.invalid",
		HandshakeServer: "handshake.example.invalid",
		HandshakePort:   443,
		PrivateKey:      pair.PrivateKey,
		PublicKey:       pair.PublicKey,
		ShortID:         shortID,
	}
}

// configureLine stores a Line transport for one edge node.
func configureLine(t *testing.T, s *store, nodeID, name string, now time.Time) subscription.Line {
	t.Helper()
	line, err := s.setLine(testLine(nodeID, name), now)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestSubscriberCreateRejectsBadSelectionWithoutWrites(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	out := createOutNode(t, s, now)

	// An Out node is not a proxy Line.
	if _, _, err := s.createSubscriber("alice", []string{out}, now); err == nil {
		t.Fatal("out node accepted as line")
	}
	// A node without stored transport settings is not selectable yet.
	if _, _, err := s.createSubscriber("alice", []string{edge}, now); err == nil {
		t.Fatal("unconfigured line accepted")
	}
	// An empty selection and an unknown node are rejected too.
	if _, _, err := s.createSubscriber("alice", nil, now); err == nil {
		t.Fatal("empty selection accepted")
	}
	if _, _, err := s.createSubscriber("alice", []string{"ffffffffffffffffffffffffffffffff"}, now); err == nil {
		t.Fatal("unknown node accepted")
	}
	// None of the rejected attempts may leave a row behind.
	var subscribers, credentials, tokens int
	if err := s.db.QueryRow(`SELECT count(*) FROM subscribers`).Scan(&subscribers); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM proxy_credentials`).Scan(&credentials); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM subscription_tokens`).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if subscribers != 0 || credentials != 0 || tokens != 0 {
		t.Fatalf("rejected creation wrote rows: subscribers=%d credentials=%d tokens=%d", subscribers, credentials, tokens)
	}
}

func TestSubscriberCreateStoresCredentialAndToken(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	sub, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if sub.State != subscription.StateActive {
		t.Fatalf("state = %s, want active", sub.State)
	}
	if err := subscription.ValidateToken(bearer); err != nil {
		t.Fatalf("bearer is not canonical: %v", err)
	}
	// The bearer resolves to exactly this subscriber.
	resolved, err := s.resolveTokenSubscriber(bearer)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ID != sub.ID {
		t.Fatalf("resolved subscriber = %s, want %s", resolved.ID, sub.ID)
	}
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].NodeID != edge {
		t.Fatalf("credentials = %d, node match failed", len(credentials))
	}
	if err := subscription.ValidateUUID(credentials[0].UUID); err != nil {
		t.Fatalf("stored uuid is not canonical: %v", err)
	}
	// The plaintext bearer must never be stored.
	var stored int
	if err := s.db.QueryRow(`SELECT count(*) FROM subscription_tokens WHERE token_hash=?`,
		subscription.TokenHash(bearer)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("token hash rows = %d, want 1", stored)
	}
}

func TestSubscriberRenameKeepsIdentityAndLeavesOtherSubscriberUntouched(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	alice, aliceToken, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, bobToken, err := s.createSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	aliceBefore, err := s.listSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	bobBefore, err := s.listSubscriberCredentials(bob.ID)
	if err != nil {
		t.Fatal(err)
	}

	renamed, err := s.renameSubscriber(alice.ID, "alice-renamed", now)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != alice.ID {
		t.Fatalf("rename changed id: %s", renamed.ID)
	}
	if renamed.DisplayName != "alice-renamed" {
		t.Fatalf("display name = %q", renamed.DisplayName)
	}
	if renamed.State != subscription.StateActive {
		t.Fatalf("rename changed state: %s", renamed.State)
	}
	// The credential UUID survives the rename.
	aliceAfter, err := s.listSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceAfter) != 1 || aliceAfter[0].UUID != aliceBefore[0].UUID {
		t.Fatalf("rename changed credentials: %+v", aliceAfter)
	}
	// The other subscriber is untouched, including his own credential.
	bobAfter, err := s.listSubscriberCredentials(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bobAfter) != 1 || bobAfter[0].UUID != bobBefore[0].UUID {
		t.Fatalf("other subscriber credential changed: %d rows", len(bobAfter))
	}
	bobSubscriber, err := s.getSubscriber(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bobSubscriber.DisplayName != "bob" {
		t.Fatalf("other subscriber renamed: %q", bobSubscriber.DisplayName)
	}
	// Both bearers still work; a rename never revokes a token.
	for _, bearer := range []string{aliceToken, bobToken} {
		if _, err := s.resolveTokenSubscriber(bearer); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSubscriberTokenRotationRevokesOldBearerOnly(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	alice, aliceToken, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, bobToken, err := s.createSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentialsBefore, err := s.listSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := s.rotateToken(alice.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == aliceToken {
		t.Fatal("rotation returned the same bearer")
	}
	if _, err := s.resolveTokenSubscriber(rotated); err != nil {
		t.Fatalf("new bearer rejected: %v", err)
	}
	if _, err := s.resolveTokenSubscriber(aliceToken); err == nil {
		t.Fatal("old bearer still accepted")
	}
	// The other subscriber keeps his bearer.
	if _, err := s.resolveTokenSubscriber(bobToken); err != nil {
		t.Fatal(err)
	}
	// A rotation never touches the VLESS credential.
	credentialsAfter, err := s.listSubscriberCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentialsAfter) != 1 || credentialsAfter[0].UUID != credentialsBefore[0].UUID {
		t.Fatalf("rotation changed credentials: %d rows", len(credentialsAfter))
	}
	// The rotated bearer is not a UUID and the UUID is not a bearer.
	if rotated == credentialsAfter[0].UUID {
		t.Fatal("bearer equals the VLESS uuid")
	}
}

func TestSubscriberStateChangeRevokesTokensInSameTransaction(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	alice, aliceToken, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, bobToken, err := s.createSubscriber("bob", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, state := range []subscription.State{subscription.StatePaused, subscription.StateDeleting} {
		updated, err := s.setSubscriberState(alice.ID, state, now)
		if err != nil {
			t.Fatal(err)
		}
		if updated.State != state {
			t.Fatalf("state = %s, want %s", updated.State, state)
		}
		// A non-active subscriber can never download.
		if _, err := s.resolveTokenSubscriber(aliceToken); err == nil {
			t.Fatalf("token still accepted in state %s", state)
		}
		// The revocation is persisted, not only filtered at read time.
		var revoked int
		if err := s.db.QueryRow(`SELECT count(*) FROM subscription_tokens WHERE subscriber_id=? AND revoked=1`, alice.ID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if revoked != 1 {
			t.Fatalf("revoked tokens = %d, want 1", revoked)
		}
		// The other subscriber is unaffected.
		if _, err := s.resolveTokenSubscriber(bobToken); err != nil {
			t.Fatal(err)
		}
		bobSubscriber, err := s.getSubscriber(bob.ID)
		if err != nil {
			t.Fatal(err)
		}
		if bobSubscriber.State != subscription.StateActive {
			t.Fatalf("other subscriber state = %s", bobSubscriber.State)
		}
	}
	// Deleted is reachable only from deleting, and it is terminal.
	if _, err := s.setSubscriberState(alice.ID, subscription.StateDeleted, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.setSubscriberState(alice.ID, subscription.StateActive, now); err == nil {
		t.Fatal("deleted subscriber reactivated")
	}
	// A deleted subscriber leaves the management list but keeps its history.
	list, err := s.listSubscribers()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range list {
		if entry.ID == alice.ID {
			t.Fatal("deleted subscriber still listed")
		}
	}
}

func TestSubscriberStateChangeRejectsInvalidTransition(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	sub, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setSubscriberState(sub.ID, subscription.StateDeleted, now); err == nil {
		t.Fatal("active subscriber jumped to deleted")
	}
	if _, err := s.setSubscriberState(sub.ID, subscription.State("unknown"), now); err == nil {
		t.Fatal("unknown state accepted")
	}
	current, err := s.getSubscriber(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != subscription.StateActive {
		t.Fatalf("state = %s, want active", current.State)
	}
}

func TestSelectLinesPreservesHistoricalUUID(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first := createEdgeNode(t, s, now)
	second := createEdgeNode(t, s, now)
	configureLine(t, s, first, "line-a", now)
	configureLine(t, s, second, "line-b", now)

	sub, _, err := s.createSubscriber("alice", []string{first}, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("credentials = %d, want 1", len(before))
	}

	// Adding a second line keeps the first UUID and adds a new one.
	credentials, err := s.selectLines(sub.ID, []string{first, second}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("credentials = %d, want 2", len(credentials))
	}
	after, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	byNode := map[string]string{}
	for _, credential := range after {
		byNode[credential.NodeID] = credential.UUID
	}
	if byNode[first] != before[0].UUID {
		t.Fatalf("uuid of the kept line changed: %s -> %s", before[0].UUID, byNode[first])
	}
	if byNode[second] == "" {
		t.Fatal("new line has no credential")
	}
	if err := subscription.ValidateUUID(byNode[second]); err != nil {
		t.Fatalf("new uuid is not canonical: %v", err)
	}

	// Dropping a line deactivates its credential but never reuses the UUID.
	if _, err := s.selectLines(sub.ID, []string{second}, now); err != nil {
		t.Fatal(err)
	}
	dropped, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped credential was deleted: %d rows", len(dropped))
	}
	var active int
	if err := s.db.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND active=1`, sub.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active credentials = %d, want 1", active)
	}
	// Selecting the dropped line again keeps its historical UUID.
	if _, err := s.selectLines(sub.ID, []string{first, second}, now); err != nil {
		t.Fatal(err)
	}
	final, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range final {
		if credential.NodeID == first && credential.UUID != before[0].UUID {
			t.Fatalf("uuid was regenerated: %s", credential.UUID)
		}
	}
}

func TestSelectLinesRejectsInvalidSelection(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	out := createOutNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	sub, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.selectLines(sub.ID, []string{out}, now); err == nil {
		t.Fatal("out node accepted as line")
	}
	if _, err := s.selectLines(sub.ID, nil, now); err == nil {
		t.Fatal("empty selection accepted")
	}
	// The failed selection changed nothing.
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(credentials))
	}
}

func TestSelectLinesRequiresActiveSubscriber(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	second := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	configureLine(t, s, second, "line-b", now)

	sub, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.setSubscriberState(sub.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.selectLines(sub.ID, []string{edge, second}, now); err == nil {
		t.Fatal("paused subscriber changed lines")
	}
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(credentials))
	}
}

func TestSetLinePreservesTransportIdentity(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	out := createOutNode(t, s, now)

	stored := configureLine(t, s, edge, "line-a", now)

	// A rename with new keys keeps the original REALITY identity.
	renamed := testLine(edge, "line-renamed")
	renamed.SortOrder = 5
	renamed.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	renamed.PublicKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	updated, err := s.setLine(renamed, now)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "line-renamed" || updated.SortOrder != 5 {
		t.Fatalf("rename not applied: name=%q order=%d", updated.DisplayName, updated.SortOrder)
	}
	if updated.PrivateKey != stored.PrivateKey || updated.PublicKey != stored.PublicKey || updated.ShortID != stored.ShortID {
		t.Fatal("transport identity was replaced")
	}
	reloaded, err := s.getLine(edge)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.PrivateKey != stored.PrivateKey || reloaded.ShortID != stored.ShortID {
		t.Fatal("stored transport identity changed")
	}
	if reloaded.DisplayName != "line-renamed" || reloaded.SortOrder != 5 {
		t.Fatalf("stored label not updated: name=%q order=%d", reloaded.DisplayName, reloaded.SortOrder)
	}
	// An Out node never becomes a Line.
	if _, err := s.setLine(testLine(out, "out-line"), now); err == nil {
		t.Fatal("out node accepted as line")
	}
	// A line for an unknown node is rejected.
	if _, err := s.setLine(testLine("ffffffffffffffffffffffffffffffff", "ghost"), now); err == nil {
		t.Fatal("unknown node accepted as line")
	}
}

func TestListLinesOrdersBySortOrder(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first := createEdgeNode(t, s, now)
	second := createEdgeNode(t, s, now)
	// The second line is stored first but must be listed last.
	late := testLine(second, "line-a")
	late.SortOrder = 9
	if _, err := s.setLine(late, now); err != nil {
		t.Fatal(err)
	}
	early := testLine(first, "line-b")
	early.SortOrder = 2
	if _, err := s.setLine(early, now); err != nil {
		t.Fatal(err)
	}

	lines, err := s.listLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if lines[0].NodeID != first || lines[1].NodeID != second {
		t.Fatalf("unexpected order: %s %s", lines[0].NodeID, lines[1].NodeID)
	}
}

func TestSubscriberTokenRevocationIsIndependentOfCredential(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	sub, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.revokeTokens(sub.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveTokenSubscriber(bearer); err == nil {
		t.Fatal("revoked bearer still accepted")
	}
	after, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].UUID != credentials[0].UUID {
		t.Fatalf("credential was released by a token revocation: %d rows", len(after))
	}
	// Revocation is idempotent.
	if err := s.revokeTokens(sub.ID, now); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownBearerIsRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	if _, _, err := s.createSubscriber("alice", []string{edge}, now); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "short", "not-a-token"} {
		if _, err := s.resolveTokenSubscriber(token); err == nil {
			t.Fatalf("invalid token accepted: %q", token)
		}
	}
	// A canonical but unknown bearer is rejected as well.
	unknown, err := subscription.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveTokenSubscriber(unknown); err == nil {
		t.Fatal("unknown token accepted")
	}
}

// TestResolveTokenSubscriberReportsDatabaseFailure verifies that a database
// failure is never disguised as an invalid token. A closed database must be
// reported as a database problem, because a client that retries after a
// transient failure has to be able to tell the two cases apart.
func TestResolveTokenSubscriberReportsDatabaseFailure(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	_, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The bearer is valid and known before the database goes away.
	if _, err := s.resolveTokenSubscriber(bearer); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = s.resolveTokenSubscriber(bearer)
	if err == nil {
		t.Fatal("closed database reported a resolved subscriber")
	}
	if !hasErrorCode(err, "DATABASE_UNAVAILABLE") {
		t.Fatalf("error %q does not carry code DATABASE_UNAVAILABLE", err)
	}
	// The failure message never contains the bearer.
	if strings.Contains(err.Error(), bearer) {
		t.Fatal("error message leaks the bearer")
	}
}

// TestRevokeTokensRejectsUnknownSubscriber verifies that a revocation for an
// unknown subscriber is an error instead of a silent success. A mistyped
// identifier must never be reported as a successful revocation.
func TestRevokeTokensRejectsUnknownSubscriber(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	sub, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}

	err = s.revokeTokens("ffffffffffffffffffffffffffffffff", now)
	if err == nil {
		t.Fatal("revocation of an unknown subscriber reported success")
	}
	if !hasErrorCode(err, "SUBSCRIBER_NOT_FOUND") {
		t.Fatalf("error %q does not carry code SUBSCRIBER_NOT_FOUND", err)
	}
	// The known subscriber keeps his bearer: the failed call revoked nothing.
	if _, err := s.resolveTokenSubscriber(bearer); err != nil {
		t.Fatal(err)
	}
	// The known subscriber can still be revoked normally.
	if err := s.revokeTokens(sub.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveTokenSubscriber(bearer); err == nil {
		t.Fatal("revoked bearer still accepted")
	}
}

// TestRenameSubscriberRejectsTombstone verifies that a deleting or deleted
// subscriber keeps its tombstone: its display name stays frozen. A paused
// subscriber may still be renamed.
func TestRenameSubscriberRejectsTombstone(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	sub, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}

	// A paused subscriber is renamed: the pause is a temporary desired state.
	if _, err := s.setSubscriberState(sub.ID, subscription.StatePaused, now); err != nil {
		t.Fatal(err)
	}
	renamed, err := s.renameSubscriber(sub.ID, "alice-paused", now)
	if err != nil {
		t.Fatalf("paused subscriber was not renamed: %v", err)
	}
	if renamed.DisplayName != "alice-paused" {
		t.Fatalf("display name = %q", renamed.DisplayName)
	}

	// A deleting subscriber keeps its tombstone.
	if _, err := s.setSubscriberState(sub.ID, subscription.StateDeleting, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.renameSubscriber(sub.ID, "alice-renamed", now); err == nil {
		t.Fatal("deleting subscriber was renamed")
	} else if !hasErrorCode(err, "SUBSCRIBER_TOMBSTONED") {
		t.Fatalf("error %q does not carry code SUBSCRIBER_TOMBSTONED", err)
	}
	// A deleted subscriber keeps its tombstone too.
	if _, err := s.setSubscriberState(sub.ID, subscription.StateDeleted, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.renameSubscriber(sub.ID, "alice-renamed", now); err == nil {
		t.Fatal("deleted subscriber was renamed")
	} else if !hasErrorCode(err, "SUBSCRIBER_TOMBSTONED") {
		t.Fatalf("error %q does not carry code SUBSCRIBER_TOMBSTONED", err)
	}
	// The stored name is exactly the one from before the deletion.
	stored, err := s.getSubscriber(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DisplayName != "alice-paused" {
		t.Fatalf("stored display name = %q, want alice-paused", stored.DisplayName)
	}
}

// TestCorruptLineSettingsAreRejected verifies that a stored Line that does not
// satisfy the domain contract is never handed to a caller. A row that was
// modified outside the Hub must fail instead of reaching a client
// configuration.
func TestCorruptLineSettingsAreRejected(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)

	// An IP address is not a valid REALITY server name. The write path never
	// stores such a value, so the row is corrupted on purpose.
	if _, err := s.db.Exec(`UPDATE line_settings SET server_name=? WHERE node_id=?`, "203.0.113.7", edge); err != nil {
		t.Fatal(err)
	}

	_, err := s.getLine(edge)
	if err == nil {
		t.Fatal("corrupt line was returned by getLine")
	}
	if !hasErrorCode(err, "LINE_SETTINGS_CORRUPT") {
		t.Fatalf("error %q does not carry code LINE_SETTINGS_CORRUPT", err)
	}
	if _, err := s.listLines(); err == nil {
		t.Fatal("corrupt line was returned by listLines")
	} else if !hasErrorCode(err, "LINE_SETTINGS_CORRUPT") {
		t.Fatalf("error %q does not carry code LINE_SETTINGS_CORRUPT", err)
	}
}

func TestSchemaV3DataSurvivesV4Migration(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	// Seed real schema-3 rows that must survive the upgrade: an agent task
	// and a session. The task is enqueued through the validated path.
	task, err := newFixedTask(edge, protocol.KindHealthStatus, json.RawMessage(`{}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.enqueueTaskAt(task, now); err != nil {
		t.Fatal(err)
	}
	hash, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO admin VALUES(1,?)`, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO sessions VALUES(x'73657373696F6E2D746F6B656E2D68617368','session-csrf',1,?,?)`, now.Add(3600).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	candidateBefore, err := s.latestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	nodeBefore, err := s.getNodeAt(edge, now)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the database in its schema-3 shape: the subscription tables do
	// not exist yet and the version is 3.
	if _, err = s.db.Exec(`DROP TABLE route_policy_events; DROP TABLE route_policies; DROP TABLE mesh_route_events; DROP TABLE mesh_routes; DROP TABLE mesh_enrollment_keys; DROP TABLE mesh_devices; DROP TABLE out_bindings; DROP TABLE subscribers; DROP TABLE proxy_credentials; DROP TABLE subscription_tokens; DROP TABLE line_settings; PRAGMA user_version=3;`); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("user_version = %d, want 3", version)
	}

	// The migration to v6 must succeed and keep the schema-3 data.
	if err = s.migrate(); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 8 {
		t.Fatalf("user_version = %d, want 8", version)
	}
	after, err := s.getNodeAt(edge, now)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != nodeBefore.ID || after.DisplayName != nodeBefore.DisplayName || after.VlessPort != nodeBefore.VlessPort {
		t.Fatal("node data changed by the migration")
	}
	candidateAfter, err := s.latestCandidate(edge)
	if err != nil {
		t.Fatal(err)
	}
	if candidateAfter.Revision != candidateBefore.Revision || candidateAfter.ConfigSHA256 != candidateBefore.ConfigSHA256 {
		t.Fatal("candidate changed by the migration")
	}
	var tasks int
	if err = s.db.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND operation_id=?`, edge, task.OperationID).Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if tasks != 1 {
		t.Fatalf("agent task rows after migration = %d, want 1", tasks)
	}
	var sessions int
	if err = s.db.QueryRow(`SELECT count(*) FROM sessions WHERE hex(token_hash)='73657373696F6E2D746F6B656E2D68617368' AND csrf='session-csrf' AND authenticated=1`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("session rows after migration = %d, want 1", sessions)
	}
	adminHash, err := s.adminHash()
	if err != nil {
		t.Fatal(err)
	}
	if adminHash != hash {
		t.Fatal("admin hash changed by the migration")
	}

	// The new tables work on the migrated database.
	configureLine(t, s, edge, "line-a", now)
	sub, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveTokenSubscriber(bearer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.getSubscriber(sub.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaV4MigrationRollsBackOnFailure(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	// Simulate a v3 database and a failing v4 migration. The failure must
	// leave the database exactly at v3 without any partial table.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`DROP TABLE route_policy_events; DROP TABLE route_policies; DROP TABLE mesh_route_events; DROP TABLE mesh_routes; DROP TABLE mesh_enrollment_keys; DROP TABLE mesh_devices; DROP TABLE out_bindings; DROP TABLE subscribers; DROP TABLE proxy_credentials; DROP TABLE subscription_tokens; DROP TABLE line_settings; PRAGMA user_version=3;`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// A table that already exists makes the v4 migration fail.
	if _, err = s.db.Exec(`CREATE TABLE line_settings (node_id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err = s.migrate(); err == nil {
		t.Fatal("failed migration was reported as success")
	}
	var version int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("user_version = %d after failed migration, want 3", version)
	}
	// No partial subscription table survived the rollback.
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='subscribers'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("partial subscribers table survived the rollback")
	}
	// The pre-existing node data is still there.
	if _, err = s.getNodeAt(edge, now); err != nil {
		t.Fatal(err)
	}
}

func TestSelectLinesReselectRestoresInactiveCredential(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	first := createEdgeNode(t, s, now)
	second := createEdgeNode(t, s, now)
	configureLine(t, s, first, "line-a", now)
	configureLine(t, s, second, "line-b", now)

	sub, _, err := s.createSubscriber("alice", []string{first, second}, now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	uuidByNode := map[string]string{}
	for _, credential := range before {
		uuidByNode[credential.NodeID] = credential.UUID
	}

	// Drop the first line: its credential becomes inactive.
	if _, err = s.selectLines(sub.ID, []string{second}, now); err != nil {
		t.Fatal(err)
	}
	var active int
	if err = s.db.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND active=1`, sub.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active credentials = %d, want 1", active)
	}

	// Select it again: the credential must become active again and keep its
	// historical UUID. An inactive row must never stay silently inactive.
	if _, err = s.selectLines(sub.ID, []string{first, second}, now); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM proxy_credentials WHERE subscriber_id=? AND active=1`, sub.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 2 {
		t.Fatalf("active credentials after reselect = %d, want 2", active)
	}
	after, err := s.listSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range after {
		if credential.UUID != uuidByNode[credential.NodeID] {
			t.Fatalf("uuid changed for node %s", credential.NodeID)
		}
	}
	// The selection change bumps the revision so a publication can notice.
	var revision int
	if err = s.db.QueryRow(`SELECT revision FROM subscribers WHERE id=?`, sub.ID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision < 2 {
		t.Fatalf("revision = %d, want at least 2", revision)
	}
}

func TestSubscriberStateChangeIsIdempotent(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	sub, bearer, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	var revisionBefore int
	if err = s.db.QueryRow(`SELECT revision FROM subscribers WHERE id=?`, sub.ID).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}

	// Repeating the current state is a no-op, not an error.
	again, err := s.setSubscriberState(sub.ID, subscription.StateActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != subscription.StateActive {
		t.Fatalf("state = %s", again.State)
	}
	var revisionAfter int
	if err = s.db.QueryRow(`SELECT revision FROM subscribers WHERE id=?`, sub.ID).Scan(&revisionAfter); err != nil {
		t.Fatal(err)
	}
	if revisionAfter != revisionBefore {
		t.Fatalf("revision changed on an idempotent call: %d -> %d", revisionBefore, revisionAfter)
	}
	if _, err := s.resolveTokenSubscriber(bearer); err != nil {
		t.Fatal(err)
	}

	// Repeating a non-active state keeps the revocation in place.
	if _, err = s.setSubscriberState(sub.ID, subscription.StateDeleting, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.setSubscriberState(sub.ID, subscription.StateDeleting, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveTokenSubscriber(bearer); err == nil {
		t.Fatal("token accepted after a repeated deleting state")
	}
	var revoked int
	if err = s.db.QueryRow(`SELECT count(*) FROM subscription_tokens WHERE subscriber_id=? AND revoked=1`, sub.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Fatalf("revoked tokens = %d, want 1", revoked)
	}
}

func TestSetLineRejectsPortMismatch(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	line := testLine(edge, "line-a")
	line.Port = 443
	if _, err := s.setLine(line, now); err == nil {
		t.Fatal("port mismatch accepted")
	}
	// The rejected line was not stored.
	if _, err := s.getLine(edge); err == nil {
		t.Fatal("rejected line was stored")
	}
}

func TestSetLineRejectsInvalidRealitySettings(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	// An IP address is not a valid REALITY server name.
	ipServer := testLine(edge, "line-a")
	ipServer.ServerName = "203.0.113.7"
	if _, err := s.setLine(ipServer, now); err == nil {
		t.Fatal("ip server name accepted")
	}

	// A host with a scheme is not a valid handshake target.
	scheme := testLine(edge, "line-a")
	scheme.HandshakeServer = "https://handshake.example.invalid"
	if _, err := s.setLine(scheme, now); err == nil {
		t.Fatal("handshake server with scheme accepted")
	}

	// Nothing was stored by the rejected attempts.
	if _, err := s.getLine(edge); err == nil {
		t.Fatal("rejected line was stored")
	}
}

func TestSetLineCanonicalizesLowercaseHosts(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)

	// Upper case DNS names are valid input; the stored value is canonical.
	line := testLine(edge, "line-a")
	line.ServerName = "Line.Example.Invalid"
	line.HandshakeServer = "Handshake.Example.Invalid"
	stored, err := s.setLine(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ServerName != "line.example.invalid" || stored.HandshakeServer != "handshake.example.invalid" {
		t.Fatalf("hosts were not canonicalized: %q %q", stored.ServerName, stored.HandshakeServer)
	}
	reloaded, err := s.getLine(edge)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ServerName != "line.example.invalid" || reloaded.HandshakeServer != "handshake.example.invalid" {
		t.Fatalf("stored hosts are not canonical: %q %q", reloaded.ServerName, reloaded.HandshakeServer)
	}
}

func TestSubscriberErrorsCarryStableCodes(t *testing.T) {
	s, now := subscriberStoreFixture(t)
	edge := createEdgeNode(t, s, now)
	configureLine(t, s, edge, "line-a", now)
	sub, _, err := s.createSubscriber("alice", []string{edge}, now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"unknown subscriber", func() error { _, e := s.getSubscriber("ffffffffffffffffffffffffffffffff"); return e }(), "SUBSCRIBER_NOT_FOUND"},
		{"invalid subscriber id", func() error { _, e := s.getSubscriber("nope"); return e }(), "SUBSCRIBER_ID_INVALID"},
		{"invalid name", func() error { _, e := s.renameSubscriber(sub.ID, "  ", now); return e }(), "DISPLAY_NAME_INVALID"},
		{"invalid line id", func() error { _, e := s.setLine(subscription.Line{NodeID: "nope"}, now); return e }(), "LINE_NODE_ID_INVALID"},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
		if !hasErrorCode(tc.err, tc.code) {
			t.Fatalf("%s: error %q does not carry code %s", tc.name, tc.err, tc.code)
		}
	}
}

// hasErrorCode reports whether the sanitized error carries the given stable
// error code.
func hasErrorCode(err error, code string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), code)
}
