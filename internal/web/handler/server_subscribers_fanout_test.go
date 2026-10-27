package handler

import (
	"encoding/json"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// TestLinesSaveFansOutToEveryCredentialSubscriber pins the #7 fan-out: saving a
// Line must queue a fresh publication for every subscriber that ever held a
// credential on it, without failing the save when the fan-out itself cannot
// complete.
func TestLinesSaveFansOutToEveryCredentialSubscriber(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	node, _ := createPendingNode(t, app, "edge", "line-fan-01", 8443, 2222)
	configureLine(t, app.Store, node.ID, "line-a", time.Now())
	// A Line outside the delivery window is never published, so put it inside
	// the window before the save under test.
	markLineOnline(t, app.Store, node.ID, app.Now())

	for _, name := range []string{"alice", "bob"} {
		w := b.post("/subscribers", url.Values{"display_name": {name}, "line_" + node.ID: {"1"}})
		require2xx(t, w)
	}
	subs, err := app.Store.ListSubscribers()
	if err != nil || len(subs) != 2 {
		t.Fatalf("subscriber setup: %d subscribers (err %v)", len(subs), err)
	}
	// Creating a subscriber queues its first publication. The chain of the
	// second creation is still in flight, and the drain correctly refuses to
	// enqueue while that is the case, so settle it: the save below has to be
	// the only publication trigger left.
	settleTasks(t, app.Store, node.ID)

	// The fan-out source is every subscriber that ever held a credential on
	// the Line, not only the currently selected ones. Both subscribers must be
	// collected before any store write runs.
	credentialSubscribers, err := app.lineCredentialSubscriberIDs(node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentialSubscribers) != 2 {
		t.Fatalf("fan-out subscribers = %v, want both credentialed subscribers", credentialSubscribers)
	}

	// Publication is recorded by the immutable candidate revisions and their
	// fixed Agent task chain, not by the subscriber rows: a subscriber has no
	// per-Line state of its own. Saving the Line again must publish one more
	// revision with a fresh four-task chain. The save changes the REALITY
	// handshake address, a transport field of the compiled candidate; a save
	// that only renames the label changes no compiled byte and is correctly
	// withheld by the drain instead.
	before := subscriberPublicationSnapshot(t, app.Store, node.ID)

	w := b.post("/lines", url.Values{
		"node_id": {node.ID}, "display_name": {"line-a-renamed"}, "sort_order": {"1"},
		"server": {"line.example.invalid"}, "port": {"8443"},
		"server_name":      {"handshake.example.invalid"},
		"handshake_server": {"handshake2.example.invalid"}, "handshake_port": {"443"},
	})
	if got := w.Result(); got.StatusCode != http.StatusOK {
		t.Fatalf("save status %d want 200", got.StatusCode)
	}

	after := subscriberPublicationSnapshot(t, app.Store, node.ID)
	if after.latestRevision <= before.latestRevision {
		t.Fatalf("line latest revision %d -> %d, fan-out published nothing", before.latestRevision, after.latestRevision)
	}
	if after.tasks <= before.tasks {
		t.Fatalf("line tasks %d -> %d, fan-out enqueued no chain", before.tasks, after.tasks)
	}
	// The second revision's chain points at that revision, so the tasks are
	// publication work and not unrelated bookkeeping.
	if got := subscriberChainRevision(t, app.Store, node.ID); got != after.latestRevision {
		t.Fatalf("latest chain revision %d, latest candidate %d", got, after.latestRevision)
	}
	// The republished snapshot carries every subscriber that held a
	// credential, so the fan-out never drops a user that entered while a
	// chain was still in flight.
	latest, err := app.Store.LatestCandidate(node.ID)
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]bool{}
	for _, sub := range subs {
		credentials, cErr := app.Store.ListSubscriberCredentials(sub.ID)
		if cErr != nil || len(credentials) == 0 {
			t.Fatalf("credentials of %s: %d (err %v)", sub.ID, len(credentials), cErr)
		}
		for _, credential := range credentials {
			missing[credential.UUID] = true
		}
	}
	for _, user := range latest.Document.Users {
		delete(missing, user.UUID)
	}
	if len(missing) != 0 {
		t.Fatalf("republished snapshot lost credentials: %v", missing)
	}

	// The API projection exposes the same precise sync evidence as the page.
	api := b.req("GET", "/api/subscribers", nil, nil)
	requireStatus(t, api, http.StatusOK)
	var body struct {
		Subscribers []struct {
			ID         string `json:"id"`
			SyncStatus string `json:"sync_status"`
			SyncCode   string `json:"sync_code"`
			SyncLabel  string `json:"sync_label"`
			Lines      []struct {
				NodeID     string `json:"node_id"`
				SyncStatus string `json:"sync_status"`
				SyncCode   string `json:"sync_code"`
			} `json:"lines"`
		} `json:"subscribers"`
	}
	if err := json.Unmarshal(api.Body.Bytes(), &body); err != nil {
		t.Fatalf("api projection is not valid JSON: %v", err)
	}
	if len(body.Subscribers) != 2 {
		t.Fatalf("api subscribers = %d want 2", len(body.Subscribers))
	}
	for _, sub := range body.Subscribers {
		if sub.SyncStatus == "" || sub.SyncLabel == "" {
			t.Fatalf("subscriber %s api lacks sync_status/sync_label: %+v", sub.ID, sub)
		}
		if len(sub.Lines) != 1 || sub.Lines[0].SyncStatus == "" {
			t.Fatalf("subscriber %s api lacks line sync_status: %+v", sub.ID, sub.Lines)
		}
	}
}

// subscriberPublication is the durable publication record of one Line.
type subscriberPublication struct {
	latestRevision int64
	tasks          int
}

// subscriberPublicationSnapshot reads the publication record of one Line: the
// newest immutable candidate revision and the number of queued Agent tasks.
func subscriberPublicationSnapshot(t *testing.T, s *store.Store, nodeID string) subscriberPublication {
	t.Helper()
	var snapshot subscriberPublication
	if err := s.DB.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, nodeID).
		Scan(&snapshot.latestRevision); err != nil {
		t.Fatal(err)
	}
	snapshot.tasks = taskCount(t, s, nodeID)
	return snapshot
}

// subscriberChainRevision returns the candidate revision that the newest fixed
// task chain publishes.
func subscriberChainRevision(t *testing.T, s *store.Store, nodeID string) int64 {
	t.Helper()
	var raw string
	if err := s.DB.QueryRow(`SELECT params FROM agent_tasks WHERE node_id=? AND kind=? ORDER BY revision DESC LIMIT 1`,
		nodeID, protocol.KindConfigCheck).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var params struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		t.Fatalf("chain params are not valid JSON: %v", err)
	}
	return params.Revision
}
