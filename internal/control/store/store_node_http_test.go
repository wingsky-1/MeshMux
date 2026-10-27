package store_test

// Ruling R11: an HTTP proxy is a Hub-visible external egress node. It has no
// Agent, pairing, candidate or readback (status is always "external"), its
// credentials live in node_http_proxy next to the other node secrets, and the
// subscription egress slot (one row, MAX_OUTS = 1) selects it exactly like an
// Out. The used-by interlock and the thorough delete are the same rules.
//
// These tests drive the real store and the real candidate renderer; the
// `sing-box check` evidence is in internal/node (render_http_egress_test.go).

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"

	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// httpProxyFixture creates one configured Line, one external HTTP proxy and
// one active subscriber selecting the Line. It returns their ids.
func httpProxyFixture(t *testing.T, s *store.Store, now time.Time) (string, string, string) {
	t.Helper()
	lineNode, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLine(testSelectionLine(t, lineNode.ID), now); err != nil {
		t.Fatal(err)
	}
	proxy, err := s.CreateHTTPProxyNode("办公室代理", "http://alice:s3cret@proxy.example.invalid:8080", now)
	if err != nil {
		t.Fatal(err)
	}
	sub, _, err := s.CreateSubscriber("alice", []string{lineNode.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	return lineNode.ID, proxy.ID, sub.ID
}

func TestHTTPProxyNodeIsExternalAndHasNoAgentState(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	proxy, err := s.CreateHTTPProxyNode("办公室代理", "http://Alice:S3cret@Proxy.Example.Invalid:8080/", now)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Role != string(nodedomain.RoleHTTP) || proxy.Status != "external" {
		t.Fatalf("proxy node = role %q status %q", proxy.Role, proxy.Status)
	}
	if proxy.VlessPort != 0 || proxy.SSHPort != 0 {
		t.Fatalf("external proxy ports = %d/%d, want 0/0", proxy.VlessPort, proxy.SSHPort)
	}
	// A proxy is never offline: it has no heartbeat to miss.
	stored, err := s.GetNodeAt(proxy.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Offline {
		t.Fatal("external http proxy reported offline")
	}
	// No agent state of any kind exists for it.
	for table, want := range map[string]int{
		"node_pairing": 0, "node_identities": 0, "node_candidates": 0, "agent_tasks": 0,
	} {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM `+table+` WHERE node_id=?`, proxy.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
	// The canonical URL never carries userinfo; credentials are separate
	// columns and the DB file stays 0600.
	var rawURL, username, password string
	if err := s.DB.QueryRow(`SELECT url, username, password FROM node_http_proxy WHERE node_id=?`, proxy.ID).
		Scan(&rawURL, &username, &password); err != nil {
		t.Fatal(err)
	}
	if rawURL != "http://proxy.example.invalid:8080" {
		t.Fatalf("stored URL = %q, want the credential-free canonical form", rawURL)
	}
	if username != "Alice" || password != "S3cret" {
		t.Fatalf("stored credentials = %q/%q", username, password)
	}
	info, err := os.Stat(filepath.Join(s.Dir, "meshmux.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o, want 0600", info.Mode().Perm())
	}
	pool, err := s.OutPool(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 1 || pool[0].Server != "proxy.example.invalid" || pool[0].Port != 8080 {
		t.Fatalf("pool projection = %+v, want host:port only", pool)
	}
}

func TestHTTPProxySelectionStaysOutOfTheLineCandidate(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatalf("http egress selection rejected: %v", err)
	}
	if usedBy, err := s.OutUsedBy(proxyID); err != nil || len(usedBy) != 1 {
		t.Fatalf("used-by = %v err=%v", usedBy, err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate, err := store.BuildLineCandidateTx(tx, lineID, 3)
	if err != nil {
		t.Fatal(err)
	}
	// The Line candidate is the proxy port and user set only: the egress lives
	// in the client document the subscriber downloads, never in the server
	// snapshot.
	if candidate.Out != nil {
		t.Fatalf("line candidate carries an egress: %+v", candidate.Out)
	}
	if candidate.Route != nil {
		t.Fatalf("line candidate carries a route: %s", candidate.Route)
	}
	document, err := json.Marshal(nodedomain.NewCandidateDocument(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document), "proxy.example.invalid") {
		t.Fatalf("candidate document carries the external egress: %s", document)
	}
	// The selection is the only egress slot row (MAX_OUTS = 1).
	var rows int
	if err := tx.QueryRow(`SELECT count(*) FROM subscription_outs WHERE subscriber_id=?`, subID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("egress slot rows = %d, want 1", rows)
	}
}

func TestHTTPProxyEgressIsExcludedFromOutAuthorizationGate(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// No Out node is enrolled at all: the HTTP proxy still gives the Line a
	// configured, available egress, so the policy may keep the out tag without
	// an OUT_NOT_AUTHORIZED / OUT_OFFLINE_FAIL_CLOSED refusal. The availability
	// is the operator's declaration, so it is never reported as a bare
	// "available with no code": the code names the declaration and
	// ExternalDeclared distinguishes it from a confirmed managed Out.
	facts, err := store.OutEgressFactsTx(tx, lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Configured || !facts.Available || !facts.ExternalDeclared ||
		facts.OutID != proxyID || facts.Code != store.CodeLineEgressExternalDeclared {
		t.Fatalf("http egress facts = %+v", facts)
	}
	state, code, err := store.LineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressExternal || code != store.CodeLineEgressExternalDeclared {
		t.Fatalf("line egress state = %q/%q, want external/%s", state, code, store.CodeLineEgressExternalDeclared)
	}
}

func TestHTTPProxyDeleteIsThoroughAndInterlocked(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatal(err)
	}
	err := s.DeleteOutAt(proxyID, now)
	if err == nil || !strings.Contains(err.Error(), s.Subscribers.OutReferencedCode()) {
		t.Fatalf("referenced http proxy delete = %v, want %s", err, s.Subscribers.OutReferencedCode())
	}
	if _, err := s.GetNodeAt(proxyID, now); err != nil {
		t.Fatalf("refused delete removed the node: %v", err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOutAt(proxyID, now); err != nil {
		t.Fatalf("unreferenced http proxy delete: %v", err)
	}
	if _, err := s.GetNodeAt(proxyID, now); err == nil {
		t.Fatal("http proxy node survived the delete")
	}
	var rows int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_http_proxy WHERE node_id=?`, proxyID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("node_http_proxy rows = %d, want the row deleted", rows)
	}
}

// TestSchema16RebuildPreservesNodesAndChildren replays the schema-16 rebuild
// on a populated database: the nodes rebuild must copy every row and leave the
// child tables, the HTTP proxy row and the candidate immutability trigger
// intact.
func TestSchema16RebuildPreservesNodesAndChildren(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatal(err)
	}
	edge, err := s.GetNodeAt(lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=15`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("schema 16 replay: %v", err)
	}
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != store.DatabaseSchemaVersion {
		t.Fatalf("version after replay = %d err=%v", version, err)
	}
	if stored, err := s.GetNodeAt(lineID, now); err != nil || stored.Role != edge.Role || stored.DisplayName != edge.DisplayName {
		t.Fatalf("edge node lost by rebuild: %+v err=%v", stored, err)
	}
	if _, err := s.GetNodeAt(proxyID, now); err != nil {
		t.Fatalf("http proxy lost by rebuild: %v", err)
	}
	var proxyRows, candidateRows, edgeRows int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_http_proxy WHERE node_id=?`, proxyID).Scan(&proxyRows); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, lineID).Scan(&candidateRows); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM subscription_lines WHERE subscriber_id=?`, subID).Scan(&edgeRows); err != nil {
		t.Fatal(err)
	}
	if proxyRows != 1 || candidateRows == 0 || edgeRows != 1 {
		t.Fatalf("rebuilt children: proxy=%d candidates=%d lines=%d", proxyRows, candidateRows, edgeRows)
	}
	fkRows, err := s.DB.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if fkRows.Next() {
		fkRows.Close()
		t.Fatal("schema 16 rebuild left a foreign key violation")
	}
	fkRows.Close()
	// The narrowed candidate trigger survives the rebuild: a live candidate
	// still refuses a delete, and an update still refuses unconditionally.
	if _, err := s.DB.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,2,'{}','x',?)`, lineID, now.Unix()); err != nil {
		t.Fatalf("insert probe candidate: %v", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM node_candidates WHERE node_id=?`, lineID); err == nil || !strings.Contains(err.Error(), "CANDIDATE_IMMUTABLE") {
		t.Fatalf("candidate trigger lost by rebuild: %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE node_candidates SET config_sha256='y' WHERE node_id=?`, lineID); err == nil || !strings.Contains(err.Error(), "CANDIDATE_IMMUTABLE") {
		t.Fatalf("candidate update trigger lost by rebuild: %v", err)
	}
}

// TestHTTPProxyDeleteSkipsTheOutCandidateChain pins the lifecycle branch: an
// external HTTP proxy has no Agent, no candidate and no ACL, so its delete must
// never reach BuildLineCandidateTx (which would answer NODE_ROLE_INVALID and
// turn every proxy delete into a permanent failure), and it must never publish
// an empty ACL chain for a host that does not exist.
func TestHTTPProxyDeleteSkipsTheOutCandidateChain(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	_, proxyID, _ := httpProxyFixture(t, s, now)
	// A published candidate on the proxy would be the only way the cleanup
	// branch runs; nothing can create one, which is exactly the invariant. The
	// delete therefore has nothing to clear and must succeed.
	if _, err := s.DB.Exec(`SELECT revision FROM node_candidates WHERE node_id=?`, proxyID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOutAt(proxyID, now); err != nil {
		t.Fatalf("http proxy delete = %v, want success without an out chain", err)
	}
	var candidates, tasks int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, proxyID).Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=?`, proxyID).Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if candidates != 0 || tasks != 0 {
		t.Fatalf("proxy delete wrote candidate/task rows: candidates=%d tasks=%d", candidates, tasks)
	}
	if _, err := s.GetNodeAt(proxyID, now); err == nil {
		t.Fatal("http proxy node survived the delete")
	}
}

// TestHTTPProxyRetryIsAnExplicitNoop pins the retry path: there is no Agent
// chain to republish for an external proxy, so the call answers the stable
// "not applicable" code instead of a silent success that would read as a
// published and confirmed chain.
func TestHTTPProxyRetryIsAnExplicitNoop(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	_, proxyID, _ := httpProxyFixture(t, s, now)
	if err := s.RetryOutSync(proxyID, now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodeOutSyncNotApplicable) {
		t.Fatalf("http proxy retry = %v, want %s", err, store.CodeOutSyncNotApplicable)
	}
	var candidates int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, proxyID).Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if candidates != 0 {
		t.Fatalf("http proxy retry published %d candidates", candidates)
	}
}

// TestHTTPProxyReadbackReportsTheDeclaration pins the diagnosis projection: the
// proxy half is reported as the operator's declaration (with the stable code)
// and never as a healthy managed Out, and the declaration alone never makes the
// pair healthy — the Line still has to prove its own inbound half.
func TestHTTPProxyReadbackReportsTheDeclaration(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired', last_heartbeat=? WHERE id=?`, now.Unix(), lineID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatal(err)
	}
	lineReadback, err := s.NodeCoordinationReadback(lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if lineReadback.Allowlist != store.LineEgressExternal ||
		lineReadback.AllowlistCode != store.CodeLineEgressExternalDeclared {
		t.Fatalf("line allowlist fact = %+v, want the external declaration", lineReadback)
	}
	if lineReadback.FinalEgress == store.LineEgressHealthy || lineReadback.RetryPending {
		t.Fatalf("line readback = %+v, want a declared egress that is not retry-pending", lineReadback)
	}
	proxyReadback, err := s.NodeCoordinationReadback(proxyID, now)
	if err != nil {
		t.Fatalf("proxy readback: %v", err)
	}
	if proxyReadback.Allowlist != store.LineEgressExternal ||
		proxyReadback.FinalEgress != store.LineEgressExternal ||
		proxyReadback.AllowlistCode != store.CodeLineEgressExternalDeclared ||
		proxyReadback.RetryPending {
		t.Fatalf("proxy readback = %+v, want the external declaration", proxyReadback)
	}
}

// TestHTTPProxyURLUpdateDoesNotRepublishTheBoundLines pins the client-chain
// split: the egress endpoint is composed into the subscriber's document at
// download time, so changing it converges nothing on the server side. A Line
// publishes its listener and user set only.
func TestHTTPProxyURLUpdateDoesNotRepublishTheBoundLines(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.DB.Exec(`UPDATE nodes SET status='paired', last_heartbeat=? WHERE id=?`, now.Unix(), lineID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: proxyID}, now); err != nil {
		t.Fatal(err)
	}
	before := candidateCount(t, s, lineID)

	proxy, err := s.SetHTTPProxy(proxyID, "http://bob:n3w@edge.example.invalid:3128", now)
	if err != nil {
		t.Fatalf("proxy URL update: %v", err)
	}
	if proxy.Server != "edge.example.invalid" || proxy.Port != 3128 {
		t.Fatalf("stored proxy projection = %+v, want only host:port", proxy)
	}
	// A Line publishes its listener and user set only, so a changed egress
	// endpoint converges nothing on the server: the next download composes the
	// new dial body from the stored row.
	if got := candidateCount(t, s, lineID); got != before {
		t.Fatalf("proxy URL update republished the line: %d -> %d", before, got)
	}
	var username, password, rawURL string
	if err := s.DB.QueryRow(`SELECT url, username, password FROM node_http_proxy WHERE node_id=?`, proxyID).
		Scan(&rawURL, &username, &password); err != nil {
		t.Fatal(err)
	}
	if rawURL != "http://edge.example.invalid:3128" || username != "bob" || password != "n3w" {
		t.Fatalf("stored proxy = %q/%q/%q", rawURL, username, password)
	}
	// A credential-free URL removes the previous Basic auth instead of leaving a
	// secret the UI no longer shows.
	if _, err := s.SetHTTPProxy(proxyID, "http://edge.example.invalid:3128", now); err != nil {
		t.Fatal(err)
	}
	var nullUser, nullPassword sql.NullString
	if err := s.DB.QueryRow(`SELECT username, password FROM node_http_proxy WHERE node_id=?`, proxyID).
		Scan(&nullUser, &nullPassword); err != nil {
		t.Fatal(err)
	}
	if nullUser.Valid || nullPassword.Valid {
		t.Fatalf("credential-free update kept credentials: %+v/%+v", nullUser, nullPassword)
	}
}

// candidateCount reads how many immutable revisions a node has.
func candidateCount(t *testing.T, s *store.Store, nodeID string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestHTTPProxyCreateValidatesURLAndDisplayName(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	for _, raw := range []string{
		"",
		"proxy.example.invalid:8080",
		"https://proxy.example.invalid:8080",
		"http://proxy.example.invalid",
		"http://proxy.example.invalid:8080/path",
		"http://proxy.example.invalid:8080?query=1",
	} {
		if _, err := s.CreateHTTPProxyNode("proxy", raw, now); err == nil {
			t.Fatalf("URL %q accepted", raw)
		}
	}
	if _, err := s.CreateHTTPProxyNode("", "http://proxy.example.invalid:8080", now); err == nil {
		t.Fatal("empty display name accepted")
	}
	var nodes int
	if err := s.DB.QueryRow(`SELECT count(*) FROM nodes`).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 {
		t.Fatalf("rejected creations wrote %d nodes", nodes)
	}
	if _, err := s.CreateHTTPProxyNode("proxy", "http://proxy.example.invalid:8080", now); err != nil {
		t.Fatalf("credential-free proxy rejected: %v", err)
	}
}

// TestHTTPProxyEgressComposesAndSurvivesArtifact recomposes a saved selection
// through the download path: the HTTP egress remains part of the approved
// artifact without ever entering a client document.
func TestHTTPProxyEgressComposesAndSurvivesArtifact(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, proxyID, subID := httpProxyFixture(t, s, now)
	if _, err := s.DB.Exec(`INSERT INTO policy_rules(stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at)
	  VALUES('custom-proxy-http','1','代理','proxy','domain','["ai.example.invalid"]','custom',?,?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	verifier := &selectionVerifier{}
	result, err := s.ApproveSubscriptionSelection(t.Context(), subID, "", store.SelectionSpec{
		LineIDs: []string{lineID},
		OutID:   proxyID,
		Rules:   []store.RuleRevision{{StableKey: "custom-proxy-http", Version: 1}},
	}, verifier, now)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if result.Preview.Blocking() {
		t.Fatalf("http egress preview blocked: %+v", result.Preview.Diagnostics)
	}
	if !result.Saved {
		t.Fatal("approved http egress selection was not saved")
	}
	documents, artifactID, err := s.SubscriptionArtifact(subID)
	if err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if artifactID == "" || documents.ContentID != artifactID {
		t.Fatalf("artifact id = %q content = %q", artifactID, documents.ContentID)
	}
	// The client chains itself to the egress, so the external proxy endpoint is
	// part of the artifact; it must never be missing from it.
	if !strings.Contains(string(documents.SingBox), "proxy.example.invalid") {
		t.Fatalf("the client document does not name the external proxy: %s", documents.SingBox)
	}
}
