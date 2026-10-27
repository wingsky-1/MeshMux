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

func TestHTTPProxySelectionRendersHTTPEgressInLineCandidate(t *testing.T) {
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
	candidate, err := s.BuildLineCandidateTx(tx, lineID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Out == nil || candidate.Out.Type != nodedomain.OutEgressHTTP ||
		candidate.Out.Server != "proxy.example.invalid" || candidate.Out.Port != 8080 ||
		candidate.Out.Username != "alice" || candidate.Out.Password != "s3cret" {
		t.Fatalf("line candidate egress = %+v", candidate.Out)
	}
	if candidate.Out.Key != "" || candidate.Out.UUID != "" {
		t.Fatal("http egress carries an SS key or the void UUID")
	}
	// The selection is the only egress slot row (MAX_OUTS = 1).
	var rows int
	if err := tx.QueryRow(`SELECT count(*) FROM subscription_outs WHERE subscriber_id=?`, subID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("egress slot rows = %d, want 1", rows)
	}
	// The rendered candidate is a v3 document carrying the http egress, not a
	// route-free or link-key shape.
	document, err := json.Marshal(nodedomain.NewCandidateDocument(candidate))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"type":"http"`) {
		t.Fatalf("candidate document carries no http egress: %s", document)
	}
	var decoded nodedomain.CandidateDocument
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("rendered candidate does not decode: %v", err)
	}
	if decoded.Out == nil || decoded.Out.Username != "alice" {
		t.Fatalf("decoded candidate egress = %+v", decoded.Out)
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
	// an OUT_NOT_AUTHORIZED / OUT_OFFLINE_FAIL_CLOSED refusal.
	facts, err := s.OutEgressFactsTx(tx, lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Configured || !facts.Available || facts.OutID != proxyID || facts.Code != "" {
		t.Fatalf("http egress facts = %+v", facts)
	}
	state, code, err := s.LineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		t.Fatal(err)
	}
	if state != store.LineEgressExternal || code != "" {
		t.Fatalf("line egress state = %q/%q, want external", state, code)
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
	if strings.Contains(string(documents.SingBox), "proxy.example.invalid") {
		t.Fatal("the external http proxy leaked into the client document")
	}
}
