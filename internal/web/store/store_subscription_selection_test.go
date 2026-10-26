package store

// The Task-4 storage leg: the four edge tables, the selection snapshot and the
// approved-artifact rule. The tests use a fake verifier, so no kernel binary is
// required; the real `sing-box check` evidence lives in the composer test and in
// the handler gate test.

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// selectionStore opens a store at the current schema.
func selectionStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// selectionFixture inserts one configured Line, one configured Out and one
// active subscriber that selects the Line.
func selectionFixture(t *testing.T, s *Store, now time.Time) (string, string, string) {
	t.Helper()
	lineNode, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	line, err := s.SetLine(testSelectionLine(t, lineNode.ID), now)
	if err != nil {
		t.Fatal(err)
	}
	_ = line
	outNode, _, err := s.CreateNode("out", "out", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetOutTransport(outNode.ID, "out.example.invalid", outNode.VlessPort, now); err != nil {
		t.Fatal(err)
	}
	sub, _, err := s.CreateSubscriber("alice", []string{lineNode.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	return lineNode.ID, outNode.ID, sub.ID
}

// testSelectionLine builds one canonical public Line transport.
func testSelectionLine(t *testing.T, nodeID string) subscription.Line {
	t.Helper()
	pair, err := subscription.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := subscription.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	return subscription.Line{
		NodeID: nodeID, DisplayName: "香港 01", Server: "line.example.invalid", Port: 8443, SortOrder: 1,
		ServerName: "line.example.invalid", HandshakeServer: "handshake.example.invalid", HandshakePort: 443,
		PrivateKey: pair.PrivateKey, PublicKey: pair.PublicKey, ShortID: shortID,
	}
}

// selectionVerifier is a fake kernel gate. It records the documents it saw and
// can fail either kernel.
type selectionVerifier struct {
	singBoxCalls int
	mihomoCalls  int
	singBoxDocs  [][]byte
	mihomoDocs   [][]byte
	failSingBox  bool
	failMihomo   bool
	missingMiho  bool
}

func (v *selectionVerifier) CheckSingBox(_ context.Context, document []byte) (string, error) {
	v.singBoxCalls++
	v.singBoxDocs = append(v.singBoxDocs, append([]byte(nil), document...))
	if v.failSingBox {
		return "", errors.New(node.CodePublishCheckSingBox + ": refused")
	}
	return "sing-box accepted", nil
}

func (v *selectionVerifier) CheckMihomo(_ context.Context, document []byte) (string, error) {
	v.mihomoCalls++
	v.mihomoDocs = append(v.mihomoDocs, append([]byte(nil), document...))
	if v.missingMiho {
		return "", errors.New(node.CodePublishMihomoMissing + ": not installed")
	}
	if v.failMihomo {
		return "", errors.New(node.CodePublishCheckMihomo + ": refused")
	}
	return "mihomo accepted", nil
}

func TestSchema13CreatesSelectionTables(t *testing.T) {
	s := selectionStore(t)
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != DatabaseSchemaVersion {
		t.Fatalf("user_version = %d (const %d)", version, DatabaseSchemaVersion)
	}
	for _, table := range []string{"subscription_lines", "subscription_outs", "subscription_rules", "subscription_networks", "subscription_snapshots"} {
		var name string
		if err := s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("%s missing after migration: %v", table, err)
		}
	}
	// Replaying the migration must not fail on its own earlier write.
	if err := s.Migrate(); err != nil {
		t.Fatalf("replayed Migrate(): %v", err)
	}
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("version after replay = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
}

func TestSaveSubscriptionSelectionWritesEdgesAndSnapshot(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, outID, subID := selectionFixture(t, s, now)

	selection, err := s.SaveSubscriptionSelection(subID, SelectionSpec{
		LineIDs: []string{lineID},
		OutID:   outID,
		Rules:   []RuleRevision{{StableKey: "preset-direct-cn", Version: 1}},
	}, now)
	if err != nil {
		t.Fatalf("SaveSubscriptionSelection: %v", err)
	}
	if len(selection.Lines) != 1 || selection.Lines[0].NodeID != lineID || selection.Lines[0].Position != 0 {
		t.Fatalf("selection lines = %+v", selection.Lines)
	}
	if selection.Out == nil || selection.Out.OutID != outID {
		t.Fatalf("selection out = %+v", selection.Out)
	}
	if len(selection.Rules) != 1 || selection.Rules[0].StableKey != "preset-direct-cn" {
		t.Fatalf("selection rules = %+v", selection.Rules)
	}

	// The four edge tables are the only reference source; the snapshot stores
	// the selection and no rendered byte.
	var selectionJSON string
	if err := s.DB.QueryRow(`SELECT selection_json FROM subscription_snapshots WHERE subscriber_id=?`, subID).Scan(&selectionJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(selectionJSON, "outbounds") || strings.Contains(selectionJSON, "mixed-port") {
		t.Fatalf("snapshot stores rendered bytes: %s", selectionJSON)
	}
	for table, want := range map[string]int{"subscription_lines": 1, "subscription_outs": 1, "subscription_rules": 1, "subscription_networks": 0} {
		var count int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE subscriber_id=?`, subID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s rows = %d, want %d", table, count, want)
		}
	}
}

func TestSaveSubscriptionSelectionKeepsCredentialPerLine(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	before, err := s.ListSubscriberCredentials(subID)
	if err != nil || len(before) != 1 {
		t.Fatalf("credentials = %d err=%v", len(before), err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{LineIDs: []string{lineID}}, now); err != nil {
		t.Fatal(err)
	}
	after, err := s.ListSubscriberCredentials(subID)
	if err != nil || len(after) != 1 {
		t.Fatalf("credentials after save = %d err=%v", len(after), err)
	}
	if after[0].UUID != before[0].UUID {
		t.Fatal("a re-save minted a new UUID for a kept Line")
	}

	// Dropping the Line only deactivates the credential: the UUID stays
	// auditable and is never handed out twice.
	second, _, err := s.CreateNode("edge", "line-2", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLine(testSelectionLine(t, second.ID), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{LineIDs: []string{second.ID}}, now); err != nil {
		t.Fatal(err)
	}
	after, err = s.ListSubscriberCredentials(subID)
	if err != nil || len(after) != 2 {
		t.Fatalf("credentials after switch = %d err=%v", len(after), err)
	}
	active := 0
	for _, credential := range after {
		if credential.NodeID == second.ID {
			if credential.UUID == "" {
				t.Fatal("the new Line has no credential")
			}
			active++
		}
	}
	if active != 1 {
		t.Fatalf("the new Line has %d credentials, want 1", active)
	}
	var droppedActive int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM proxy_credentials WHERE subscriber_id=? AND node_id=? AND active=1`, subID, lineID).Scan(&droppedActive); err != nil {
		t.Fatal(err)
	}
	if droppedActive != 0 {
		t.Fatal("a dropped Line kept an active credential")
	}
}

func TestSaveSubscriptionSelectionRefusesSecondOutAndOutConflict(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, outID, subID := selectionFixture(t, s, now)

	// 1.0 single Out: the table constraint enforces position=0 and one row.
	if _, err := s.DB.Exec(`INSERT INTO subscription_outs(subscriber_id, out_id, position, out_revision, created_at) VALUES(?,?,1,0,0)`, subID, outID); err == nil {
		t.Fatal("a second Out row was accepted")
	}

	// The first subscription records the Line's Out choice.
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{LineIDs: []string{lineID}, OutID: outID}, now); err != nil {
		t.Fatalf("first Out selection: %v", err)
	}
	// A later subscription on the same Line cannot silently keep the Line
	// direct: the Line publishes one route, so the choices must agree.
	second, _, err := s.CreateSubscriber("bob", []string{lineID}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SaveSubscriptionSelection(second.ID, SelectionSpec{LineIDs: []string{lineID}}, now)
	if err == nil || !strings.HasPrefix(err.Error(), CodeOutSelectionConflict) {
		t.Fatalf("conflicting Out selection = %v, want %s", err, CodeOutSelectionConflict)
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Fatalf("conflict does not name the existing subscription: %v", err)
	}
	// Selecting the same Out is accepted.
	if _, err := s.SaveSubscriptionSelection(second.ID, SelectionSpec{LineIDs: []string{lineID}, OutID: outID}, now); err != nil {
		t.Fatalf("matching Out selection: %v", err)
	}
}

func TestSaveSubscriptionSelectionStrictValidation(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, outID, subID := selectionFixture(t, s, now)

	var before int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_lines WHERE subscriber_id=?`, subID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		spec SelectionSpec
		code string
	}{
		{"no lines", SelectionSpec{}, "LINES_REQUIRED"},
		{"unknown line", SelectionSpec{LineIDs: []string{"ffffffffffffffffffffffffffffffff"}}, "LINE_NOT_FOUND"},
		{"line as out", SelectionSpec{LineIDs: []string{lineID}, OutID: lineID}, "OUT_ROLE_INVALID"},
		{"unknown rule", SelectionSpec{LineIDs: []string{lineID}, Rules: []RuleRevision{{StableKey: "missing", Version: 1}}}, "RULE_NOT_FOUND"},
		{"unknown device", SelectionSpec{LineIDs: []string{lineID}, NetworkIDs: []string{"ffffffffffffffffffffffffffffffff"}}, "MESH_DEVICE_NOT_FOUND"},
		{"bad out id", SelectionSpec{LineIDs: []string{lineID}, OutID: "nope"}, CodeSelectionInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.SaveSubscriptionSelection(subID, tc.spec, now)
			if err == nil || !strings.HasPrefix(err.Error(), tc.code) {
				t.Fatalf("save = %v, want %s", err, tc.code)
			}
		})
	}
	// The failed saves must not change the edges the subscriber already had.
	var after int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_lines WHERE subscriber_id=?`, subID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("a failed save changed the edge rows: %d -> %d", before, after)
	}
	_ = outID
}

func TestSelectionUsedByNames(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, outID, subID := selectionFixture(t, s, now)
	device, err := s.CreateMeshDevice(mesh.DeviceSpec{
		DisplayName: "iPad", Purpose: mesh.PurposeMeshOnly, Platform: mesh.PlatformIOS, NodeName: "ipad",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{
		LineIDs:    []string{lineID},
		OutID:      outID,
		Rules:      []RuleRevision{{StableKey: "preset-direct-cn", Version: 1}},
		NetworkIDs: []string{device.ID},
	}, now); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]func(string) ([]string, error){
		"line":    s.LineUsedBy,
		"out":     s.OutUsedBy,
		"network": s.MeshDeviceUsedBy,
	} {
		id := lineID
		switch name {
		case "out":
			id = outID
		case "network":
			id = device.ID
		}
		names, err := query(id)
		if err != nil {
			t.Fatalf("%s used-by: %v", name, err)
		}
		if len(names) != 1 || names[0] != "alice" {
			t.Fatalf("%s used-by = %q, want [alice]", name, names)
		}
	}
}

// TestRuleDeleteRefusedWithSubscriptionName proves the Task-3 delete guard and
// the Task-4 edge table agree: the rule library refuses the delete and names
// the subscription.
func TestRuleDeleteRefusedWithSubscriptionName(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{
		LineIDs: []string{lineID},
		Rules:   []RuleRevision{{StableKey: "preset-direct-cn", Version: 1}},
	}, now); err != nil {
		t.Fatal(err)
	}
	lib := policy.New(s.DB)
	used, err := lib.RuleUsedBy("preset-direct-cn", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 1 || used[0].DisplayName() != "alice" {
		t.Fatalf("rule used-by = %+v, want [alice]", used)
	}
	// The library delete guard reads the same edge: a referenced revision is
	// refused with the subscription name. The preset guard fires first, so a
	// custom rule is used to exercise the reference branch.
	if _, err := lib.CreateCustomRule("custom-cn", "自定义直连", policy.ActionDirect, policy.MatcherGeoSite, []string{"cn"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{
		LineIDs: []string{lineID},
		Rules:   []RuleRevision{{StableKey: "custom-cn", Version: 1}},
	}, now); err != nil {
		t.Fatal(err)
	}
	err = lib.DeleteRule("custom-cn", 1)
	if err == nil || !strings.HasPrefix(err.Error(), policy.CodeReferenced) {
		t.Fatalf("referenced delete = %v, want %s", err, policy.CodeReferenced)
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Fatalf("referenced delete does not name the subscription: %v", err)
	}
}

func TestApproveSubscriptionSelectionRecordsArtifactAndRefusesDrift(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	verifier := &selectionVerifier{}
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, verifier, now)
	if err != nil {
		t.Fatalf("ApproveSubscriptionSelection: %v", err)
	}
	preview := result.Preview
	if !result.Saved || !preview.Approved || preview.ContentID == "" {
		t.Fatalf("result = %+v, want an approved artifact", result)
	}
	if verifier.singBoxCalls != 1 || verifier.mihomoCalls != 1 {
		t.Fatalf("gate calls = %d/%d, want 1/1", verifier.singBoxCalls, verifier.mihomoCalls)
	}
	documents, artifactID, err := s.SubscriptionArtifact(subID)
	if err != nil {
		t.Fatalf("SubscriptionArtifact: %v", err)
	}
	if artifactID != preview.ContentID || len(documents.SingBox) == 0 || len(documents.Mihomo) == 0 {
		t.Fatalf("artifact = %q documents=%d/%d", artifactID, len(documents.SingBox), len(documents.Mihomo))
	}
	// A second recomposition is byte-identical: the download is re-derived.
	again, _, err := s.SubscriptionArtifact(subID)
	if err != nil || string(again.SingBox) != string(documents.SingBox) {
		t.Fatalf("recomposition drifted: err=%v", err)
	}

	// Drift: the stored approval no longer matches the recomposition.
	if _, err := s.DB.Exec(`UPDATE subscription_snapshots SET artifact_id='deadbeef' WHERE subscriber_id=?`, subID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SubscriptionArtifact(subID); err == nil || !strings.HasPrefix(err.Error(), CodeArtifactDrift) {
		t.Fatalf("drifted artifact = %v, want %s", err, CodeArtifactDrift)
	}
}

func TestApproveSubscriptionSelectionRefusesUnapprovedAndFailedGate(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	// A saved selection without an approval cannot be downloaded.
	if _, err := s.SaveSubscriptionSelection(subID, SelectionSpec{LineIDs: []string{lineID}}, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SubscriptionArtifact(subID); err == nil || !strings.HasPrefix(err.Error(), CodeArtifactNotApproved) {
		t.Fatalf("unapproved artifact = %v, want %s", err, CodeArtifactNotApproved)
	}

	// A refusing sing-box gate leaves the artifact unapproved.
	failing := &selectionVerifier{failSingBox: true}
	failedResult, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, failing, now)
	if err != nil {
		t.Fatalf("gate refusal must be a diagnostic, not an error: %v", err)
	}
	if failedResult.Saved || failedResult.Preview.Approved || failedResult.Preview.Code() != CodeComposeGateFailed {
		t.Fatalf("result = %+v, want a blocking %s", failedResult, CodeComposeGateFailed)
	}
	if _, _, err := s.SubscriptionArtifact(subID); err == nil || !strings.HasPrefix(err.Error(), CodeArtifactNotApproved) {
		t.Fatalf("artifact after refused gate = %v, want %s", err, CodeArtifactNotApproved)
	}
}

func TestMihomoAbsentDegradesWithoutBlocking(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	verifier := &selectionVerifier{missingMiho: true}
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, verifier, now)
	if err != nil {
		t.Fatal(err)
	}
	preview := result.Preview
	if !preview.Approved || !preview.MihomoSkipped {
		t.Fatalf("preview = %+v, want approved with the mihomo gate skipped", preview)
	}
	if len(preview.Gates) != 1 || preview.Gates[0] != kernelSingBox {
		t.Fatalf("gates = %q, want [sing-box]", preview.Gates)
	}
	var reminder bool
	for _, diagnostic := range preview.Diagnostics {
		if diagnostic.Code == CodeComposeMihomoSkipped && diagnostic.Level == subscription.DiagnosticReminder {
			reminder = true
		}
	}
	if !reminder {
		t.Fatalf("diagnostics = %+v, want the skipped-gate reminder", preview.Diagnostics)
	}

	// A Mihomo that refuses a document is a blocking failure, not a skip.
	refusing := &selectionVerifier{failMihomo: true}
	refusedResult, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, refusing, now)
	if err != nil {
		t.Fatal(err)
	}
	if refusedResult.Saved || refusedResult.Preview.Code() != CodeComposeGateFailed {
		t.Fatalf("result = %+v, want a blocking gate failure", refusedResult)
	}
}

func TestPreviewSubscriptionSelectionWritesNothing(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	var edgesBefore, snapshotsBefore int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_lines`).Scan(&edgesBefore); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_snapshots`).Scan(&snapshotsBefore); err != nil {
		t.Fatal(err)
	}
	verifier := &selectionVerifier{}
	draft, err := s.DraftSubscriptionSelection(subID, "", SelectionSpec{LineIDs: []string{lineID}})
	if err != nil {
		t.Fatal(err)
	}
	preview := s.PreviewDraftSelection(draft, verifier)
	if !preview.Approved {
		t.Fatalf("preview = %+v, want approved", preview)
	}
	var edges, snapshots int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_lines`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM subscription_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if edges != edgesBefore || snapshots != snapshotsBefore {
		t.Fatalf("preview wrote %d edges and %d snapshots", edges-edgesBefore, snapshots-snapshotsBefore)
	}
}

// TestImplicitRecomputeReadsTheEdgeTable proves the subscriber synchronization
// now derives its Line set from the Task-4 edge table: a reference that has no
// credential row yet is still drained, and a credential row whose edge is gone
// stays in the set so its UUID is removed from the Line.
func TestImplicitRecomputeReadsTheEdgeTable(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(lineIDs) != 1 || lineIDs[0] != lineID {
		t.Fatalf("line set = %q, want [%s]", lineIDs, lineID)
	}

	// Drop the credential row but keep the edge: the selection still names the
	// Line, so the implicit recompute must still target it.
	if _, err := s.DB.Exec(`DELETE FROM proxy_credentials WHERE subscriber_id=?`, subID); err != nil {
		t.Fatal(err)
	}
	tx, err = s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	lineIDs, err = subscriberHistoricalLineIDsTx(tx, subID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(lineIDs) != 1 || lineIDs[0] != lineID {
		t.Fatalf("edge-only line set = %q, want [%s]", lineIDs, lineID)
	}

	// Drop the edge but keep the credential: the historical UUID still has to
	// be removed from the Line, so the Line stays in the set.
	if _, err := s.DB.Exec(`DELETE FROM subscription_lines WHERE subscriber_id=?`, subID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO proxy_credentials(id, subscriber_id, node_id, uuid, active, created_at, updated_at)
	  VALUES('ffffffffffffffffffffffffffffffff',?,?,'11111111-1111-4111-8111-111111111111',0,0,0)`, subID, lineID); err != nil {
		t.Fatal(err)
	}
	tx, err = s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	lineIDs, err = subscriberHistoricalLineIDsTx(tx, subID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(lineIDs) != 1 || lineIDs[0] != lineID {
		t.Fatalf("credential-only line set = %q, want [%s]", lineIDs, lineID)
	}
}
