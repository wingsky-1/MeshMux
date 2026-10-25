package web

// HTTP tests for the explicit release check and the gated approval of one
// target per node (#11c-1 Task 6). The check never mutates; the approval is the
// only path that writes a 11b record, and it stamps the pending config.stage row
// in the same transaction as the chain, so the Agent's first poll cannot see an
// unstamped row.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// upgradeApproveFixture pairs one Line whose initial chain already finished, so
// an approval has no unfinished chain to refuse. observed is the Agent version
// the Hub last read back: a mixed-version fleet fixture, because the readback
// validator of this build only accepts its own version.
func upgradeApproveFixture(t *testing.T, observed string) (b *browser, app *Server, nodeID, token string) {
	t.Helper()
	app, _ = testApp(t)
	created, code := createPendingNode(t, app, "edge", "upgrade-approve", 8443, 2222)
	pairing := pairJSON(t, app, created.ID, "edge", code)
	requireStatus(t, pairing, http.StatusOK)
	var paired struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(pairing.Body.Bytes(), &paired); err != nil || paired.IdentityToken == "" {
		t.Fatalf("pairing did not issue an identity: %.200s", pairing.Body.String())
	}
	confirmChain(t, app.store, created.ID, app.now())
	if _, err := app.store.db.Exec(`UPDATE nodes SET observed_agent_version=?, observed_at=? WHERE id=?`,
		observed, app.now().Unix(), created.ID); err != nil {
		t.Fatal(err)
	}
	b = &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)
	return b, app, created.ID, paired.IdentityToken
}

func latestRevision(t *testing.T, app *Server, nodeID string) int64 {
	t.Helper()
	stored, err := app.store.latestCandidate(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return stored.Revision
}

func countStamped(t *testing.T, app *Server, nodeID string) int {
	t.Helper()
	var count int
	if err := app.store.db.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND target_version<>''`,
		nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func decodeApprove(t *testing.T, w *httptest.ResponseRecorder, status int) upgradeApproveReceipt {
	t.Helper()
	requireStatus(t, w, status)
	var receipt upgradeApproveReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("approval receipt: %v %.300s", err, w.Body.String())
	}
	if receipt.OperationID == "" {
		t.Fatal("approval receipt carries no operation id")
	}
	return receipt
}

func approveUpgrade(t *testing.T, b *browser, nodeID, version string) *httptest.ResponseRecorder {
	t.Helper()
	return b.post("/tasks/approve", url.Values{"node_id": {nodeID}, "version": {version}})
}

// seedUpgradeRouteIntent gives one node a configured Line transport and an
// active server policy, so the next approval re-derives a resolved v3 route
// from the live intent (the approval no longer copies a previous candidate's
// route).
func seedUpgradeRouteIntent(t *testing.T, app *Server, nodeID string) {
	t.Helper()
	now := app.now()
	if _, err := app.store.setLine(testLine(nodeID, "upgrade-line"), now); err != nil {
		t.Fatal(err)
	}
	created, err := app.store.createRoutePolicy(PolicyLayerServer, "升级服务端策略",
		json.RawMessage(publishServerDirect), nil, "op-upgrade-policy", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.activateRoutePolicy(created.ID, created.Revision, "op-upgrade-activate", now); err != nil {
		t.Fatal(err)
	}
}

// TestCheckUpdateIsAdvisoryOnly pins the explicit button: one operator click
// queries the latest release, the page reports it as unverified, and nothing is
// stored, approved or enqueued. A failed query is shown as unknown instead of a
// guessed version, and an unverified tag can never be approved.
func TestCheckUpdateIsAdvisoryOnly(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	app.releaseSource = func(context.Context) (string, error) { return "1.0.1", nil }
	before := latestRevision(t, app, nodeID)

	w := b.req("GET", "/tasks/check", nil, nil)
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{"1.0.1", "未验证", "仅提示", "检查新版本"} {
		if !strings.Contains(body, want) {
			t.Fatalf("check page is missing %q", want)
		}
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("check changed the candidate revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("check wrote %d upgrade records, want 0", got)
	}

	// A failed query is unknown, never a cached or guessed release.
	app.releaseSource = func(context.Context) (string, error) { return "", errors.New("unreachable") }
	w = b.req("GET", "/tasks/check", nil, nil)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "无法确认") {
		t.Fatal("failed check did not state that the release is unknown")
	}

	// The check is an authenticated operator action.
	if got := (&browser{app: app}).req("GET", "/tasks/check", nil, nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated check status=%d, want 401", got.Code)
	}

	// Approving the unverified tag is refused and stores nothing.
	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, "1.0.1"), http.StatusConflict)
	if receipt.OK || receipt.ErrorCode != codeUpgradeManifestUnavailable {
		t.Fatalf("unverified approval = %+v, want MANIFEST_UNAVAILABLE", receipt)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("refused approval wrote %d upgrade records", got)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused approval changed the candidate revision: %d -> %d", before, got)
	}
}

// TestApproveEnqueuesStampedChain pins the single transaction: the approved
// release becomes one new candidate revision plus the fixed four-task chain, and
// the pending config.stage row of that very chain carries the pinned target.
func TestApproveEnqueuesStampedChain(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(sum[:])
	before := latestRevision(t, app, nodeID)

	approval := approveUpgrade(t, b, nodeID, manifest.Version)
	receipt := decodeApprove(t, approval, http.StatusOK)
	if !receipt.OK || receipt.Status != "queued" {
		t.Fatalf("approval = %+v, want queued", receipt)
	}
	if receipt.Target != manifest.Version || receipt.ManifestSHA256 != wantSHA {
		t.Fatalf("approval pins %q/%q, want %q/%q", receipt.Target, receipt.ManifestSHA256, manifest.Version, wantSHA)
	}
	if receipt.PolicySchema != upgrade.PolicySchema {
		t.Fatalf("policy_schema = %d, want %d", receipt.PolicySchema, upgrade.PolicySchema)
	}
	if len(receipt.RoutePolicyRevisions) != 2 {
		t.Fatalf("route_policy_revisions = %v, want the client and server layers", receipt.RoutePolicyRevisions)
	}
	if receipt.Revision != before+1 || len(receipt.Tasks) != len(protocol.PublicationKinds) {
		t.Fatalf("approval revision/tasks = %d/%v", receipt.Revision, receipt.Tasks)
	}
	// The receipt advertises only what was actually enqueued. There is no
	// "order"/"hub first" claim: the Hub upgrades itself in 11d, so promising a
	// Hub step here would be a receipt that overstates.
	if strings.Contains(approval.Body.String(), `"order"`) {
		t.Fatalf("receipt advertises an order it did not create: %s", approval.Body.String())
	}
	if receipt.StageOperationID == "" {
		t.Fatal("approval receipt does not name the stamped stage row")
	}

	// The chain exists exactly once, all four steps pending after the commit.
	var pending int
	if err := app.store.db.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status='pending'`,
		nodeID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != len(protocol.PublicationKinds) {
		t.Fatalf("pending tasks = %d, want %d", pending, len(protocol.PublicationKinds))
	}
	// The four pending rows are one chain of the approved candidate revision.
	var chained int
	if err := app.store.db.QueryRow(`SELECT count(*) FROM agent_tasks WHERE node_id=? AND status='pending' AND params LIKE ?`,
		nodeID, `%"revision":`+strconv.FormatInt(receipt.Revision, 10)+`%`).Scan(&chained); err != nil {
		t.Fatal(err)
	}
	if chained != len(protocol.PublicationKinds) {
		t.Fatalf("pending tasks of revision %d = %d, want %d", receipt.Revision, chained, len(protocol.PublicationKinds))
	}
	// The stage row of the same chain carries the pinned target, so the first
	// poll after this commit already sees the upgrade.
	var gotVersion, gotManifest, gotOperation string
	var gotPolicy int
	var gotTargetRevision int64
	if err := app.store.db.QueryRow(`SELECT operation_id, target_version, target_manifest_sha256, policy_schema, target_revision
 FROM agent_tasks WHERE node_id=? AND kind=? AND status='pending' AND target_version<>''`,
		nodeID, protocol.KindConfigStage).Scan(&gotOperation, &gotVersion, &gotManifest, &gotPolicy, &gotTargetRevision); err != nil {
		t.Fatal(err)
	}
	if gotOperation != receipt.StageOperationID || gotVersion != manifest.Version || gotManifest != wantSHA ||
		gotPolicy != upgrade.PolicySchema || gotTargetRevision != receipt.Revision {
		t.Fatalf("stamped stage = %q %q %q %d %d", gotOperation, gotVersion, gotManifest, gotPolicy, gotTargetRevision)
	}
	if got := countStamped(t, app, nodeID); got != 1 {
		t.Fatalf("stamped rows = %d, want exactly one", got)
	}
}

// TestApprovePinsObservedArchitecture pins U4 on the approval side: the Hub
// stamps the manifest projection of the target node's read-back architecture,
// not blindly its own. A node behind a Hub of another architecture therefore
// verifies the bytes it selects from the same served set.
func TestApprovePinsObservedArchitecture(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	if _, err := app.store.db.Exec(`UPDATE nodes SET observed_architecture=? WHERE id=?`, otherArch, nodeID); err != nil {
		t.Fatal(err)
	}
	manifest, err := upgrade.ForArch(otherArch)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(sum[:])

	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusOK)
	if receipt.ManifestSHA256 != wantSHA {
		t.Fatalf("approval pins %q, want the %s projection %q", receipt.ManifestSHA256, otherArch, wantSHA)
	}
	var stored string
	if err := app.store.db.QueryRow(`SELECT target_manifest_sha256 FROM agent_tasks
 WHERE node_id=? AND target_version<>''`, nodeID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != wantSHA {
		t.Fatalf("stamped manifest = %q, want %q", stored, wantSHA)
	}
}

// TestUpgradeApproveRefusesInFlightChain pins the single-flight guard: a second
// approval while the first chain is unfinished is refused, the live revision is
// untouched and the previous target stays the only record.
func TestUpgradeApproveRefusesInFlightChain(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	first := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusOK)
	live := latestRevision(t, app, nodeID)

	second := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusConflict)
	if second.OK || second.ErrorCode != "TASKS_IN_PROGRESS" {
		t.Fatalf("second approval = %+v, want TASKS_IN_PROGRESS", second)
	}
	if got := latestRevision(t, app, nodeID); got != live || got != first.Revision {
		t.Fatalf("previous revision did not stay live: %d, want %d", got, first.Revision)
	}
	if got := countStamped(t, app, nodeID); got != 1 {
		t.Fatalf("stamped rows = %d, want the first chain only", got)
	}
}

// TestUpgradeMixedVersionGate pins the mixed-version rule twice: as the pure
// gate, and end to end on a node whose latest candidate already carries a v3
// route. A v3 document only reaches a node that reports this build; an older
// read-back is refused with a stable code and stores nothing.
func TestUpgradeMixedVersionGate(t *testing.T) {
	v3 := node.Candidate{Route: json.RawMessage(`{"rules":[],"final":"direct"}`)}
	v1 := node.Candidate{}
	for _, tc := range []struct {
		name      string
		candidate node.Candidate
		observed  string
		want      string
	}{
		{"v3 to the shipping build", v3, node.CurrentAgentVersion(), ""},
		{"v3 to an older build", v3, "0.9.0", codeUpgradeAgentIncompatible},
		{"v3 to an unknown build", v3, "", codeUpgradeAgentIncompatible},
		{"v1 to an older build", v1, "0.9.0", ""},
	} {
		err := mixedVersionGate(tc.candidate, tc.observed)
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %s", tc.name, err, tc.want)
		}
	}

	// A node without a read-back version is excluded from the approval control:
	// the Hub does not guess which schema it can consume.
	view := upgradeSnapshot{}
	if !view.targetExcluded(Node{ID: "unknown"}) {
		t.Fatal("a node without a read-back version was offered an approval")
	}
	if view.targetExcluded(Node{ID: "older", ObservedAgentVersion: "0.9.0"}) {
		t.Fatal("a mixed-version node was hidden instead of labelled")
	}

	// End to end: the approval resolves a v3 route from the live policy, and an
	// older node is refused instead of being force-published.
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	seedUpgradeRouteIntent(t, app, nodeID)
	before := latestRevision(t, app, nodeID)
	refusal := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusConflict)
	if refusal.OK || refusal.ErrorCode != codeUpgradeAgentIncompatible {
		t.Fatalf("v3 approval for an older node = %+v, want UPGRADE_AGENT_INCOMPATIBLE", refusal)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused v3 approval advanced the revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("refused v3 approval wrote %d upgrade records", got)
	}
}

// TestUpgradeApproveAllowsRetryAfterFailedChain pins that a terminal failure
// frees the node: the same target may be approved again, because a failed chain
// is not an unfinished one, and the new attempt is its own revision.
func TestUpgradeApproveAllowsRetryAfterFailedChain(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	first := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusOK)
	// The Agent reports the stage step failed, which ends that chain.
	if _, err := app.store.db.Exec(`UPDATE agent_tasks SET status='failed' WHERE node_id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	second := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusOK)
	if second.Revision <= first.Revision {
		t.Fatalf("retry revision = %d, want above %d", second.Revision, first.Revision)
	}
	if got := countStamped(t, app, nodeID); got != 2 {
		t.Fatalf("stamped rows = %d, want both attempts recorded", got)
	}
	// The history collapses the duplicate, so a retry does not fake a release.
	tx, err := app.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	history, err := approvedReleaseChainTx(tx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0] != manifest.Version {
		t.Fatalf("approved history = %v, want one release", history)
	}
}

// TestUpgradeApproveRefusesUnobservedNode pins the exclusion the page shows: a
// node without a read-back version cannot be approved, because the Hub cannot
// tell which candidate schema it consumes.
func TestUpgradeApproveRefusesUnobservedNode(t *testing.T) {
	b, app, nodeID, _ := upgradeApproveFixture(t, "")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	before := latestRevision(t, app, nodeID)
	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusConflict)
	if receipt.OK || receipt.ErrorCode != "UPGRADE_AGENT_UNOBSERVED" {
		t.Fatalf("unobserved approval = %+v, want UPGRADE_AGENT_UNOBSERVED", receipt)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused approval advanced the revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("refused approval wrote %d upgrade records", got)
	}
}

// TestUpgradeApproveRefusesUnknownNodeAndBadVersion pins the two request-shape
// refusals before any read.
func TestUpgradeApproveRefusesUnknownNodeAndBadVersion(t *testing.T) {
	b, _, nodeID, _ := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeApprove(t, approveUpgrade(t, b, strings.Repeat("f", 32), manifest.Version), http.StatusNotFound); got.ErrorCode != "NODE_NOT_FOUND" {
		t.Fatalf("unknown node = %+v", got)
	}
	if got := decodeApprove(t, approveUpgrade(t, b, "not-a-node", manifest.Version), http.StatusBadRequest); got.ErrorCode != codeUpgradeTargetInvalid {
		t.Fatalf("malformed node = %+v", got)
	}
	if got := decodeApprove(t, approveUpgrade(t, b, nodeID, "latest"), http.StatusBadRequest); got.ErrorCode != codeUpgradeTargetInvalid {
		t.Fatalf("floating version = %+v", got)
	}
	// The approval is a CSRF-protected management POST.
	if w := (&browser{app: b.app}).post("/tasks/approve", url.Values{"node_id": {nodeID}, "version": {manifest.Version}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated approval status=%d, want 401", w.Code)
	}
}

// TestApproveRefusedUntilHubSelfUpgrade pins the self-version boundary and the
// page's claim: a node already reporting this build is refused as
// UPGRADE_ALREADY_CURRENT (nothing written), and the page says a *newer* release
// needs 11d plus real pins. Approving a lagging node is a separate, intended
// path covered by TestApproveEnqueuesStampedChain.
func TestApproveRefusedUntilHubSelfUpgrade(t *testing.T) {
	// A node that already reports this build.
	b, app, nodeID, _ := upgradeApproveFixture(t, node.CurrentAgentVersion())
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	before := latestRevision(t, app, nodeID)
	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusConflict)
	if receipt.OK || receipt.ErrorCode != "UPGRADE_ALREADY_CURRENT" {
		t.Fatalf("self-version approval = %+v, want UPGRADE_ALREADY_CURRENT", receipt)
	}
	if got := latestRevision(t, app, nodeID); got != before {
		t.Fatalf("refused approval advanced the revision: %d -> %d", before, got)
	}
	if got := countStamped(t, app, nodeID); got != 0 {
		t.Fatalf("refused approval wrote %d upgrade records", got)
	}

	// The page states the boundary instead of letting the operator discover it
	// through a refusal.
	app.releaseSource = func(context.Context) (string, error) { return manifest.Version, nil }
	// The page states the boundary precisely: newer releases need 11d, while a
	// lagging node is still approvable to this Hub's release.
	body := b.req("GET", "/tasks/check", nil, nil).Body.String()
	for _, want := range []string{"11d", "无法批准", "落后于本机的节点仍可批准"} {
		if !strings.Contains(body, want) {
			t.Fatalf("check page does not state %q", want)
		}
	}
	if strings.Contains(body, "不会有可成功的升级") {
		t.Fatal("check page claims no upgrade can succeed")
	}
}

// TestAgentUpgradeTargetReadsPersistedStamp pins the Agent read of the stamp:
// the node reads its own stage row regardless of the row status (the stamp is
// written while the row is pending), and another node or an unstamped row is
// not found.
func TestAgentUpgradeTargetReadsPersistedStamp(t *testing.T) {
	b, app, nodeID, token := upgradeApproveFixture(t, "0.9.0")
	manifest, err := upgrade.ForArch(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	receipt := decodeApprove(t, approveUpgrade(t, b, nodeID, manifest.Version), http.StatusOK)

	w := bearerReq(app, "GET", "/api/agent/upgrade-target/"+receipt.StageOperationID, token, nil)
	requireStatus(t, w, http.StatusOK)
	var target struct {
		TargetVersion  string `json:"target_version"`
		ManifestSHA256 string `json:"manifest_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatalf("target body: %v %.200s", err, w.Body.String())
	}
	if target.TargetVersion != manifest.Version || target.ManifestSHA256 != receipt.ManifestSHA256 {
		t.Fatalf("target = %+v, want %q/%q", target, manifest.Version, receipt.ManifestSHA256)
	}

	// A row that already moved on keeps its stamp: the read is not pending-only.
	if _, err := app.store.db.Exec(`UPDATE agent_tasks SET status='healthy' WHERE operation_id=?`, receipt.StageOperationID); err != nil {
		t.Fatal(err)
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/"+receipt.StageOperationID, token, nil); got.Code != http.StatusOK {
		t.Fatalf("stamped healthy row status=%d, want 200", got.Code)
	}

	// An unstamped stage row and an unknown id are both not found.
	var unstamped string
	if err := app.store.db.QueryRow(`SELECT operation_id FROM agent_tasks WHERE node_id=? AND kind=? AND target_version='' LIMIT 1`,
		nodeID, protocol.KindConfigStage).Scan(&unstamped); err != nil {
		t.Fatal(err)
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/"+unstamped, token, nil); got.Code != http.StatusNotFound {
		t.Fatalf("unstamped row status=%d, want 404", got.Code)
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/"+strings.Repeat("a", 32), token, nil); got.Code != http.StatusNotFound {
		t.Fatalf("unknown row status=%d, want 404", got.Code)
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/not-a-hex-id", token, nil); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed id status=%d, want 400", got.Code)
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/"+receipt.StageOperationID, "", nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated read status=%d, want 401", got.Code)
	}
	// Another node's identity cannot read this row, so the channel never
	// discloses that some other node is being upgraded.
	other, otherCode := createPendingNode(t, app, "edge", "upgrade-other", 8444, 2223)
	otherPairing := pairJSON(t, app, other.ID, "edge", otherCode)
	requireStatus(t, otherPairing, http.StatusOK)
	var otherPaired struct {
		IdentityToken string `json:"identity_token"`
	}
	if err := json.Unmarshal(otherPairing.Body.Bytes(), &otherPaired); err != nil || otherPaired.IdentityToken == "" {
		t.Fatalf("second pairing did not issue an identity: %.200s", otherPairing.Body.String())
	}
	if got := bearerReq(app, "GET", "/api/agent/upgrade-target/"+receipt.StageOperationID, otherPaired.IdentityToken, nil); got.Code != http.StatusNotFound {
		t.Fatalf("foreign node read status=%d, want 404", got.Code)
	}
}
