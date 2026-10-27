package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

func PolicyFixtures() (json.RawMessage, json.RawMessage, json.RawMessage) {
	// The client payload is a legacy read fixture: Task 6 closed the client
	// layer to writes, so it is inserted directly where a preview needs one.
	// It deliberately has no exceptions/ssids (both refused since schema 17).
	client := json.RawMessage(`{"default":"proxy","rules":[{"priority":1000,"match":{"ipcidrs":["100.64.0.0/10"]},"action":"tailscale"}]}`)
	server := json.RawMessage(`{"default":"direct","rules":[{"priority":100,"match":{"geosite":["ai"]},"action":"out"}]}`)
	pins := json.RawMessage(`{"geosite":{"ai":{"source":"https://example.invalid/ai.srs","version":"v1","sha256":"` + strings.Repeat("a", 64) + `"}}}`)
	return client, server, pins
}

// SeedLegacyClientPolicyStore inserts one active client revision for a legacy
// read/preview fixture and returns its id. A previous active client row is
// superseded first, mirroring the layer's one-active invariant.
func SeedLegacyClientPolicyStore(t *testing.T, s *store.Store, payload json.RawMessage, now time.Time) string {
	t.Helper()
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	stamp := now.Unix()
	if _, err := s.DB.Exec(`UPDATE route_policies SET status='superseded', updated_at=? WHERE layer='client' AND status='active'`, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO route_policies(id, revision, layer, name, payload, pins, status, operation_id, created_at, updated_at)
		VALUES(?,1,'client','legacy-client',?,'{}','active','legacy-client',?,?)`,
		id, string(payload), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO route_policy_events(policy_id, revision, kind, from_status, to_status, operation_id, created_at)
		VALUES(?,1,'create','','active','legacy-client',?)`, id, stamp); err != nil {
		t.Fatal(err)
	}
	return id
}

const PublishServerDirect = `{"default":"direct","rules":[]}`

// FixturePublishVerifier is the test double of the kernel gate. It runs no
// binary, so the assembly, gate ordering and refusal semantics are exercised
// without a kernel install, while the recorded documents are still the exact
// bytes the pipeline would have handed to a real kernel.
//
// Two behaviours of the real gate are modelled here on purpose:
//
//   - a missing kernel is a refusal with its own stable code, never a pass;
//   - a rejection carries no document content.
type FixturePublishVerifier struct {
	mu sync.Mutex

	singBoxCalls int
	mihomoCalls  int

	// singBoxDocs and mihomoDocs keep every checked document in order.
	singBoxDocs [][]byte
	mihomoDocs  [][]byte

	// RejectSingBoxAt and RejectMihomoAt fail the n-th (1-based) call.
	RejectSingBoxAt int
	RejectMihomoAt  int

	// MissingSingBox and MissingMihomo make one gate unavailable.
	MissingSingBox bool
	MissingMihomo  bool
}

func (v *FixturePublishVerifier) CheckSingBox(_ context.Context, document []byte) (string, error) {
	return v.check(fixtureSingBoxGate, fixtureGateRun{
		calls:    &v.singBoxCalls,
		docs:     &v.singBoxDocs,
		rejectAt: &v.RejectSingBoxAt,
		missing:  &v.MissingSingBox,
	}, document)
}

func (v *FixturePublishVerifier) CheckMihomo(_ context.Context, document []byte) (string, error) {
	return v.check(fixtureMihomoGate, fixtureGateRun{
		calls:    &v.mihomoCalls,
		docs:     &v.mihomoDocs,
		rejectAt: &v.RejectMihomoAt,
		missing:  &v.MissingMihomo,
	}, document)
}

// fixtureGate names the binary and the stable codes of one kernel. The fixture
// reports the same wording the real gate does.
type fixtureGate struct {
	binary   string
	version  string
	missing  string
	rejected string
}

var (
	fixtureSingBoxGate = fixtureGate{
		binary:   "sing-box",
		version:  node.SingBoxPublishVersion,
		missing:  node.CodePublishSingBoxMissing,
		rejected: node.CodePublishCheckSingBox,
	}
	fixtureMihomoGate = fixtureGate{
		binary:   "mihomo",
		version:  node.MihomoVersion,
		missing:  node.CodePublishMihomoMissing,
		rejected: node.CodePublishCheckMihomo,
	}
)

// fixtureGateRun points at the counters and switches of one kernel, so both
// checks share one implementation while the verifier keeps one field set per
// kernel.
type fixtureGateRun struct {
	calls    *int
	docs     *[][]byte
	rejectAt *int
	missing  *bool
}

// check records one checked document and applies the two refusal rules of the
// real gate: a missing kernel is a refusal with its own stable code, never a
// pass, and a rejection carries no document content.
func (v *FixturePublishVerifier) check(gate fixtureGate, run fixtureGateRun, document []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	(*run.calls)++
	*run.docs = append(*run.docs, append([]byte(nil), document...))
	if *run.missing {
		return "", errors.New(gate.missing + ": the pinned " + gate.binary + " binary is missing")
	}
	if *run.rejectAt == *run.calls {
		return "", errors.New(gate.rejected + ": " + gate.binary + " refused the assembled document")
	}
	return gate.binary + " " + gate.version + " accepted the assembled document", nil
}

// HasSingBoxDocument reports whether one checked document contains needle.
func (v *FixturePublishVerifier) HasSingBoxDocument(needle string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, document := range v.singBoxDocs {
		if strings.Contains(string(document), needle) {
			return true
		}
	}
	return false
}

func (v *FixturePublishVerifier) Counts() (int, int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.singBoxCalls, v.mihomoCalls
}

// PublishFixture is one Hub with a paired Line, stored transport and an active
// server intent, so a publication has a real target.
type PublishFixture struct {
	Store    *store.Store
	Now      time.Time
	Line     string
	LineName string
}

// NewPublishFixture builds the fixture without any Out: the "Line direct"
// configured state, which is the default deployment.
func NewPublishFixture(t *testing.T) PublishFixture {
	t.Helper()
	s, now := SubscriberStore(t)
	line := PairedStoreNode(t, s, "edge", now)
	settings := TestLine(line, "line-a")
	settings.Server = "203.0.113.7"
	settings.ServerName = "line.example.invalid"
	if _, err := s.SetLine(settings, now); err != nil {
		t.Fatal(err)
	}
	MarkLineOnline(t, s, line, now)
	if _, _, err := s.CreateSubscriber("alice", []string{line}, now); err != nil {
		t.Fatal(err)
	}
	SeedInitialChain(t, s, line, now)
	ConfirmChain(t, s, line, now)
	return PublishFixture{Store: s, Now: now, Line: line, LineName: "line-a"}
}

// ActivatePolicy creates and activates one revision for a layer. The client
// layer was closed to writes in Task 6, so its calls insert a legacy revision
// directly: the preview/gate path still needs a row to read, and this is the
// only way such a row can exist after the upgrade.
func (f PublishFixture) ActivatePolicy(t *testing.T, layer store.PolicyLayer, payload, pins string) store.RoutePolicy {
	t.Helper()
	if layer == store.PolicyLayerClient {
		SeedLegacyClientPolicyStore(t, f.Store, json.RawMessage(payload), f.Now)
		return store.RoutePolicy{Layer: layer, Revision: 1}
	}
	if pins == "" {
		pins = `{}`
	}
	created, err := f.Store.CreateRoutePolicy(layer, "策略-"+string(layer),
		json.RawMessage(payload), json.RawMessage(pins), "op-create", f.Now)
	if err != nil {
		t.Fatalf("create %s policy: %v", layer, err)
	}
	active, err := f.Store.ActivateRoutePolicy(created.ID, created.Revision, "op-activate", f.Now)
	if err != nil {
		t.Fatalf("activate %s policy: %v", layer, err)
	}
	return active
}
