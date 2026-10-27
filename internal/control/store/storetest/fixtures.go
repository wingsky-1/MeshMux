// Package storetest holds the fixtures the control/store tests share.
//
// It is test support, not production code: every export here exists only to let
// two test packages open the same store and build the same canonical Line. It
// imports the store root, so no domain package may import it.
package storetest

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	subdomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// SelectionStore opens a store at the current schema and closes it with the
// test.
func SelectionStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// SelectionLine builds one canonical public Line transport.
func SelectionLine(t *testing.T, nodeID string) subdomain.Line {
	t.Helper()
	pair, err := subdomain.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := subdomain.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	return subdomain.Line{
		NodeID: nodeID, DisplayName: "香港 01", Server: "line.example.invalid", Port: 8443, SortOrder: 1,
		ServerName: "line.example.invalid", HandshakeServer: "handshake.example.invalid", HandshakePort: 443,
		PrivateKey: pair.PrivateKey, PublicKey: pair.PublicKey, ShortID: shortID,
	}
}

// SelectionFixture inserts one configured Line, one configured Out and one
// active subscriber that selects the Line. It returns their ids.
func SelectionFixture(t *testing.T, s *store.Store, now time.Time) (string, string, string) {
	t.Helper()
	lineNode, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLine(SelectionLine(t, lineNode.ID), now); err != nil {
		t.Fatal(err)
	}
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

// SubscriberStore opens a private store and returns it with the fixed
// test clock. Every test works on its own temporary directory.
func SubscriberStore(t *testing.T) (*store.Store, time.Time) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := store.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, time.Unix(1_700_000_000, 0)
}

// ResolveBearer is the test-side read of the bearer contract: only an active
// token of an active subscriber resolves. The production download path resolves
// the same rows inside one snapshot transaction.
func ResolveBearer(t *testing.T, s *store.Store, token string) (subdomain.Subscriber, error) {
	t.Helper()
	if err := subdomain.ValidateToken(token); err != nil {
		return subdomain.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	var subscriberID string
	err := s.DB.QueryRow(`SELECT subscriber_id FROM subscription_tokens WHERE token_hash=? AND revoked=0`,
		subdomain.TokenHash(token)).Scan(&subscriberID)
	if errors.Is(err, sql.ErrNoRows) {
		return subdomain.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	if err != nil {
		return subdomain.Subscriber{}, errors.New("DATABASE_UNAVAILABLE")
	}
	sub, err := s.GetSubscriber(subscriberID)
	if err != nil {
		if strings.HasPrefix(err.Error(), "SUBSCRIBER_NOT_FOUND") {
			return subdomain.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
		}
		return subdomain.Subscriber{}, err
	}
	if sub.State != subdomain.StateActive {
		return subdomain.Subscriber{}, errors.New("TOKEN_INVALID: unknown or expired subscription token")
	}
	return sub, nil
}

// ReadStoredLine returns one stored Line through the production list path. It
// keeps the old single-row assertions while the single-row getter is gone.
func ReadStoredLine(t *testing.T, s *store.Store, nodeID string) (subdomain.Line, error) {
	t.Helper()
	lines, err := s.ListLines()
	if err != nil {
		return subdomain.Line{}, err
	}
	for _, line := range lines {
		if line.NodeID == nodeID {
			return line, nil
		}
	}
	return subdomain.Line{}, errors.New("LINE_NOT_FOUND: unknown line")
}

// CreateEdgeNode inserts one edge node so it can be used as a proxy Line.
// The display name is a fixed short label: it must fit the node name policy.
func CreateEdgeNode(t *testing.T, s *store.Store, now time.Time) string {
	t.Helper()
	node, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// CreateOutNode inserts one out node; it can never serve a proxy Line.
func CreateOutNode(t *testing.T, s *store.Store, now time.Time) string {
	t.Helper()
	node, _, err := s.CreateNode("out", "out", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}
	return node.ID
}

// TestLine returns a valid Line transport for one node. The port matches the
// VLESS port of the fixture nodes.
func TestLine(nodeID, name string) subdomain.Line {
	pair, err := subdomain.NewRealityKeyPair()
	if err != nil {
		panic(err)
	}
	shortID, err := subdomain.NewShortID()
	if err != nil {
		panic(err)
	}
	return subdomain.Line{
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

// ConfigureLine stores a Line transport for one edge node.
func ConfigureLine(t *testing.T, s *store.Store, nodeID, name string, now time.Time) subdomain.Line {
	t.Helper()
	line, err := s.SetLine(TestLine(nodeID, name), now)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// HasErrorCode reports whether the sanitized error carries the given stable
// error code.
func HasErrorCode(err error, code string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), code)
}

// hubDatabaseRecord writes the per-operation Hub database backup record the gate
// and the irreversible-confirmation action read. It is metadata only and 0600;
// the payload is one private database copy, because an approval must never
// confirm a record that holds nothing to restore. The record lives at
// <data-dir>/database-backup/<op32hex>/record.json, never in the flat pointer.
func HubDatabaseRecord(t *testing.T, dataDir, operationID string, mutate func(*backup.Record)) (string, backup.Record) {
	t.Helper()
	root := filepath.Join(dataDir, store.DatabaseBackupDirName)
	opDir := filepath.Join(root, operationID)
	payload := filepath.Join(opDir, store.DatabaseBackupPayloadDirName)
	if err := os.MkdirAll(payload, 0700); err != nil {
		t.Fatal(err)
	}
	// The payload bytes are a fixture copy, never opened by the approval path.
	if err := os.WriteFile(filepath.Join(payload, "meshmux.db"), []byte("fixture database copy"), 0600); err != nil {
		t.Fatal(err)
	}
	record := backup.Record{
		Schema: backup.RecordSchema, OperationID: operationID,
		FromVersion: "1.0.0", TargetVersion: "1.0.1",
		DBSchema: store.DatabaseSchemaVersion - 1, PolicySchema: upgrade.PolicySchema,
		ManifestSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64),
		PayloadPath: payload, PayloadSHA256: strings.Repeat("c", 64),
		PayloadFiles: 1, IntegrityOK: true, State: backup.StateStaged,
		CreatedAt: time.Now().UTC(),
	}
	if mutate != nil {
		mutate(&record)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(opDir, store.DatabaseBackupRecordName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, record
}

func ReadStoredDatabaseRecord(t *testing.T, path string) backup.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record backup.Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("stored record is not JSON: %v", err)
	}
	return record
}

// enrollNodeIdentity records a valid, unrevoked Agent identity for one node.
// A Line without an identity is not enrolled and can never serve a
// credential.
func EnrollNodeIdentity(t *testing.T, s *store.Store, nodeID string, now time.Time) {
	t.Helper()
	if _, err := s.DB.Exec(`INSERT INTO node_identities(node_id, token_hash, created_at, revoked) VALUES(?,?,?,0)`,
		nodeID, store.TokenHash(store.RandomToken()), now.Unix()); err != nil {
		t.Fatal(err)
	}
}
func PublishConvergedCandidate(t *testing.T, s *store.Store, nodeID string, line subdomain.Line, credentials []subdomain.Credential, now time.Time) {
	t.Helper()
	users := make([]node.VLESSUser, 0, len(credentials))
	for _, credential := range credentials {
		users = append(users, node.VLESSUser{CredentialID: credential.ID, UUID: credential.UUID})
	}
	reality := &node.RealityConfig{
		ServerName:      line.ServerName,
		HandshakeServer: line.HandshakeServer,
		HandshakePort:   line.HandshakePort,
		PrivateKey:      line.PrivateKey,
		ShortID:         line.ShortID,
	}
	var revision int64
	if err := s.DB.QueryRow(`SELECT COALESCE(MAX(revision),0)+1 FROM node_candidates WHERE node_id=?`, nodeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	candidate := node.Candidate{
		NodeID:        nodeID,
		Role:          node.RoleEdge,
		Revision:      revision,
		VLESSPort:     8443,
		KernelVersion: node.KernelVersion,
		Users:         users,
		Reality:       reality,
	}
	document, err := json.Marshal(node.NewCandidateDocument(candidate))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := store.CandidateSHA256(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO node_candidates(node_id, revision, candidate_json, config_sha256, created_at) VALUES(?,?,?,?,?)`,
		nodeID, candidate.Revision, document, digest, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE nodes SET status='paired', last_heartbeat=?, observed_revision=?, observed_config_sha256=?,
	 observed_at=?, updated_at=? WHERE id=?`, now.Unix(), candidate.Revision, digest, now.Unix(), now.Unix(), nodeID); err != nil {
		t.Fatal(err)
	}
}

// downloadLineFixture returns a valid Line transport for one node. The port
// matches the VLESS port of the fixture nodes.
func DownloadLineFixture(t *testing.T, nodeID, name string) subdomain.Line {
	t.Helper()
	pair, err := subdomain.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := subdomain.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	return subdomain.Line{
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

// publishConvergedCandidate writes the next candidate revision of one Line
// and records the matching readback evidence on the node.
// enrollNodeIdentity records a valid, unrevoked Agent identity for one node.
// A Line without an identity is not enrolled and can never serve a
// credential.
func DownloadFixture(t *testing.T, s *store.Store, now time.Time) (string, subdomain.Line, subdomain.Subscriber, string, subdomain.Credential) {
	t.Helper()
	created, _, err := s.CreateNode("edge", "line", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := created.ID
	EnrollNodeIdentity(t, s, nodeID, now)
	line, err := s.SetLine(DownloadLineFixture(t, nodeID, "line-a"), now)
	if err != nil {
		t.Fatal(err)
	}
	sub, bearer, err := s.CreateSubscriber("alice", []string{nodeID}, now)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.ListSubscriberCredentials(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("expected one credential, got %d", len(credentials))
	}
	PublishConvergedCandidate(t, s, nodeID, line, credentials, now)
	return nodeID, line, sub, bearer, credentials[0]
}
