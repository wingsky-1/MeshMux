package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/wingsky-1/MeshMux/internal/core/node/client"
	"slices"
	"strings"
	"testing"
)

// The frozen v1 baseline must never change. The digest pins the exact bytes
// of the v1 document, so a new field, a changed key order or a changed tag
// breaks this test instead of silently changing the active configuration of
// every already deployed node.
const (
	v1GoldenLength = 280
	v1GoldenSHA256 = "abfd6ca429cf402a3a66f9291ac73d4244ae8ecde06e0a1e0953046bcea226ea"
)

const (
	// renderFixturePrivateKey is a synthetic X25519 fixture generated for
	// this test file only. It is not a production key and is never written
	// to a host: the renderer keeps it in memory and the node only ever
	// stores the value the Hub delivered. It is fixed so the rendered bytes
	// and their digest are reproducible across runs.
	renderFixturePrivateKey = "tnILRhHeIrUXzzvieuqqZkSh8BvSiMYsWeZJjyjP8fg"
	renderFixtureShortID    = "0123456789abcdef"
	renderFixtureServerName = "www.example.invalid"
	renderFixtureHandshake  = "handshake.example.invalid"
	renderFixtureHandshakeP = 443
)

func v2Candidate(users ...VLESSUser) Candidate {
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Users = users
	candidate.Reality = &RealityConfig{
		ServerName:      renderFixtureServerName,
		HandshakeServer: renderFixtureHandshake,
		HandshakePort:   renderFixtureHandshakeP,
		PrivateKey:      renderFixturePrivateKey,
		ShortID:         renderFixtureShortID,
	}
	return candidate
}

func v2User(credentialID, uuid string) VLESSUser {
	return VLESSUser{CredentialID: credentialID, UUID: uuid}
}

// decodeRendered decodes a rendered candidate into a generic structure.
//
// A rendered v2 document carries the VLESS UUIDs and the REALITY private
// key, so this test never prints a decoded object, an inbound, a user or a
// rendered document. A failure reports the shape that broke, not the secret
// that broke it.
func decodeRendered(t *testing.T, document []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatal("rendered candidate is not valid JSON")
	}
	return decoded
}

func renderedInbound(t *testing.T, document []byte) map[string]any {
	t.Helper()
	decoded := decodeRendered(t, document)
	inbounds, ok := decoded["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("rendered candidate has no single inbound")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("rendered inbound is not an object")
	}
	return inbound
}

// renderedUsers returns the rendered user objects without ever printing one.
func renderedUsers(t *testing.T, inbound map[string]any) []map[string]any {
	t.Helper()
	raw, ok := inbound["users"].([]any)
	if !ok {
		t.Fatal("rendered inbound has no users array")
	}
	users := make([]map[string]any, 0, len(raw))
	for _, element := range raw {
		user, ok := element.(map[string]any)
		if !ok {
			t.Fatal("rendered user is not an object")
		}
		users = append(users, user)
	}
	return users
}

func TestCompileCandidateV1BaselineBytesAreFrozen(t *testing.T) {
	document, err := CompileCandidate(validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(document)
	if len(document) != v1GoldenLength || hex.EncodeToString(sum[:]) != v1GoldenSHA256 {
		t.Fatalf("frozen v1 candidate changed: length=%d", len(document))
	}
	// The exact shape is pinned as well: the tag keeps the revision, the
	// users array stays present and empty, and the log stays disabled.
	inbound := renderedInbound(t, document)
	if inbound["tag"] != "meshmux-vless-r9" {
		t.Fatal("v1 tag changed")
	}
	users, ok := inbound["users"].([]any)
	if !ok || len(users) != 0 {
		t.Fatal("v1 users array changed")
	}
	if _, ok := inbound["tls"]; ok {
		t.Fatal("v1 candidate gained a TLS block")
	}
}

func TestCompileCandidateV2RendersRealityInbound(t *testing.T) {
	candidate := v2Candidate(v2User(strings.Repeat("1", 32), "11111111-1111-4111-8111-111111111111"))
	document, err := CompileCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeRendered(t, document)
	if log, ok := decoded["log"].(map[string]any); !ok || log["disabled"] != true {
		t.Fatal("v2 candidate does not keep the log disabled")
	}
	outbounds, ok := decoded["outbounds"].([]any)
	if !ok || len(outbounds) != 1 {
		t.Fatal("v2 candidate does not have exactly one outbound")
	}
	outbound, ok := outbounds[0].(map[string]any)
	if !ok || outbound["type"] != "direct" || outbound["tag"] != "direct" {
		t.Fatal("v2 candidate has a wrong outbound")
	}

	inbound := renderedInbound(t, document)
	if inbound["type"] != "vless" || inbound["listen"] != "0.0.0.0" || inbound["listen_port"] != float64(8443) {
		t.Fatal("v2 inbound shape changed")
	}
	// The v2 tag is node scoped and stays stable across revisions and
	// display name changes.
	if inbound["tag"] != "meshmux-vless-"+strings.Repeat("a", 32) {
		t.Fatal("v2 tag is not node scoped")
	}
	revisioned := candidate
	revisioned.Revision = 4242
	other, err := CompileCandidate(revisioned)
	if err != nil {
		t.Fatal(err)
	}
	if renderedInbound(t, other)["tag"] != inbound["tag"] {
		t.Fatal("v2 tag changed with the revision")
	}

	tls, ok := inbound["tls"].(map[string]any)
	if !ok {
		t.Fatal("v2 candidate has no TLS block")
	}
	if tls["enabled"] != true {
		t.Fatal("v2 TLS is not enabled")
	}
	if tls["server_name"] != renderFixtureServerName {
		t.Fatal("v2 server name changed")
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok {
		t.Fatal("v2 candidate has no REALITY block")
	}
	if reality["enabled"] != true {
		t.Fatal("v2 REALITY is not enabled")
	}
	handshake, ok := reality["handshake"].(map[string]any)
	if !ok || handshake["server"] != renderFixtureHandshake || handshake["server_port"] != float64(renderFixtureHandshakeP) {
		t.Fatal("v2 REALITY handshake changed")
	}
	if reality["private_key"] != renderFixturePrivateKey {
		t.Fatal("v2 REALITY private key changed")
	}
	shortIDs, ok := reality["short_id"].([]any)
	if !ok || len(shortIDs) != 1 || shortIDs[0] != renderFixtureShortID {
		t.Fatal("v2 REALITY short id changed")
	}

	users := renderedUsers(t, inbound)
	if len(users) != 1 {
		t.Fatalf("v2 candidate rendered %d users, want 1", len(users))
	}
	user := users[0]
	if user["name"] != strings.Repeat("1", 32) {
		t.Fatal("v2 user name is not the credential id")
	}
	if user["uuid"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("v2 user uuid changed")
	}
	// The flow token is exact. A typo would be rejected by sing-box.
	if user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("v2 flow token = %q, want xtls-rprx-vision", user["flow"])
	}
}

func TestCompileCandidateV2UserOrderIsDeterministic(t *testing.T) {
	first := v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111")
	second := v2User(strings.Repeat("b", 32), "bbbbbbbb-2222-4222-8222-222222222222")
	third := v2User(strings.Repeat("c", 32), "cccccccc-3333-4333-8333-333333333333")

	ordered := v2Candidate(first, second, third)
	shuffled := v2Candidate(third, first, second)
	reversed := v2Candidate(second, third, first)

	reference, err := CompileCandidate(ordered)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]Candidate{"shuffled": shuffled, "reversed": reversed} {
		document, err := CompileCandidate(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if string(document) != string(reference) {
			t.Fatalf("%s credential order changed the rendered bytes", name)
		}
	}
	// The rendered order is the credential id order, not the input order.
	users := renderedUsers(t, renderedInbound(t, reference))
	if len(users) != 3 {
		t.Fatalf("rendered %d users, want 3", len(users))
	}
	for index, want := range []string{
		strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32),
	} {
		if users[index]["name"] != want {
			t.Fatalf("rendered user %d has the wrong credential id", index)
		}
	}
}

func TestCompileCandidateV2SpecificUserRemovalKeepsOthers(t *testing.T) {
	first := v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111")
	second := v2User(strings.Repeat("b", 32), "bbbbbbbb-2222-4222-8222-222222222222")
	third := v2User(strings.Repeat("c", 32), "cccccccc-3333-4333-8333-333333333333")

	before, err := CompileCandidate(v2Candidate(first, second, third))
	if err != nil {
		t.Fatal(err)
	}
	after, err := CompileCandidate(v2Candidate(first, third))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("removing a credential did not change the rendered bytes")
	}
	users := renderedUsers(t, renderedInbound(t, after))
	if len(users) != 2 {
		t.Fatalf("rendered %d users after removal, want 2", len(users))
	}
	for _, user := range users {
		if user["name"] == strings.Repeat("b", 32) {
			t.Fatal("the removed credential is still rendered")
		}
	}
	// The rest of the listener is untouched by a single credential change.
	beforeInbound := renderedInbound(t, before)
	afterInbound := renderedInbound(t, after)
	if beforeInbound["tag"] != afterInbound["tag"] {
		t.Fatal("a credential change moved the inbound tag")
	}
}

func TestCompileCandidateV2EmptyUserSetIsLegal(t *testing.T) {
	candidate := v2Candidate()
	document, err := CompileCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	inbound := renderedInbound(t, document)
	users, ok := inbound["users"].([]any)
	if !ok || len(users) != 0 {
		t.Fatal("an empty credential set must render an empty array")
	}
	// The listener itself stays intact: the REALITY block is still there.
	tls, ok := inbound["tls"].(map[string]any)
	if !ok {
		t.Fatal("the REALITY listener disappeared with the last credential")
	}
	if _, ok := tls["reality"]; !ok {
		t.Fatal("the REALITY block disappeared with the last credential")
	}
}

func TestCompileCandidateV2RejectsInvalidInput(t *testing.T) {
	cases := map[string]Candidate{}
	outNode := v2Candidate(v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"))
	outNode.Role = RoleOut
	cases["out node with users"] = outNode

	usersWithoutReality := validCandidate()
	usersWithoutReality.Role = RoleEdge
	usersWithoutReality.Users = []VLESSUser{
		v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"),
	}
	cases["users without reality"] = usersWithoutReality

	duplicate := v2Candidate(
		v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"),
		v2User(strings.Repeat("a", 32), "bbbbbbbb-2222-4222-8222-222222222222"),
	)
	cases["duplicate credential id"] = duplicate

	duplicateUUID := v2Candidate(
		v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"),
		v2User(strings.Repeat("b", 32), "aaaaaaaa-1111-4111-8111-111111111111"),
	)
	cases["duplicate uuid"] = duplicateUUID

	badUUID := v2Candidate(v2User(strings.Repeat("a", 32), "not-a-uuid"))
	cases["malformed uuid"] = badUUID

	badKey := v2Candidate(v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"))
	badKey.Reality = &RealityConfig{
		ServerName:      renderFixtureServerName,
		HandshakeServer: renderFixtureHandshake,
		HandshakePort:   renderFixtureHandshakeP,
		PrivateKey:      "not-a-key",
		ShortID:         renderFixtureShortID,
	}
	cases["malformed private key"] = badKey

	badPort := v2Candidate(v2User(strings.Repeat("a", 32), "aaaaaaaa-1111-4111-8111-111111111111"))
	badPort.Reality = &RealityConfig{
		ServerName:      renderFixtureServerName,
		HandshakeServer: renderFixtureHandshake,
		HandshakePort:   0,
		PrivateKey:      renderFixturePrivateKey,
		ShortID:         renderFixtureShortID,
	}
	cases["invalid handshake port"] = badPort

	for name, candidate := range cases {
		if _, err := CompileCandidate(candidate); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestCompileCandidateV2LargeUserSetIsDeterministicAndBounded(t *testing.T) {
	users := largeV2UserSet()
	document, err := CompileCandidate(v2Candidate(users...))
	if err != nil {
		t.Fatal(err)
	}
	// The rendered document stays inside the candidate body bound that the
	// Hub transport accepts, so the maximum user set is deliverable.
	if len(document) > client.MaxConfigBody {
		t.Fatalf("rendered candidate is %d bytes, want <= %d", len(document), client.MaxConfigBody)
	}
	shuffled := make([]VLESSUser, 0, len(users))
	for _, user := range slices.Backward(users) {
		shuffled = append(shuffled, user)
	}
	other, err := CompileCandidate(v2Candidate(shuffled...))
	if err != nil {
		t.Fatal(err)
	}
	if string(document) != string(other) {
		t.Fatal("the rendered candidate depends on the credential order")
	}
	largeUsers := renderedUsers(t, renderedInbound(t, document))
	if len(largeUsers) != MaxCandidateUsers {
		t.Fatalf("rendered %d users, want %d", len(largeUsers), MaxCandidateUsers)
	}
}

func TestCompileCandidateV2DocumentFitsTheCandidateBodyBound(t *testing.T) {
	candidate := v2Candidate(largeV2UserSet()...)
	document := NewCandidateDocument(candidate)
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > client.MaxConfigBody {
		t.Fatalf("candidate document is %d bytes, want <= %d", len(body), client.MaxConfigBody)
	}
	var decoded CandidateDocument
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(document) {
		t.Fatal("the candidate document did not survive a round trip")
	}
}

// largeV2UserSet builds the maximum credential set with deterministic
// identifiers. The credentials are synthetic: the test never contacts a
// node and never writes the rendered bytes to a host.
func largeV2UserSet() []VLESSUser {
	users := make([]VLESSUser, 0, MaxCandidateUsers)
	for index := range MaxCandidateUsers {
		users = append(users, v2User(
			fmt.Sprintf("%032x", index+1),
			fmt.Sprintf("%08x-1111-4111-8111-111111111111", index+1),
		))
	}
	return users
}
