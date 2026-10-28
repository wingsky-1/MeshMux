package spec

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// outLinkKeyFixture is one canonical 16-byte link key, repeated here because
// the render package tests own the renderer fixture.
const outLinkKeyFixture = "MDEyMzQ1Njc4OWFiY2RlZg=="

// testRealityPrivateKey returns a freshly generated X25519 private key in the
// canonical unpadded base64url form. The key is generated per test run so no
// key material is stored in the repository.
func testRealityPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes())
}

func testReality(t *testing.T) *RealityConfig {
	t.Helper()
	return &RealityConfig{
		ServerName:      "www.example.invalid",
		HandshakeServer: "www.example.invalid",
		HandshakePort:   443,
		PrivateKey:      testRealityPrivateKey(t),
		ShortID:         "0123456789abcdef",
	}
}

func testV2Candidate(t *testing.T) Candidate {
	t.Helper()
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Users = []VLESSUser{{
		CredentialID: strings.Repeat("1", 32),
		UUID:         "9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d",
	}}
	candidate.Reality = testReality(t)
	return candidate
}

func TestCandidateV1DocumentBytesStayFrozen(t *testing.T) {
	document := NewCandidateDocument(validCandidate())
	if document.Schema != CandidateSchema {
		t.Fatalf("baseline schema = %q, want %q", document.Schema, CandidateSchema)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"meshmux-node/v1","node_id":"` + strings.Repeat("a", 32) +
		`","role":"out","revision":9,"vless_port":8443,"kernel_version":"` + KernelVersion + `"}`
	if string(body) != want {
		t.Fatalf("frozen v1 bytes = %s, want %s", body, want)
	}
	indented, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(indented), "{\n  \"schema\": \"meshmux-node/v1\",\n  \"node_id\":") {
		t.Fatalf("v1 indentation changed: %s", indented)
	}
	if strings.Contains(string(indented), "users") || strings.Contains(string(indented), "reality") {
		t.Fatalf("v1 document leaked the v2 blocks: %s", indented)
	}
}

func TestCandidateOptionalBlocksRoundTrip(t *testing.T) {
	candidate := testV2Candidate(t)
	document := NewCandidateDocument(candidate)
	if document.Schema != CandidateSchema {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchema)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"schema":"meshmux-node/v1"`,
		`"users":[{"credential_id":"` + strings.Repeat("1", 32) + `","uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"}]`,
		`"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid","handshake_port":443,"private_key":"`,
		`"short_id":"0123456789abcdef"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("v2 document is missing %s: %s", want, body)
		}
	}

	var decoded CandidateDocument
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != CandidateSchema {
		t.Fatalf("decoded schema = %q", decoded.Schema)
	}
	if !decoded.Candidate().Equal(candidate) {
		t.Fatalf("decoded candidate = %+v, want %+v", decoded.Candidate(), candidate)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateEmptyUsersAreLegalAndOmitted(t *testing.T) {
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Reality = testReality(t)
	document := NewCandidateDocument(candidate)
	if document.Schema != CandidateSchema {
		t.Fatalf("schema = %q, want %q", document.Schema, CandidateSchema)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"users"`) {
		t.Fatalf("an empty optional users block was emitted: %s", body)
	}
	explicit := `{"schema":"meshmux-node/v1","node_id":"` + strings.Repeat("a", 32) +
		`","role":"edge","revision":9,"vless_port":8443,"kernel_version":"` + KernelVersion +
		`","users":[],"reality":` + mustJSON(t, testReality(t)) + `}`
	var decoded CandidateDocument
	if err := json.Unmarshal([]byte(explicit), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Users) != 0 || decoded.Users == nil {
		t.Fatalf("decoded users = %#v, want an empty array", decoded.Users)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCandidateMarshalFailsClosedOnInvalidShapes(t *testing.T) {
	users := []VLESSUser{{CredentialID: strings.Repeat("1", 32), UUID: "9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"}}
	cases := []struct {
		name     string
		document CandidateDocument
	}{
		{
			name: "unknown schema",
			document: CandidateDocument{
				Schema:        "meshmux-node/v9",
				NodeID:        strings.Repeat("a", 32),
				Role:          RoleEdge,
				Revision:      9,
				VLESSPort:     8443,
				KernelVersion: KernelVersion,
			},
		},
		{
			name: "users without reality",
			document: CandidateDocument{
				Schema:        CandidateSchema,
				NodeID:        strings.Repeat("a", 32),
				Role:          RoleEdge,
				Revision:      9,
				VLESSPort:     8443,
				KernelVersion: KernelVersion,
				Users:         users,
			},
		},
		{
			name: "edge out without reality",
			document: CandidateDocument{
				Schema:        CandidateSchema,
				NodeID:        strings.Repeat("a", 32),
				Role:          RoleEdge,
				Revision:      9,
				VLESSPort:     8443,
				KernelVersion: KernelVersion,
				Out:           &OutEgress{Server: "203.0.113.10", Port: 8444, Key: outLinkKeyFixture},
			},
		},
	}
	for _, test := range cases {
		body, err := json.Marshal(test.document)
		if err == nil {
			t.Fatalf("%s was marshalled instead of rejected: %s", test.name, body)
		}
		if len(body) != 0 {
			t.Fatalf("%s produced bytes while failing: %s", test.name, body)
		}
	}
}

func TestCandidateV2StrictDecodingRejectsMalformedDocuments(t *testing.T) {
	reality := testReality(t)
	realityJSON, err := json.Marshal(reality)
	if err != nil {
		t.Fatal(err)
	}
	prefix := `{"schema":"meshmux-node/v2","node_id":"` + strings.Repeat("a", 32) +
		`","role":"edge","revision":9,"vless_port":8443,"kernel_version":"` + KernelVersion + `"`
	user := `{"credential_id":"` + strings.Repeat("1", 32) + `","uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"}`

	cases := []string{
		// Missing required blocks.
		prefix + `,"users":[` + user + `]}`,
		prefix + `,"users":[],"reality":` + string(realityJSON) + `,"extra":1}`,
		// Unknown, duplicate and null fields.
		prefix + `,"users":[` + user + `],"reality":` + string(realityJSON) + `,"unknown":1}`,
		prefix + `,"users":[` + user + `],"reality":` + string(realityJSON) + `,"users":[]}`,
		prefix + `,"users":null,"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[],"reality":null}`,
		prefix + `,"users":[{"credential_id":"` + strings.Repeat("1", 32) + `","uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d","extra":1}],"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[{"credential_id":"` + strings.Repeat("1", 32) + `","uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d","uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"}],"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[{"credential_id":null,"uuid":"9f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"}],"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[{"credential_id":"` + strings.Repeat("1", 32) + `","uuid":null}],"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[null],"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":{},"reality":` + string(realityJSON) + `}`,
		prefix + `,"users":[],"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid","handshake_port":443,"private_key":"` + reality.PrivateKey + `","short_id":"0123456789abcdef","extra":1}}`,
		prefix + `,"users":[],"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid","handshake_port":443,"private_key":"` + reality.PrivateKey + `","short_id":"0123456789abcdef","short_id":"0123456789abcdee"}}`,
		prefix + `,"users":[],"reality":{"server_name":null,"handshake_server":"www.example.invalid","handshake_port":443,"private_key":"` + reality.PrivateKey + `","short_id":"0123456789abcdef"}}`,
		prefix + `,"users":[],"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid","handshake_port":0,"private_key":"` + reality.PrivateKey + `","short_id":"0123456789abcdef"}}`,
		prefix + `,"users":[],"reality":{"server_name":"www.example.invalid","handshake_server":"www.example.invalid","handshake_port":443,"private_key":"` + reality.PrivateKey + `","short_id":"0123456789abcdef"}}}`,
	}
	for _, body := range cases {
		var decoded CandidateDocument
		if err := json.Unmarshal([]byte(body), &decoded); err == nil {
			t.Fatalf("malformed v2 document accepted: %s", body)
		}
	}
}

func TestCandidateOptionalBlocksShareV1(t *testing.T) {
	reality := mustJSON(t, testReality(t))
	prefix := `{"schema":"meshmux-node/v1","node_id":"` + strings.Repeat("a", 32) +
		`","role":"edge","revision":9,"vless_port":8443,"kernel_version":"` + KernelVersion + `"`
	body := prefix + `,"users":[],"reality":` + reality + `}`
	var decoded CandidateDocument
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("v1 document with optional blocks rejected: %v", err)
	}
	if decoded.Schema != CandidateSchema || decoded.Reality == nil {
		t.Fatalf("decoded = %+v", decoded)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateV2RejectsDuplicateCredentials(t *testing.T) {
	candidate := testV2Candidate(t)
	duplicateUUID := candidate
	duplicateUUID.Users = append([]VLESSUser(nil), candidate.Users...)
	duplicateUUID.Users = append(duplicateUUID.Users, VLESSUser{
		CredentialID: strings.Repeat("2", 32),
		UUID:         candidate.Users[0].UUID,
	})
	if err := duplicateUUID.Validate(); err == nil {
		t.Fatal("duplicate VLESS UUID accepted")
	}

	duplicateID := candidate
	duplicateID.Users = append([]VLESSUser(nil), candidate.Users...)
	duplicateID.Users = append(duplicateID.Users, VLESSUser{
		CredentialID: candidate.Users[0].CredentialID,
		UUID:         "1f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d",
	})
	if err := duplicateID.Validate(); err == nil {
		t.Fatal("duplicate credential id accepted")
	}
}

func TestCandidateV2RejectsOutRoleAndMissingReality(t *testing.T) {
	candidate := testV2Candidate(t)
	candidate.Role = RoleOut
	if err := candidate.Validate(); err == nil {
		t.Fatal("Out candidate with users and reality accepted")
	}

	candidate = testV2Candidate(t)
	candidate.Reality = nil
	if err := candidate.Validate(); err == nil {
		t.Fatal("candidate with users but no reality accepted")
	}

	baseline := validCandidate()
	baseline.Role = RoleEdge
	if err := baseline.Validate(); err != nil {
		t.Fatalf("v1 baseline without reality rejected: %v", err)
	}
}

func TestCandidateV2RejectsMalformedCredentialsAndReality(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Candidate)
	}{
		{"uppercase uuid", func(c *Candidate) { c.Users[0].UUID = strings.ToUpper(c.Users[0].UUID) }},
		{"uuid v1", func(c *Candidate) { c.Users[0].UUID = c.Users[0].UUID[:14] + "1" + c.Users[0].UUID[15:] }},
		{"uuid without dashes", func(c *Candidate) { c.Users[0].UUID = strings.ReplaceAll(c.Users[0].UUID, "-", "") }},
		{"short credential id", func(c *Candidate) { c.Users[0].CredentialID = strings.Repeat("1", 31) }},
		{"uppercase credential id", func(c *Candidate) { c.Users[0].CredentialID = "ABCDEF0123456789ABCDEF0123456789" }},
		{"reality server name with scheme", func(c *Candidate) { c.Reality.ServerName = "https://www.example.invalid" }},
		{"reality server name uppercase", func(c *Candidate) { c.Reality.ServerName = "WWW.example.invalid" }},
		{"reality server name is an ip", func(c *Candidate) { c.Reality.ServerName = "192.0.2.10" }},
		{"handshake server with port", func(c *Candidate) { c.Reality.HandshakeServer = "www.example.invalid:443" }},
		{"handshake server with path", func(c *Candidate) { c.Reality.HandshakeServer = "www.example.invalid/path" }},
		{"handshake server with credentials", func(c *Candidate) { c.Reality.HandshakeServer = "user@www.example.invalid" }},
		{"handshake server is not an ip", func(c *Candidate) { c.Reality.HandshakeServer = "999.1.1.1" }},
		{"handshake port zero", func(c *Candidate) { c.Reality.HandshakePort = 0 }},
		{"handshake port too large", func(c *Candidate) { c.Reality.HandshakePort = 65536 }},
		{"private key padded", func(c *Candidate) { c.Reality.PrivateKey = c.Reality.PrivateKey + "=" }},
		{"private key short", func(c *Candidate) { c.Reality.PrivateKey = c.Reality.PrivateKey[:42] }},
		{"private key all zero", func(c *Candidate) { c.Reality.PrivateKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }},
		{"short id uppercase", func(c *Candidate) { c.Reality.ShortID = strings.ToUpper(c.Reality.ShortID) }},
		{"short id short", func(c *Candidate) { c.Reality.ShortID = "0123456789abcde" }},
	}
	for _, test := range cases {
		candidate := testV2Candidate(t)
		test.mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("%s accepted", test.name)
		}
	}
}

func TestCandidateV2AcceptsIPHandshakeServer(t *testing.T) {
	candidate := testV2Candidate(t)
	candidate.Reality.HandshakeServer = "192.0.2.10"
	if err := candidate.Validate(); err != nil {
		t.Fatalf("IP handshake server rejected: %v", err)
	}
}

func TestCandidateV2RejectsTooManyUsers(t *testing.T) {
	candidate := testV2Candidate(t)
	candidate.Users = make([]VLESSUser, 0, MaxCandidateUsers+1)
	for i := 0; i <= MaxCandidateUsers; i++ {
		candidate.Users = append(candidate.Users, VLESSUser{
			CredentialID: strings.Repeat("a", 31) + string(rune('0'+i%10)),
			UUID:         uuidForIndex(i),
		})
	}
	if err := candidate.Validate(); err == nil {
		t.Fatal("candidate with more than 1024 users accepted")
	}
}

// uuidForIndex builds a deterministic, syntactically valid UUIDv4 for the
// unique-user count test.
func uuidForIndex(index int) string {
	const hexDigits = "0123456789abcdef"
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = hexDigits[(index+i)%16]
	}
	raw[6] = '4'
	raw[8] = '8'
	encoded := make([]byte, 32)
	for i, b := range raw {
		encoded[i*2] = hexDigits[b>>4]
		encoded[i*2+1] = hexDigits[b&0x0f]
	}
	return string(encoded[0:8]) + "-" + string(encoded[8:12]) + "-" + string(encoded[12:16]) +
		"-" + string(encoded[16:20]) + "-" + string(encoded[20:32])
}

func TestCandidateEqualComparesV2Blocks(t *testing.T) {
	candidate := testV2Candidate(t)
	same := candidate
	same.Users = append([]VLESSUser(nil), candidate.Users...)
	same.Reality = candidate.Reality
	if !candidate.Equal(same) {
		t.Fatal("identical candidates reported as different")
	}
	changed := candidate
	changed.Users = append([]VLESSUser(nil), candidate.Users...)
	changed.Users[0].UUID = "1f8b1c2d-3e4f-4a5b-8c7d-6e5f4a3b2c1d"
	if candidate.Equal(changed) {
		t.Fatal("candidates with different users reported as equal")
	}
	changed = candidate
	changed.Reality = &RealityConfig{
		ServerName:      candidate.Reality.ServerName,
		HandshakeServer: candidate.Reality.HandshakeServer,
		HandshakePort:   candidate.Reality.HandshakePort,
		PrivateKey:      candidate.Reality.PrivateKey,
		ShortID:         "fedcba9876543210",
	}
	if candidate.Equal(changed) {
		t.Fatal("candidates with different reality reported as equal")
	}
	if !candidate.Equal(candidate) {
		t.Fatal("a candidate is not equal to itself")
	}
}
