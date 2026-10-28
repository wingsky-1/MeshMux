package agent

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/render"
	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// Test fixtures for the Agent runtime. The pure domain fixtures live in the
// spec package tests; the runtime tests repeat the smallest candidate shape
// they need so each package stays self-contained.

func validConfig() Config {
	return Config{
		HubURL:       "https://hub.example.invalid",
		NodeID:       strings.Repeat("a", 32),
		Role:         RoleOut,
		VLESSPort:    8443,
		SSHPort:      2222,
		AgentVersion: spec.CurrentAgentVersion(),
		AgentSHA256:  strings.Repeat("b", 64),
		KernelSHA256: strings.Repeat("c", 64),
	}
}

func validCandidate() Candidate {
	return Candidate{
		NodeID:        strings.Repeat("a", 32),
		Role:          RoleOut,
		Revision:      9,
		VLESSPort:     8443,
		KernelVersion: KernelVersion,
	}
}

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

func largeV2UserSet() []VLESSUser {
	users := make([]VLESSUser, 0, MaxCandidateUsers)
	for index := range MaxCandidateUsers {
		users = append(users, VLESSUser{
			CredentialID: fmt.Sprintf("%032x", index+1),
			UUID:         fmt.Sprintf("%08x-1111-4111-8111-111111111111", index+1),
		})
	}
	return users
}

func v2Candidate(users ...VLESSUser) Candidate {
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Users = users
	candidate.Reality = &RealityConfig{
		ServerName:      "www.example.invalid",
		HandshakeServer: "handshake.example.invalid",
		HandshakePort:   443,
		PrivateKey:      "tnILRhHeIrUXzzvieuqqZkSh8BvSiMYsWeZJjyjP8fg",
		ShortID:         "0123456789abcdef",
	}
	return candidate
}

// Test-only forwarders keep the runtime tests focused on runtime behaviour
// rather than on qualifying the pure domain package at every call site.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return spec.NewCandidateDocument(candidate)
}

func CompileCandidate(candidate Candidate) ([]byte, error) {
	return render.CompileCandidate(candidate)
}

func CompileACL(candidate Candidate, sources []string) ([]byte, error) {
	return render.CompileACL(candidate, sources)
}

func CurrentAgentVersion() string { return spec.CurrentAgentVersion() }

func KernelReleaseFor(architecture string) (KernelRelease, bool) {
	return spec.KernelReleaseFor(architecture)
}
