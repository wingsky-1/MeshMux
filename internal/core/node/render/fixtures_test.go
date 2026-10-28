package render

import (
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// Test fixtures for the renderer. The pure domain fixtures live in the spec
// package tests; the renderer only needs the frozen baseline and the optional
// REALITY block, so they are repeated here in the smallest shape that exercises
// the renderer.

func validConfig() Config {
	return Config{
		HubURL:       "https://hub.example.invalid",
		NodeID:       strings.Repeat("a", 32),
		Role:         RoleOut,
		VLESSPort:    8443,
		SSHPort:      2222,
		AgentVersion: CurrentAgentVersion(),
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

// Test-only forwarders keep the renderer tests focused on rendering rather
// than on qualifying the pure domain package at every call site.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return spec.NewCandidateDocument(candidate)
}

func ParseHTTPProxyURL(raw string) (OutEgress, error) { return spec.ParseHTTPProxyURL(raw) }

func ParseRole(value string) (Role, error) { return spec.ParseRole(value) }

func NewOutLinkKey() (string, error) { return spec.NewOutLinkKey() }

func ValidateOutLinkKey(key string) error { return spec.ValidateOutLinkKey(key) }

func CurrentAgentVersion() string { return spec.CurrentAgentVersion() }

func KernelReleaseFor(architecture string) (KernelRelease, bool) {
	return spec.KernelReleaseFor(architecture)
}
