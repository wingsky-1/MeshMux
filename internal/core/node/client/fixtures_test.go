package client

import (
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// Test fixtures for the outbound Hub client. The client only needs one valid
// install configuration and the candidate document builder.

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

func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return spec.NewCandidateDocument(candidate)
}
