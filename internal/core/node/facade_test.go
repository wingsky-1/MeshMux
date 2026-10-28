package node

import (
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/agent"
)

// TestFacadePublishCodesMatchAgent keeps the literal facade constants (the
// error-code golden requires literals in this package) from drifting away from
// the agent declarations.
func TestFacadePublishCodesMatchAgent(t *testing.T) {
	pairs := map[string]string{
		CodePublishCheckSingBox:   agent.CodePublishCheckSingBox,
		CodePublishCheckMihomo:    agent.CodePublishCheckMihomo,
		CodePublishSingBoxMissing: agent.CodePublishSingBoxMissing,
		CodePublishMihomoMissing:  agent.CodePublishMihomoMissing,
		CodePublishMihomoVersion:  agent.CodePublishMihomoVersion,
	}
	for facade, agentValue := range pairs {
		if facade != agentValue {
			t.Fatalf("facade publish code %q != agent %q", facade, agentValue)
		}
	}
}
