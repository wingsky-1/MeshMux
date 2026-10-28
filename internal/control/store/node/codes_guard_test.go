package node

// The stable error codes of the node domain are declared twice on purpose: the
// literal stays in this package because the error-code golden freezes every Code*
// const declared here, and the emitting layer declares the same value in its own
// vocabulary so the layer below can report it without importing this package.
//
// A drift between the two copies would be a real defect — a log line or a stored
// diagnosis row would name a code the layer never emits — and the compiler cannot
// see it, so this test pins them together.

import (
	"testing"

	storeline "github.com/wingsky-1/MeshMux/internal/control/store/node/line"
	storeout "github.com/wingsky-1/MeshMux/internal/control/store/node/out"
)

func TestStableCodesStayInSync(t *testing.T) {
	cases := []struct {
		name    string
		layer   string
		here    string
		emitted string
	}{
		{"CodeLineEgressExternalDeclared", "line", CodeLineEgressExternalDeclared, storeline.CodeLineEgressExternalDeclared},
		{"CodeOutSyncPending", "line", CodeOutSyncPending, storeline.CodeOutSyncPending},
		{"CodeOutSyncInProgress", "out", CodeOutSyncInProgress, storeout.CodeOutSyncInProgress},
		{"CodeOutNotAuthorized", "out", CodeOutNotAuthorized, storeout.CodeOutNotAuthorized},
		{"CodeOutSyncNotApplicable", "out", CodeOutSyncNotApplicable, storeout.CodeOutSyncNotApplicable},
		{"OutAclSourceMismatchCode", "out", OutAclSourceMismatchCode, storeout.OutAclSourceMismatchCode},
	}
	for _, tc := range cases {
		if tc.emitted != tc.here {
			t.Errorf("%s: the %s layer declares %q, this package declares %q", tc.name, tc.layer, tc.emitted, tc.here)
		}
	}
}
