package handler

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// fixturePublishVerifier is the test double of the kernel gate. It runs no
// binary, so the assembly, gate ordering and refusal semantics are exercised
// without a kernel install, while the recorded documents are still the exact
// bytes the pipeline would have handed to a real kernel.
//
// Two behaviours of the real gate are modelled here on purpose:
//
//   - a missing kernel is a refusal with its own stable code, never a pass;
//   - a rejection carries no document content.
type fixturePublishVerifier struct {
	mu sync.Mutex

	singBoxCalls int
	mihomoCalls  int

	// singBoxDocs and mihomoDocs keep every checked document in order.
	singBoxDocs [][]byte
	mihomoDocs  [][]byte

	// rejectSingBoxAt and rejectMihomoAt fail the n-th (1-based) call.
	rejectSingBoxAt int
	rejectMihomoAt  int

	// missingSingBox and missingMihomo make one gate unavailable.
	missingSingBox bool
	missingMihomo  bool
}

func (v *fixturePublishVerifier) CheckSingBox(_ context.Context, document []byte) (string, error) {
	return v.check(fixtureSingBoxGate, fixtureGateRun{
		calls:    &v.singBoxCalls,
		docs:     &v.singBoxDocs,
		rejectAt: &v.rejectSingBoxAt,
		missing:  &v.missingSingBox,
	}, document)
}

func (v *fixturePublishVerifier) CheckMihomo(_ context.Context, document []byte) (string, error) {
	return v.check(fixtureMihomoGate, fixtureGateRun{
		calls:    &v.mihomoCalls,
		docs:     &v.mihomoDocs,
		rejectAt: &v.rejectMihomoAt,
		missing:  &v.missingMihomo,
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
func (v *fixturePublishVerifier) check(gate fixtureGate, run fixtureGateRun, document []byte) (string, error) {
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

// hasSingBoxDocument reports whether one checked document contains needle.
func (v *fixturePublishVerifier) hasSingBoxDocument(needle string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, document := range v.singBoxDocs {
		if strings.Contains(string(document), needle) {
			return true
		}
	}
	return false
}

func (v *fixturePublishVerifier) counts() (int, int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.singBoxCalls, v.mihomoCalls
}
