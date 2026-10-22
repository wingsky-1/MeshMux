package web

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
	v.mu.Lock()
	defer v.mu.Unlock()
	v.singBoxCalls++
	v.singBoxDocs = append(v.singBoxDocs, append([]byte(nil), document...))
	if v.missingSingBox {
		return "", errors.New(node.CodePublishSingBoxMissing + ": the pinned sing-box binary is missing")
	}
	if v.rejectSingBoxAt == v.singBoxCalls {
		return "", errors.New(node.CodePublishCheckSingBox + ": sing-box refused the assembled document")
	}
	return "sing-box " + node.SingBoxPublishVersion + " accepted the assembled document", nil
}

func (v *fixturePublishVerifier) CheckMihomo(_ context.Context, document []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.mihomoCalls++
	v.mihomoDocs = append(v.mihomoDocs, append([]byte(nil), document...))
	if v.missingMihomo {
		return "", errors.New(node.CodePublishMihomoMissing + ": the pinned mihomo binary is missing")
	}
	if v.rejectMihomoAt == v.mihomoCalls {
		return "", errors.New(node.CodePublishCheckMihomo + ": mihomo refused the assembled document")
	}
	return "mihomo " + node.MihomoVersion + " accepted the assembled document", nil
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
