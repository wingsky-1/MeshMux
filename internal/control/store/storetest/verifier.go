package storetest

import (
	"context"
	"errors"

	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// Verifier is a fake kernel gate. It records the documents it saw and can fail
// either kernel, so a store test never needs a real sing-box or mihomo binary.
type Verifier struct {
	SingBoxCalls int
	MihomoCalls  int
	SingBoxDocs  [][]byte
	MihomoDocs   [][]byte
	FailSingBox  bool
	FailMihomo   bool
	MissingMihom bool
}

// CheckSingBox records the document and reports the configured outcome.
func (v *Verifier) CheckSingBox(_ context.Context, document []byte) (string, error) {
	v.SingBoxCalls++
	v.SingBoxDocs = append(v.SingBoxDocs, append([]byte(nil), document...))
	if v.FailSingBox {
		return "", errors.New(nodedomain.CodePublishCheckSingBox + ": refused")
	}
	return "sing-box accepted", nil
}

// CheckMihomo records the document and reports the configured outcome.
func (v *Verifier) CheckMihomo(_ context.Context, document []byte) (string, error) {
	v.MihomoCalls++
	v.MihomoDocs = append(v.MihomoDocs, append([]byte(nil), document...))
	if v.MissingMihom {
		return "", errors.New(nodedomain.CodePublishMihomoMissing + ": not installed")
	}
	if v.FailMihomo {
		return "", errors.New(nodedomain.CodePublishCheckMihomo + ": refused")
	}
	return "mihomo accepted", nil
}
