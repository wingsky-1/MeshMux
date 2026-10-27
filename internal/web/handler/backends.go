package handler

// The cross-domain bridges the root package supplies to its subpackages. Each
// one is a single read: it resolves a fact through the domain that owns it and
// adapts it to the interface another domain declared. Keeping them here means no
// domain package imports a sibling, and the meeting point stays visible.

import (
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	subcore "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// meshModelForPolicy is the narrow bridge the policy snapshot uses: it resolves
// one device's read-only mesh model through the Mesh domain and reports whether
// the result carries usable Line labels. It mints no Headscale key.
func (app *Server) meshModelForPolicy(record store.MeshDeviceRecord, now time.Time) (subcore.MeshConfigModel, bool) {
	plan, err := app.meshServer.MeshConfigPreflight(record, now)
	if err != nil || len(plan.Model.LineLabels) == 0 {
		return subcore.MeshConfigModel{}, false
	}
	return plan.Model, true
}
