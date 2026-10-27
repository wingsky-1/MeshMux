package handler

// The cross-domain bridges the root package supplies to its subpackages. Each
// one is a single read: it resolves a fact through the domain that owns it and
// adapts it to the interface another domain declared. Keeping them here means no
// domain package imports a sibling, and the meeting point stays visible.
//
// The domain accessors at the bottom are the same kind of seam, and follow the
// convention the domain servers already use for their own fixtures
// (SetHubApplyForTest, KDFSlotForTest): production reaches a domain through the
// assembled router and never names it, so the servers stay unexported, while a
// domain's own test package has to drive the assembled Server — the route table,
// the authentication wrappers and the cross-domain bridges are part of what it
// verifies — and install its fake control plane the way the pre-split
// single-package test could by touching the field. Each accessor returns the
// server the constructor already built and adds no behaviour.

import (
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	subcore "github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/mesh"
	"github.com/wingsky-1/MeshMux/internal/web/handler/node"
	"github.com/wingsky-1/MeshMux/internal/web/handler/policy"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscriber"
	"github.com/wingsky-1/MeshMux/internal/web/handler/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/handler/upgrade"
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

// MeshDomainForTest is the Mesh device, enrollment and subnet-route domain.
func (app *Server) MeshDomainForTest() *mesh.Server { return app.meshServer }

// NodeDomainForTest is the node lifecycle and Agent channel domain.
func (app *Server) NodeDomainForTest() *node.Server { return app.nodeServer }

// PolicyDomainForTest is the route-policy, rule-library and publication domain.
func (app *Server) PolicyDomainForTest() *policy.Server { return app.policyServer }

// SubscriberDomainForTest is the subscriber workspace and subscription wizard.
func (app *Server) SubscriberDomainForTest() *subscriber.Server { return app.subscriberServer }

// SubscriptionDomainForTest is the public download boundary.
func (app *Server) SubscriptionDomainForTest() *subscription.Server { return app.subscriptionServer }

// UpgradeDomainForTest is the upgrade view, the Agent upgrade channels and the
// Hub backup/handoff/restore domain.
func (app *Server) UpgradeDomainForTest() *upgrade.Server { return app.upgradeServer }
