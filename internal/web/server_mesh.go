package web

// Mesh device lifecycle handlers.
//
// The page separates three kinds of truth, and never blends them:
//
//   - intent: what the Hub recorded (a device record, a revocation request);
//   - Headscale evidence: what one explicit `nodes list` reports right now.
//     A page render reads it for display only and writes nothing; the explicit
//     reconcile button is the only path that persists an observation;
//   - the one-time enrollment key: Hub-side material that is shown exactly once
//     in a POST response body, stored only as a SHA-256 digest, and never put in
//     a URL, a log line or a second response. Nothing accepts the secret back:
//     the key is spent by the transaction that proves registration, so the
//     reconcile or claim that observes the node id consumes it.
//
// A pending device never becomes registered by rendering: registration needs
// an observed Headscale node id, recorded only by an explicit reconcile or an
// explicit claim. The list therefore renders "未注册" instead of guessing a
// node from a hostname.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/headscale"
	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// meshControlPlaneTimeout bounds the Headscale reads one request performs. A
// local socket answers far below it; a stalled service is reported instead of
// hanging the page.
const meshControlPlaneTimeout = 5 * time.Second

// codeMeshHeadscaleUserUnknown is the refusal for a Headscale user name the Hub
// will not create on demand. Only the shared default user of D2 may be minted
// here; every other name has to exist already.
const codeMeshHeadscaleUserUnknown = "MESH_HEADSCALE_USER_UNKNOWN"

// Web-level route codes. They describe facts the store and the domain do not:
// the device has no observed Headscale node to approve on, and a Headscale
// command that returned success did not show the requested state in its own
// readback. Both are refusals: no intent is written and the row keeps the state
// it had before the request.
const (
	codeMeshRouteApprovalUnconfirmed = "MESH_ROUTE_APPROVAL_UNCONFIRMED"
	codeMeshRouteNodeUnobserved      = "MESH_ROUTE_NODE_UNOBSERVED"

	// codeMeshRouteUntrackedDropped is the web_event code for one approved
	// prefix that could not be carried in the complete set Headscale's replace
	// operation takes, and was therefore left out instead of blocking the whole
	// request. It is a log-only audit event: it is not a mesh_route_events kind,
	// which the schema's CHECK constraint keeps to route state changes, and not
	// a rendered failure code, because the request itself succeeded.
	codeMeshRouteUntrackedDropped = "MESH_ROUTE_UNTRACKED_DROPPED"
)

// meshUserView is one selectable Headscale user. The list is read live; the
// device only stores a name snapshot.
type meshUserView struct {
	ID   uint64
	Name string
}

// meshSubscriberView is one selectable subscriber for a proxy_mesh binding.
type meshSubscriberView struct {
	ID          string
	DisplayName string
	State       string
}

// meshKeyDisclosure carries one plaintext enrollment key and, for a
// proxy+mesh device, the one-shot client configuration that embeds the
// Headscale pre-auth key. It is filled only for the single POST response that
// issues it; renderMesh never persists or re-renders it.
type meshKeyDisclosure struct {
	Device  string
	Secret  string
	Expires string
	Config  string
	// JoinCommand is the standard Tailscale join command for devices without
	// a generated sing-box config (mesh-only / subnet-router). It never
	// embeds the secret: the key stays in its own single <pre> so the
	// exactly-once assertion keeps holding. Empty when the control-plane
	// origin is not configured; LoginConfigured tells the two cases apart.
	JoinCommand     string
	LoginConfigured bool
}

// meshDeviceView is the complete read projection of one device. It carries no
// secret: the key state is a state label, never a value.
type meshDeviceView struct {
	ID             string
	DisplayName    string
	PurposeLabel   string
	PlatformLabel  string
	HeadscaleUser  string
	NodeName       string
	SubscriberID   string
	SubscriberName string
	NodeID         string
	TailnetIP      string
	Online         string
	OnlineClass    string
	ObservedAt     string
	StatusLabel    string
	StatusClass    string
	KeyLabel       string
	KeyClass       string
	KeyExpires     string
	RevokeReason   string
	CanIssue       bool
	CanConfig      bool
	CanRevoke      bool
	CanRetry       bool
	Routes         []meshRouteView
	Claims         []meshClaimView
}

// meshClaimView is one Headscale node that carries the same name as a pending
// MeshMux device but is not owned by any device record. It is only a
// suggestion: claiming needs an explicit POST, and recordMeshObservation is the
// same evidence path a reconcile uses.
type meshClaimView struct {
	NodeID   string
	Name     string
	UserName string
}

// meshRouteView is one subnet prefix of one device. The three remote columns
// come from the same read-only `nodes list` snapshot that already annotates the
// page; they are not persisted. Desired, the last observed value and the audit
// operation id come from the Hub record, so the page never presents an
// observation as an approval or an approval as served evidence.
type meshRouteView struct {
	Prefix        string
	DesiredLabel  string
	DesiredClass  string
	ObservedLabel string
	ObservedAt    string
	Approved      bool
	Available     bool
	Served        bool
	RemoteKnown   bool
	OperationID   string
	CanApprove    bool
	CanWithdraw   bool
}

// meshPageView is the whole page model.
type meshPageView struct {
	Devices     []meshDeviceView
	Users       []meshUserView
	Subscribers []meshSubscriberView
	UsersNotice string
	NodesNotice string
	DefaultUser string
	Disclosure  *meshKeyDisclosure
	Notice      string
	NoticeClass string
}

// registerMeshRoutes registers the mesh device routes. The placeholder
// navigation loop in newServer must skip "/mesh", otherwise the placeholder page
// competes with the real page for the same path.
func (app *Server) registerMeshRoutes(r chi.Router) {
	r.Get("/mesh", app.authenticated(app.meshPage))
	r.Post("/mesh", app.mutation(app.meshCreate, true))
	r.Post("/mesh/config", app.mutation(app.meshConfigPage, true))
	r.Post("/mesh/claim", app.mutation(app.meshClaim, true))
	r.Post("/mesh/rekey", app.mutation(app.meshRekey, true))
	r.Post("/mesh/reconcile", app.mutation(app.meshReconcile, true))
	r.Post("/mesh/revoke", app.mutation(app.meshRevoke, true))
	r.Post("/mesh/retry", app.mutation(app.meshRevoke, true))
}

// meshPage renders the device list. It performs a read-only Headscale snapshot
// for the online and address columns; it never writes an observation. Only the
// explicit reconcile action persists one, so opening the page cannot silently
// settle a device.
func (app *Server) meshPage(w http.ResponseWriter, r *http.Request, sess session) {
	app.renderMesh(w, r, sess, nil, "", "")
}

// meshCreate creates one device and mints its first one-time enrollment key.
//
// Order matters: the form is validated first (no I/O), then the Headscale user
// is resolved, then the device row and its key are written. A Headscale outage
// therefore refuses the creation before anything is stored, instead of leaving a
// device whose Headscale user does not exist.
func (app *Server) meshCreate(w http.ResponseWriter, r *http.Request, sess session) {
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	if _, err := subscription.NormalizeDisplayName(displayName); err != nil {
		app.meshFail(w, r, err, codeMeshDeviceCreateFailed, "设备名称不正确。", "请使用 1-80 个可打印字符。")
		return
	}
	purpose := mesh.Purpose(strings.TrimSpace(r.PostForm.Get("purpose")))
	platform := mesh.Platform(strings.TrimSpace(r.PostForm.Get("platform")))
	subscriberID := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	if err := mesh.ValidateSubscriberBinding(purpose, subscriberID); err != nil {
		app.meshFail(w, r, err, codeMeshDeviceCreateFailed, "用途与订阅用户绑定不一致。", "proxy_mesh 必须选择订阅用户；mesh_only 必须留空；subnet_router 可留空。")
		return
	}
	if err := platform.Validate(); err != nil {
		app.meshFail(w, r, err, codeMeshDeviceCreateFailed, "客户端平台不正确。", "请从页面提供的选项中选择。")
		return
	}
	rawPrefixes := strings.Join([]string{
		r.PostForm.Get("declared_prefixes"),
		r.PostForm.Get("declared_routes"),
		r.PostForm.Get("route_prefixes"),
	}, "\n")
	declared, err := mesh.NormalizeDeclaredPrefixes(purpose, meshSplitRoutePrefixes(rawPrefixes))
	if err != nil {
		app.meshFail(w, r, err, mesh.CodeRouteDeclarationInvalid, "子网前缀不正确。", "请使用 192.168.1.0/24 这样的网络前缀，每行一个。")
		return
	}
	if purpose == mesh.PurposeSubnetRouter && len(declared) == 0 {
		app.fail(w, r, http.StatusBadRequest, mesh.CodeRouteDeclarationInvalid,
			"子网路由至少需要一个前缀。", "请在创建表单中填写至少一个规范 CIDR 前缀；只创建广告意图，批准仍需单独操作。")
		return
	}
	user := strings.TrimSpace(r.PostForm.Get("headscale_user"))
	if user == "" {
		user = mesh.DefaultHeadscaleUser
	}
	user, err = mesh.NormalizeHeadscaleUser(user)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceCreateFailed, "Headscale 用户不正确。", "请使用页面列出的 Headscale 用户。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	headscaleUser, err := app.ensureMeshUser(ctx, user)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshDeviceCreateFailed, "无法确认 Headscale 用户。", "请检查 Headscale 服务与 Web 服务组权限后重试。")
		return
	}
	now := app.now()
	record, err := app.createMeshDevice(mesh.DeviceSpec{
		DisplayName:    displayName,
		Purpose:        purpose,
		Platform:       platform,
		SubscriberID:   subscriberID,
		HeadscaleUser:  headscaleUser.Name,
		DeclaredRoutes: declared,
	}, now)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceCreateFailed, "无法创建 Mesh 设备。", "请检查名称、用途与所选订阅用户后重试。")
		return
	}
	app.event(r, "MESH_DEVICE_CREATED")
	// The device is durable at this point. A key that cannot be minted is
	// reported as its own failure with the device kept: the operator can re-sign
	// from the list, and hiding the created device would misstate the audit
	// trail.
	disclosure, configNotice, err := app.meshCreateDisclosure(ctx, record, headscaleUser, now)
	if err != nil {
		app.event(r, "MESH_DEVICE_KEY_ISSUE_FAILED")
		app.meshFail(w, r, err, codeMeshDeviceKeyIssue, "设备已创建，但一次性 Key 未签发。", "请在设备列表中重新签发 Key。")
		return
	}
	if disclosure.Config != "" {
		app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_ISSUED")
		app.event(r, "MESH_DEVICE_CONFIG_ISSUED")
		app.renderMesh(w, r, sess, disclosure, "设备已创建。配置与一次性 Key 只在本次响应中显示。", "notice")
		return
	}
	app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_ISSUED")
	message := "设备已创建。一次性 Key 只在本次响应中显示。"
	if configNotice != "" {
		message += " 设备配置未生成（" + configNotice + "）；Key 仍可用于后续操作。"
	}
	app.renderMesh(w, r, sess, disclosure, message, "notice")
}

// meshRekey withdraws the live key of a pending device and mints a new one. An
// expired device is moved back to pending first: re-enrollment is a fresh
// attempt with no observed node, which is exactly the store's expired → pending
// edge.
//
// The withdrawal happens before both the re-enrollment and the issue: the Hub
// never holds two live enrollment secrets for one device, and a device is not
// moved back to pending if its old key could not be withdrawn. A lapsed key is
// left for the issue path to retire as expired, so the audit trail keeps the two
// events apart.
//
// For a proxy+mesh device the same response also carries the device-scoped
// sing-box configuration: the Headscale pre-auth key and the Hub-side key are
// minted in one chain and neither is persisted as plaintext. Mesh-only and
// subnet-router devices keep the 9a behaviour and only refresh the Hub key.
func (app *Server) meshRekey(w http.ResponseWriter, r *http.Request, sess session) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	record, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceRekeyFailed, "无法读取 Mesh 设备。", "请刷新页面后重试。")
		return
	}
	now := app.now()
	if record.Status != mesh.StatusPending && record.Status != mesh.StatusExpired {
		app.fail(w, r, http.StatusConflict, codeMeshDeviceNotReenrollable, "当前状态不能签发一次性 Key。", "只有待注册或已过期设备可以重新签发。")
		return
	}
	keys, err := app.store.listMeshEnrollmentKeys(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceRekeyFailed, "无法读取 Key 记录。", "请检查数据库后重试。")
		return
	}
	for _, key := range keys {
		if key.State != mesh.KeyIssued || !now.Before(time.Unix(key.ExpiresAt, 0)) {
			// Lapsed keys are retired by the issue path as expired; revoking one
			// here would report an early withdrawal that did not happen.
			continue
		}
		if _, err = app.store.revokeMeshEnrollmentKey(key.ID); err != nil {
			app.meshFail(w, r, err, codeMeshDeviceRekeyFailed, "无法作废旧的一次性 Key。", "请刷新页面确认 Key 状态后重试。")
			return
		}
		app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_REVOKED")
	}
	if record.Status == mesh.StatusExpired {
		record, err = app.store.reenrollMeshDevice(deviceID, now)
		if err != nil {
			app.meshFail(w, r, err, codeMeshDeviceRekeyFailed, "无法让设备重新入网。", "请确认设备已过期且节点名未被占用。")
			return
		}
		app.event(r, "MESH_DEVICE_REENROLLED")
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	user, err := app.ensureMeshUser(ctx, record.HeadscaleUser)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshDeviceRekeyFailed, "无法确认 Headscale 用户。", "请检查 Headscale 服务后重试。")
		return
	}
	disclosure, configNotice, err := app.meshCreateDisclosure(ctx, record, user, now)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceRekeyFailed, "无法签发新的一次性 Key。", "请确认设备仍为待注册状态。")
		return
	}
	if disclosure.Config != "" {
		app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_ISSUED")
		app.event(r, "MESH_DEVICE_CONFIG_ISSUED")
		app.renderMesh(w, r, sess, disclosure, "旧 Key 已作废，新配置与一次性 Key 只在本次响应中显示。", "notice")
		return
	}
	app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_REISSUED")
	message := "旧 Key 已作废，新 Key 只在本次响应中显示。"
	if configNotice != "" {
		message += " 设备配置未生成（" + configNotice + "）。"
	}
	app.renderMesh(w, r, sess, disclosure, message, "notice")
}

// meshRouteApprove moves one declared prefix to approved in Headscale and
// records the intent only after the readback confirms it. Headscale's approve
// command replaces the whole approved set, so the request sends what Headscale
// currently reports as approved plus the new prefix: prefixes MeshMux does not
// track stay approved instead of being silently cleared, and each one gets a
// MESH_ROUTE_UNTRACKED audit event.
//
// A failed command or an unconfirmed readback leaves the row exactly as it was
// (advertised): no local intent claims an approval the control plane did not
// prove.
func (app *Server) meshRouteApprove(w http.ResponseWriter, r *http.Request, sess session) {
	device, route, ok := app.meshRouteTarget(w, r)
	if !ok {
		return
	}
	if route.Desired == mesh.RouteDesiredApproved {
		app.renderMesh(w, r, sess, nil, "前缀 "+route.Prefix+" 已是批准状态，未重复调用 Headscale。", "notice")
		return
	}
	if route.Desired == mesh.RouteDesiredRevoked {
		app.fail(w, r, http.StatusConflict, mesh.CodeRouteTransitionInvalid,
			"已撤销的前缀不能直接批准。", "请重新声明该前缀，再执行一次单独的批准。")
		return
	}
	if device.HeadscaleNodeID == 0 {
		app.fail(w, r, http.StatusConflict, codeMeshRouteNodeUnobserved,
			"设备尚未观测到 Headscale Node ID，无法批准子网路由。",
			"请先完成设备注册并“重新核对全部设备”，再批准前缀。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	node, found, err := app.meshNode(ctx, device.HeadscaleNodeID)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshRouteApproval, "无法读取 Headscale 路由状态。", "请检查 Headscale 服务后重试。")
		return
	}
	if !found {
		app.fail(w, r, http.StatusConflict, codeMeshRouteNodeUnobserved,
			"Headscale 未报告该设备的节点，无法批准子网路由。", "请重新核对；设备可能已离线或过期。")
		return
	}
	prefixes, dropped := meshRouteApprovalSet(node.ApprovedRoutes, route.Prefix, "")
	readback, err := app.mesh.SetApprovedRoutes(ctx, device.HeadscaleNodeID, prefixes)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshRouteApproval, "Headscale 未接受路由批准。", "请检查 Headscale 服务与节点状态后重试。")
		return
	}
	// The dropped entry was left out of the set, and a set operation replaces
	// the whole list: Headscale no longer approves it. That is a deliberate
	// change of the approved set, so it is audited and reported once the
	// mutation itself was accepted.
	droppedCount := app.logDroppedApprovedRoutes(r, dropped)
	if readback.ID != device.HeadscaleNodeID || !meshRoutePrefixIn(readback.ApprovedRoutes, route.Prefix) {
		app.fail(w, r, http.StatusConflict, codeMeshRouteApprovalUnconfirmed,
			"Headscale 未在 readback 中确认该前缀已批准。",
			"请重新核对；Hub 未写入批准意图，前缀仍为待批准。")
		return
	}
	now := app.now()
	if err = app.recordUntrackedApprovedRoutes(device.ID, readback, operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteApproval, "Headscale 已批准，但未声明的已批准前缀未能写入审计记录。", "请检查数据库后重新核对。")
		return
	}
	if _, err = app.store.setMeshRouteDesired(device.ID, route.Prefix, mesh.RouteDesiredApproved, operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteApproval, "Headscale 已批准，但 Hub 未能记录批准意图。", "请重新核对并检查数据库后重试。")
		return
	}
	if _, _, err = app.store.recordMeshRouteObservation(device.ID, route.Prefix, meshRouteObservedFromNode(readback, route.Prefix), operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteApproval, "批准意图已保存，但路由观测未写入。", "请重新核对以刷新证据。")
		return
	}
	app.event(r, routeEventApproved)
	app.renderMesh(w, r, sess, nil,
		"已批准前缀 "+route.Prefix+"；Headscale readback 已确认。approved 集合已更新，但这不表示客户端已实际转发流量。"+meshRouteDroppedNotice(droppedCount, false), "notice")
}

// meshRouteRevoke withdraws an approval while keeping the declaration. It sends
// the observed approved set minus the prefix, or clears the set when nothing
// else is approved. The row returns to advertised only after the readback no
// longer lists the prefix; a refusal or mismatch keeps the approved intent.
func (app *Server) meshRouteRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	device, route, ok := app.meshRouteTarget(w, r)
	if !ok {
		return
	}
	if route.Desired == mesh.RouteDesiredAdvertised {
		app.renderMesh(w, r, sess, nil, "前缀 "+route.Prefix+" 当前不是批准状态，未调用 Headscale。", "notice")
		return
	}
	if route.Desired == mesh.RouteDesiredRevoked {
		app.fail(w, r, http.StatusConflict, mesh.CodeRouteTransitionInvalid,
			"已撤销的前缀不能再次撤销批准。", "请刷新页面确认路由状态。")
		return
	}
	if device.HeadscaleNodeID == 0 {
		app.fail(w, r, http.StatusConflict, codeMeshRouteNodeUnobserved,
			"设备尚未观测到 Headscale Node ID，无法撤销路由批准。",
			"请先完成设备注册并“重新核对全部设备”。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	node, found, err := app.meshNode(ctx, device.HeadscaleNodeID)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshRouteWithdraw, "无法读取 Headscale 路由状态。", "请检查 Headscale 服务后重试。")
		return
	}
	if !found {
		app.fail(w, r, http.StatusConflict, codeMeshRouteNodeUnobserved,
			"Headscale 未报告该设备的节点，无法撤销路由批准。", "请重新核对；设备可能已离线或过期。")
		return
	}
	prefixes, dropped := meshRouteApprovalSet(node.ApprovedRoutes, "", route.Prefix)
	var readback headscale.Node
	if len(prefixes) == 0 {
		// Nothing sendable remains. Clearing is a superset of the difference the
		// caller asked for, so a prefix the adapter refuses is withdrawn too
		// instead of pinning the node to a set that can never be sent again.
		readback, err = app.mesh.ClearApprovedRoutes(ctx, device.HeadscaleNodeID)
	} else {
		readback, err = app.mesh.SetApprovedRoutes(ctx, device.HeadscaleNodeID, prefixes)
	}
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshRouteWithdraw, "Headscale 未接受撤销路由批准。", "请检查 Headscale 服务与节点状态后重试。")
		return
	}
	droppedCount := app.logDroppedApprovedRoutes(r, dropped)
	if readback.ID != device.HeadscaleNodeID || meshRoutePrefixIn(readback.ApprovedRoutes, route.Prefix) {
		app.fail(w, r, http.StatusConflict, codeMeshRouteApprovalUnconfirmed,
			"Headscale readback 中该前缀仍为已批准。",
			"请重新核对；Hub 保留已批准意图，未声称撤销成功。")
		return
	}
	now := app.now()
	if err = app.recordUntrackedApprovedRoutes(device.ID, readback, operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteWithdraw, "Headscale 已撤销批准，但未声明前缀的审计记录未写入。", "请检查数据库后重新核对。")
		return
	}
	if _, err = app.store.setMeshRouteDesired(device.ID, route.Prefix, mesh.RouteDesiredAdvertised, operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteWithdraw, "Headscale 已撤销批准，但 Hub 未能记录意图。", "请重新核对并检查数据库后重试。")
		return
	}
	if _, _, err = app.store.recordMeshRouteObservation(device.ID, route.Prefix, meshRouteObservedFromNode(readback, route.Prefix), operation(r), now); err != nil {
		app.meshFail(w, r, err, codeMeshRouteWithdraw, "撤销意图已保存，但路由观测未写入。", "请重新核对以刷新证据。")
		return
	}
	app.event(r, routeEventWithdrawn)
	app.renderMesh(w, r, sess, nil,
		"已撤销前缀 "+route.Prefix+" 的批准；声明仍保留，可再次批准。已批准集合的其余前缀未被清除。"+meshRouteDroppedNotice(droppedCount, len(prefixes) == 0), "notice")
}

// meshRouteTarget resolves the device and one declared prefix of a route action.
func (app *Server) meshRouteTarget(w http.ResponseWriter, r *http.Request) (MeshDeviceRecord, MeshRouteRecord, bool) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	device, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshRouteApproval, "无法读取 Mesh 设备。", "请刷新页面后重试。")
		return MeshDeviceRecord{}, MeshRouteRecord{}, false
	}
	route, err := app.store.getMeshRoute(deviceID, strings.TrimSpace(r.PostForm.Get("prefix")))
	if err != nil {
		app.meshFail(w, r, err, codeMeshRouteApproval, "无法读取子网路由。", "请刷新页面后重试。")
		return MeshDeviceRecord{}, MeshRouteRecord{}, false
	}
	return device, route, true
}

// meshNode returns the one node a request is about from the same read the page
// uses. Absence is reported separately from a failed read.
func (app *Server) meshNode(ctx context.Context, nodeID uint64) (headscale.Node, bool, error) {
	nodes, err := app.mesh.ListNodes(ctx, "")
	if err != nil {
		return headscale.Node{}, false, err
	}
	for _, node := range nodes {
		if node.ID == nodeID {
			return node, true, nil
		}
	}
	return headscale.Node{}, false, nil
}

// meshRouteApprovalSet builds the complete approved set Headscale's set
// operation expects. Existing entries are canonicalised when possible and
// deduplicated. add and remove are canonical prefixes; remove applies to the
// difference set of a withdrawal.
//
// An entry the Headscale adapter refuses is dropped from the set and returned in
// dropped instead of being sent back verbatim. `nodes approve-routes` replaces
// the whole list in one CSV value, so sending an exit route (0.0.0.0/0 or ::/0),
// a prefix with host bits set or anything else that is not a prefix makes the
// adapter refuse the entire request: one un-sendable entry that a device or an
// operator put into Headscale's approved list would otherwise block every later
// approval and withdrawal of a legitimate prefix forever. The values are
// returned so the caller can audit each drop; they never reach a log line.
func meshRouteApprovalSet(existing []string, add, remove string) (set, dropped []string) {
	out := make([]string, 0, len(existing)+1)
	seen := make(map[string]struct{}, len(existing)+1)
	for _, raw := range existing {
		prefix := strings.TrimSpace(raw)
		if prefix == "" {
			continue
		}
		if canonical, err := mesh.ParseRoutePrefix(prefix); err == nil {
			prefix = canonical.String()
		}
		if remove != "" && prefix == remove {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		if !headscale.ApprovableRoutePrefix(prefix) {
			dropped = append(dropped, prefix)
			continue
		}
		out = append(out, prefix)
	}
	if add != "" {
		// add is a stored declaration, which the mesh domain already refused
		// unless it is a routable prefix, so it is sendable by construction and
		// is never dropped: a request that silently approved nothing would
		// report success for a prefix Headscale never saw.
		if _, ok := seen[add]; !ok {
			out = append(out, add)
		}
	}
	sort.Strings(out)
	sort.Strings(dropped)
	return out, dropped
}

// logDroppedApprovedRoutes records one MESH_ROUTE_UNTRACKED_DROPPED event per
// approved prefix the set could not carry, and returns how many were dropped.
// The event is an audit fact, not a page failure: the request itself still
// succeeds for the prefixes that were sent. Only the stable code and
// operation_id are logged, so the network values stay out of the log.
func (app *Server) logDroppedApprovedRoutes(r *http.Request, dropped []string) int {
	for range dropped {
		app.event(r, codeMeshRouteUntrackedDropped)
	}
	return len(dropped)
}

// meshRouteDroppedNotice describes approved prefixes left out of the set MeshMux
// sent to Headscale. It names only a count, never a network, and states what
// happened to them: a replaced set no longer approves them, and a cleared set
// withdraws them with everything else.
func meshRouteDroppedNotice(count int, cleared bool) string {
	if count == 0 {
		return ""
	}
	if cleared {
		return fmt.Sprintf("另有 %d 条无法发送给 Headscale 的已批准前缀随本次清空一并撤销（记录 %s 审计事件）。",
			count, codeMeshRouteUntrackedDropped)
	}
	return fmt.Sprintf("另有 %d 条无法发送给 Headscale 的已批准前缀已被移出该集合（记录 %s 审计事件）；它们不再是批准状态，需要时请重新声明并批准。",
		count, codeMeshRouteUntrackedDropped)
}

// meshRoutePrefixIn reports membership with canonical comparison, so a
// different spelling of the same network is still the same prefix.
func meshRoutePrefixIn(list []string, prefix string) bool {
	for _, raw := range list {
		trimmed := strings.TrimSpace(raw)
		if trimmed == prefix {
			return true
		}
		if canonical, err := mesh.ParseRoutePrefix(trimmed); err == nil && canonical.String() == prefix {
			return true
		}
	}
	return false
}

// meshRouteObservedFromNode derives the single observation value the store
// keeps from the three route lists one node reports. Served is the strongest
// evidence, then approved, then advertised; absent means Headscale reported
// nothing for the prefix.
func meshRouteObservedFromNode(node headscale.Node, prefix string) mesh.RouteObserved {
	if meshRoutePrefixIn(node.SubnetRoutes, prefix) {
		return mesh.RouteObservedServed
	}
	if meshRoutePrefixIn(node.ApprovedRoutes, prefix) {
		return mesh.RouteObservedApproved
	}
	if meshRoutePrefixIn(node.AvailableRoutes, prefix) {
		return mesh.RouteObservedAdvertised
	}
	return mesh.RouteObservedNone
}

// meshRouteObservations builds the per-prefix evidence of one device for the
// reconcile pass. Every reported prefix is included, and a declared prefix the
// node no longer reports is recorded as "nothing reported" so stale evidence
// does not survive a read.
func (app *Server) meshRouteObservations(deviceID string, node headscale.Node) ([]MeshRouteObservation, error) {
	tracked, err := app.store.listMeshRoutes(deviceID)
	if err != nil {
		return nil, err
	}
	observed := make(map[string]mesh.RouteObserved, len(tracked))
	add := func(raw string, state mesh.RouteObserved) {
		canonical, err := mesh.ParseRoutePrefix(raw)
		if err != nil {
			return
		}
		prefix := canonical.String()
		if current, ok := observed[prefix]; ok && meshRouteObservedRank(current) >= meshRouteObservedRank(state) {
			return
		}
		observed[prefix] = state
	}
	for _, raw := range node.AvailableRoutes {
		add(raw, mesh.RouteObservedAdvertised)
	}
	for _, raw := range node.ApprovedRoutes {
		add(raw, mesh.RouteObservedApproved)
	}
	for _, raw := range node.SubnetRoutes {
		add(raw, mesh.RouteObservedServed)
	}
	for _, route := range tracked {
		if route.Desired == mesh.RouteDesiredRevoked {
			continue
		}
		if _, ok := observed[route.Prefix]; !ok {
			observed[route.Prefix] = mesh.RouteObservedNone
		}
	}
	out := make([]MeshRouteObservation, 0, len(observed))
	for prefix, state := range observed {
		out = append(out, MeshRouteObservation{Prefix: prefix, Observed: state})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out, nil
}

func meshRouteObservedRank(state mesh.RouteObserved) int {
	switch state {
	case mesh.RouteObservedServed:
		return 3
	case mesh.RouteObservedApproved:
		return 2
	case mesh.RouteObservedAdvertised:
		return 1
	default:
		return 0
	}
}

// recordUntrackedApprovedRoutes appends one MESH_ROUTE_UNTRACKED event for each
// approved prefix Headscale reported that no device declared. The prefix stays
// in the approved set; only an audit event records that the Hub saw it without
// adopting or approving it.
func (app *Server) recordUntrackedApprovedRoutes(deviceID string, node headscale.Node, operationID string, now time.Time) error {
	tracked, err := app.store.listMeshRoutes(deviceID)
	if err != nil {
		return err
	}
	known := make(map[string]struct{}, len(tracked))
	for _, route := range tracked {
		known[route.Prefix] = struct{}{}
	}
	for _, raw := range node.ApprovedRoutes {
		canonical, err := mesh.ParseRoutePrefix(raw)
		if err != nil {
			continue
		}
		prefix := canonical.String()
		if _, ok := known[prefix]; ok {
			continue
		}
		if _, _, err = app.store.recordMeshRouteObservation(deviceID, prefix, mesh.RouteObservedApproved, operationID, now); err != nil {
			return err
		}
	}
	return nil
}

// meshSplitRoutePrefixes turns one textarea into declaration entries. Blank
// lines are ignored by the domain normaliser; a comma is accepted because
// operators paste Headscale's own list form.
func meshSplitRoutePrefixes(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	})
}

// meshReconcile performs one explicit `nodes list` and records what Headscale
// reports for every non-revoked device. It is synchronous: no goroutine outlives
// the request, so the page the operator sees is the state the check produced.
//
// A device with a node id that is present stays as it is (or keeps its revoking
// intent); a node id that is gone settles the device (registered → expired,
// revoking → revoked). A device that never registered carries no node id and is
// not guessed from a hostname: it only gets a fresh observation timestamp.
func (app *Server) meshReconcile(w http.ResponseWriter, r *http.Request, sess session) {
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	nodes, err := app.mesh.ListNodes(ctx, "")
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshReconcileFailed, "无法读取 Headscale 节点。", "请检查 Headscale 服务与 Web 服务组权限后重试。")
		return
	}
	present := make(map[uint64]headscale.Node, len(nodes))
	for _, node := range nodes {
		present[node.ID] = node
	}
	records, err := app.store.listMeshDevices()
	if err != nil {
		app.meshFail(w, r, err, codeMeshReconcileFailed, "无法读取 Mesh 设备。", "请检查数据库后重试。")
		return
	}
	now := app.now()
	var checked, changed, failed, routesChecked, routesUntracked, routesFailed int
	for _, record := range records {
		if record.Status == mesh.StatusRevoked {
			continue
		}
		observed := uint64(0)
		var node headscale.Node
		hasNode := false
		if record.HeadscaleNodeID != 0 {
			if found, ok := present[record.HeadscaleNodeID]; ok {
				observed = record.HeadscaleNodeID
				node, hasNode = found, true
			}
		}
		next, observeErr := app.store.recordMeshObservation(record.ID, observed, now)
		if observeErr != nil {
			// One hand-edited or contradictory row must not hide the rest of the
			// inventory. The stable code is logged; the summary reports partial.
			failed++
			app.event(r, meshErrorCode(observeErr))
			continue
		}
		checked++
		if next.Status != record.Status {
			changed++
		}
		if !hasNode {
			continue
		}
		// Route evidence comes from the same single `nodes list` read. One
		// call per device keeps a contradictory device row from hiding the
		// rest of the inventory; a route failure is reported as partial, never
		// as a successful observation.
		observations, buildErr := app.meshRouteObservations(record.ID, node)
		if buildErr != nil {
			routesFailed++
			app.event(r, meshErrorCode(buildErr))
			continue
		}
		result, routeErr := app.store.reconcileMeshRoutes(record.ID, observations, operation(r), now)
		if routeErr != nil {
			routesFailed++
			app.event(r, meshErrorCode(routeErr))
			continue
		}
		routesChecked += result.Tracked
		routesUntracked += result.Untracked
	}
	app.event(r, "MESH_DEVICES_RECONCILED")
	message := fmt.Sprintf("已核对 %d 台设备，%d 台状态更新。在线与 Tailnet IP 来自本次 Headscale 读取。", checked, changed)
	if routesChecked > 0 || routesUntracked > 0 {
		message += fmt.Sprintf(" 已记录 %d 条路由观测；%d 条未声明前缀只写入审计事件，不会被自动批准。", routesChecked, routesUntracked)
	}
	class := "notice"
	if failed > 0 || routesFailed > 0 {
		message = fmt.Sprintf("已核对 %d 台设备，%d 台状态更新，%d 台设备记录无法核对", checked, changed, failed)
		if routesFailed > 0 {
			message += fmt.Sprintf("，%d 台设备的路由观测无法记录", routesFailed)
		}
		message += "（已记录稳定错误码）。"
		class = "error"
	}
	app.renderMesh(w, r, sess, nil, message, class)
}

// meshRevoke records the revocation intent and then attempts the remote removal
// once. The intent is written first on purpose: a Headscale failure must leave a
// retryable revoking device, never a vanished record with a live node.
//
// The handler is idempotent. Revoking an already revoked device reports success
// without touching Headscale again; revoking a revoking device retries the
// remote removal, which is what the retry button does. A device that never
// registered has no node to remove, so its intent alone settles it.
func (app *Server) meshRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	now := app.now()
	// Read the declarations before the revocation transaction settles them:
	// after it, every route is already revoked and the handler could not tell
	// whether the node ever carried an approved prefix. A routing device has
	// its approvals withdrawn before the node is removed, so the control plane
	// never keeps a route approved through a half-finished deletion.
	routes, routeErr := app.store.listMeshRoutes(deviceID)
	if routeErr != nil {
		app.meshFail(w, r, routeErr, codeMeshDeviceRevokeFailed, "无法读取子网路由记录。", "请刷新页面确认设备后重试。")
		return
	}
	record, _, err := app.store.requestMeshDeviceRevocation(deviceID, "USER_DELETE", now)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceRevokeFailed, "无法记录注销意图。", "请刷新页面确认设备存在后重试。")
		return
	}
	app.event(r, "MESH_DEVICE_REVOCATION_REQUESTED")
	if record.Status == mesh.StatusRevoked {
		// Idempotent repeat: nothing is left to remove.
		app.event(r, "MESH_DEVICE_REVOKED")
		app.renderMesh(w, r, sess, nil, "设备已注销，无需再次操作。", "notice")
		return
	}
	if record.HeadscaleNodeID != 0 {
		ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
		if len(routes) > 0 {
			if _, clearErr := app.mesh.ClearApprovedRoutes(ctx, record.HeadscaleNodeID); clearErr != nil && headscale.CodeOf(clearErr) != headscale.CodeNotFound {
				cancel()
				app.event(r, meshErrorCode(clearErr))
				app.renderMesh(w, r, sess, nil,
					"注销意图已保存，但撤销路由批准未完成（"+meshErrorCode(clearErr)+"）。设备保持“注销中”，可重试远端删除。", "error")
				return
			}
			app.event(r, routeEventWithdrawn)
		}
		removeErr := app.removeMeshNode(ctx, record.HeadscaleNodeID)
		cancel()
		if removeErr != nil {
			app.event(r, "MESH_DEVICE_REVOCATION_PENDING")
			app.renderMesh(w, r, sess, nil,
				"注销意图已保存，但 Headscale 删除未完成（"+meshErrorCode(removeErr)+"）。设备保持“注销中”，可重试远端删除。", "error")
			return
		}
	}
	settled, err := app.store.recordMeshObservation(deviceID, 0, now)
	if err != nil {
		app.meshFail(w, r, err, codeMeshDeviceRevokeFailed, "注销意图已保存，但状态未确认。", "请稍后重试注销，或检查服务日志。")
		return
	}
	if settled.Status == mesh.StatusRevoked {
		app.event(r, "MESH_DEVICE_REVOKED")
		app.renderMesh(w, r, sess, nil, "设备已注销；其他订阅用户、凭据与订阅 Token 不受影响。", "notice")
		return
	}
	app.event(r, "MESH_DEVICE_REVOCATION_PENDING")
	app.renderMesh(w, r, sess, nil, "注销意图已保存，远端删除尚未确认。", "notice")
}

// removeMeshNode expires the node first and then deletes it. Expiring is the
// reversible half: even if the delete fails, the node is logged out. A node that
// Headscale already reports as absent is treated as settled.
func (app *Server) removeMeshNode(ctx context.Context, nodeID uint64) error {
	if err := app.mesh.ExpireNode(ctx, nodeID); err != nil && headscale.CodeOf(err) != headscale.CodeNotFound {
		return err
	}
	if err := app.mesh.DeleteNode(ctx, nodeID); err != nil && headscale.CodeOf(err) != headscale.CodeNotFound {
		return err
	}
	return nil
}

// ensureMeshUser resolves one Headscale user by name and creates the shared
// default user of D2 when it is missing. Creating an existing user is the
// ordinary repeat case, so HEADSCALE_ALREADY_EXISTS is resolved as success.
//
// Only the shared default user may be created here. Any other name has to exist
// already: minting an arbitrary Headscale user from a form field would let one
// request reshape the tailnet's user list, which is not what the page offers.
// The returned user carries the id a pre-auth key needs, so callers never have
// to guess it from the name.
func (app *Server) ensureMeshUser(ctx context.Context, user string) (headscale.User, error) {
	users, err := app.mesh.ListUsers(ctx)
	if err != nil {
		return headscale.User{}, err
	}
	for _, existing := range users {
		if existing.Name == user {
			return existing, nil
		}
	}
	if user != mesh.DefaultHeadscaleUser {
		return headscale.User{}, meshError(codeMeshHeadscaleUserUnknown, "the named headscale user does not exist")
	}
	created, err := app.mesh.CreateUser(ctx, user)
	if err != nil {
		if headscale.CodeOf(err) == headscale.CodeAlreadyExists {
			// The user appeared between the list and the create. Read it back
			// once so the caller has the id the pre-auth key needs.
			users, listErr := app.mesh.ListUsers(ctx)
			if listErr != nil {
				return headscale.User{}, listErr
			}
			for _, existing := range users {
				if existing.Name == user {
					return existing, nil
				}
			}
			// A control plane that reports the user as existing but omits it
			// from the list is still idempotent for the create contract. The
			// caller will obtain the id from its own list before minting a key.
			return headscale.User{Name: user}, nil
		}
		return headscale.User{}, err
	}
	return created, nil
}

// createMeshDevice persists one device with a MeshMux-assigned node name. The
// label is human-readable when it can be, and a random suffix resolves the rare
// collision with a device of the same Headscale user that still occupies a name.
func (app *Server) createMeshDevice(spec mesh.DeviceSpec, now time.Time) (MeshDeviceRecord, error) {
	spec.NodeName = meshNodeName(spec.DisplayName)
	record, err := app.store.createMeshDevice(spec, now)
	if err == nil || meshErrorCode(err) != mesh.CodeNodeNameDuplicate {
		return record, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		suffix, idErr := subscription.NewID()
		if idErr != nil {
			return MeshDeviceRecord{}, idErr
		}
		spec.NodeName = meshNodeNameWithSuffix(spec.DisplayName, suffix[:6])
		record, err = app.store.createMeshDevice(spec, now)
		if err == nil || meshErrorCode(err) != mesh.CodeNodeNameDuplicate {
			return record, err
		}
	}
	return MeshDeviceRecord{}, err
}

// meshNodeName derives the MeshMux-assigned Headscale node name. It is not the
// identity (the record id is) and it is not the operator label: the label is
// mutable, the node name stays as assigned while the device occupies it.
func meshNodeName(displayName string) string { return meshNodeNameWithSuffix(displayName, "") }

func meshNodeNameWithSuffix(displayName, suffix string) string {
	base := "mesh"
	if slug := meshNodeSlug(displayName); slug != "" {
		base += "-" + slug
	}
	limit := 63 - len(suffix)
	if len(base) > limit {
		base = base[:limit]
	}
	base = strings.Trim(base, "-")
	if base == "" {
		base = "mesh"
	}
	return base + suffix
}

// meshNodeSlug reduces a display label to the lowercase letters, digits and
// single hyphens a node name accepts. A label written entirely in a script
// without ASCII letters yields no slug, and the caller falls back to a neutral
// MeshMux prefix instead of transliterating the label into an identity.
func meshNodeSlug(displayName string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(displayName) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			hyphen = false
		case !hyphen && b.Len() > 0:
			b.WriteByte('-')
			hyphen = true
		}
		if b.Len() >= 55 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// renderMesh renders the page. The response that carries a plaintext key must
// never be cached, reused from history or revalidated.
func (app *Server) renderMesh(w http.ResponseWriter, r *http.Request, sess session, disclosure *meshKeyDisclosure, notice, noticeClass string) {
	view, err := app.meshViewModel(r)
	if err != nil {
		app.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取 Mesh 设备。", "请检查数据库和服务日志。")
		return
	}
	view.Disclosure = disclosure
	view.Notice = notice
	view.NoticeClass = noticeClass
	w.Header().Set("Cache-Control", "private, no-store")
	app.render(w, r, 200, MeshPage(pageData{Title: "Mesh 设备", Path: "/mesh", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, view))
}

func (app *Server) meshDisclosure(record MeshDeviceRecord, secret string, expires time.Time) *meshKeyDisclosure {
	d := &meshKeyDisclosure{Device: record.DisplayName, Secret: secret, Expires: expires.UTC().Format("2006-01-02 15:04:05 UTC")}
	d.LoginConfigured = app.cfg.HeadscaleOrigin != ""
	if !d.LoginConfigured {
		return d
	}
	cmd := "tailscale up --login-server=" + app.cfg.HeadscaleOrigin + " --auth-key=<上方 Key>"
	if routes, err := app.store.listMeshRoutes(record.ID); err == nil {
		var advertised []string
		for _, rt := range routes {
			if rt.Desired == mesh.RouteDesiredAdvertised || rt.Desired == mesh.RouteDesiredApproved {
				advertised = append(advertised, rt.Prefix)
			}
		}
		if len(advertised) > 0 {
			cmd += " --advertise-routes=" + strings.Join(advertised, ",")
		}
	}
	d.JoinCommand = cmd
	return d
}

// meshViewModel builds the read projection. It writes nothing: the live
// Headscale read only annotates the rows, and a failed read is reported as a
// code instead of being rendered as "offline" or "not found".
func (app *Server) meshViewModel(r *http.Request) (meshPageView, error) {
	view := meshPageView{
		Devices: []meshDeviceView{}, Users: []meshUserView{}, Subscribers: []meshSubscriberView{},
		DefaultUser: mesh.DefaultHeadscaleUser,
	}
	records, err := app.store.listMeshDevices()
	if err != nil {
		return view, err
	}
	subscribers, err := app.store.listSubscribers()
	if err != nil {
		return view, err
	}
	names := make(map[string]string, len(subscribers))
	for _, sub := range subscribers {
		names[sub.ID] = sub.DisplayName
		view.Subscribers = append(view.Subscribers, meshSubscriberView{ID: sub.ID, DisplayName: sub.DisplayName, State: string(sub.State)})
	}

	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	if users, usersErr := app.mesh.ListUsers(ctx); usersErr != nil {
		view.UsersNotice = meshErrorCode(usersErr)
	} else {
		for _, user := range users {
			view.Users = append(view.Users, meshUserView{ID: user.ID, Name: user.Name})
		}
		sort.Slice(view.Users, func(i, j int) bool { return view.Users[i].Name < view.Users[j].Name })
	}
	present := map[uint64]headscale.Node{}
	if nodes, nodesErr := app.mesh.ListNodes(ctx, ""); nodesErr != nil {
		view.NodesNotice = meshErrorCode(nodesErr)
	} else {
		for _, node := range nodes {
			present[node.ID] = node
		}
	}

	claimedNodes := make(map[uint64]string, len(records))
	for _, record := range records {
		if record.HeadscaleNodeID != 0 {
			claimedNodes[record.HeadscaleNodeID] = record.ID
		}
	}
	for _, record := range records {
		entry := meshDeviceView{
			ID: record.ID, DisplayName: record.DisplayName,
			PurposeLabel: meshPurposeLabel(record.Purpose), PlatformLabel: meshPlatformLabel(record.Platform),
			HeadscaleUser: record.HeadscaleUser, NodeName: record.NodeName,
			SubscriberID: record.SubscriberID, SubscriberName: names[record.SubscriberID],
			StatusLabel: meshStatusLabel(record.Status), StatusClass: meshStatusClass(record.Status),
			RevokeReason: record.RevokeReason,
			CanIssue:     record.Status == mesh.StatusPending || record.Status == mesh.StatusExpired,
			CanConfig:    record.Purpose == mesh.PurposeProxyMesh && record.SubscriberID != "" && record.Status == mesh.StatusPending,
			CanRevoke:    record.Status != mesh.StatusRevoked,
			CanRetry:     record.Status == mesh.StatusRevoking,
		}
		if record.HeadscaleNodeID != 0 {
			entry.NodeID = strconv.FormatUint(record.HeadscaleNodeID, 10)
		}
		if record.ObservedAt != 0 {
			entry.ObservedAt = time.Unix(record.ObservedAt, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		}
		entry.Online, entry.OnlineClass, entry.TailnetIP = meshOnlineState(record, present, view.NodesNotice)
		keys, keyErr := app.store.listMeshEnrollmentKeys(record.ID)
		if keyErr != nil {
			return view, keyErr
		}
		entry.KeyLabel, entry.KeyClass, entry.KeyExpires = meshKeyState(keys, app.now())
		routes, routeErr := app.store.listMeshRoutes(record.ID)
		if routeErr != nil {
			return view, routeErr
		}
		node, nodeKnown := present[record.HeadscaleNodeID]
		entry.Routes = meshRouteViews(record, routes, node, nodeKnown && record.HeadscaleNodeID != 0)
		if view.NodesNotice == "" && record.Status == mesh.StatusPending {
			for _, candidate := range present {
				if claimedNodes[candidate.ID] != "" || !meshNodeMatchesName(candidate, record.NodeName) {
					continue
				}
				if candidate.UserName != "" && candidate.UserName != record.HeadscaleUser {
					continue
				}
				entry.Claims = append(entry.Claims, meshClaimView{
					NodeID:   strconv.FormatUint(candidate.ID, 10),
					Name:     candidate.Name,
					UserName: candidate.UserName,
				})
			}
			sort.Slice(entry.Claims, func(i, j int) bool { return entry.Claims[i].NodeID < entry.Claims[j].NodeID })
		}
		view.Devices = append(view.Devices, entry)
	}
	return view, nil
}

// meshRouteViews merges the stored declarations with the same read-only node
// snapshot the card already shows. It performs no Headscale call: approved,
// available and served come from the `nodes list` result that annotated the
// page, while the desired state, latest observation and audit key stay the Hub
// record. A prefix only Headscale reports is rendered as "未声明" and offers no
// action, because adopting an advertisement automatically would defeat the
// explicit-approval rule.
func meshRouteViews(record MeshDeviceRecord, tracked []MeshRouteRecord, node headscale.Node, nodeKnown bool) []meshRouteView {
	entries := make(map[string]*meshRouteView, len(tracked))
	actionsAllowed := record.Status != mesh.StatusRevoked && record.Status != mesh.StatusRevoking && record.HeadscaleNodeID != 0
	for _, route := range tracked {
		entries[route.Prefix] = &meshRouteView{
			Prefix:        route.Prefix,
			DesiredLabel:  meshRouteDesiredLabel(route.Desired),
			DesiredClass:  meshRouteDesiredClass(route.Desired),
			ObservedLabel: meshRouteObservedLabel(route.Observed),
			ObservedAt:    meshRouteRecordTime(route.UpdatedAt),
			OperationID:   route.OperationID,
			CanApprove:    actionsAllowed && route.Desired == mesh.RouteDesiredAdvertised,
			CanWithdraw:   actionsAllowed && route.Desired == mesh.RouteDesiredApproved,
		}
	}
	if nodeKnown {
		available := meshRoutePrefixSet(node.AvailableRoutes)
		approved := meshRoutePrefixSet(node.ApprovedRoutes)
		served := meshRoutePrefixSet(node.SubnetRoutes)
		entryFor := func(prefix string) *meshRouteView {
			entry, ok := entries[prefix]
			if !ok {
				entry = &meshRouteView{Prefix: prefix, DesiredLabel: "未声明", DesiredClass: "badge failure", ObservedLabel: "未声明", ObservedAt: "—"}
				entries[prefix] = entry
			}
			entry.RemoteKnown = true
			return entry
		}
		for prefix := range available {
			entryFor(prefix).Available = true
		}
		for prefix := range approved {
			entryFor(prefix).Approved = true
		}
		for prefix := range served {
			entryFor(prefix).Served = true
		}
	}
	out := make([]meshRouteView, 0, len(entries))
	for _, entry := range entries {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

func meshRoutePrefixSet(list []string) map[string]struct{} {
	set := make(map[string]struct{}, len(list))
	for _, raw := range list {
		canonical, err := mesh.ParseRoutePrefix(raw)
		if err != nil {
			continue
		}
		set[canonical.String()] = struct{}{}
	}
	return set
}

func meshRouteDesiredLabel(desired mesh.RouteDesired) string {
	switch desired {
	case mesh.RouteDesiredAdvertised:
		return "待批准"
	case mesh.RouteDesiredApproved:
		return "已批准"
	case mesh.RouteDesiredRevoked:
		return "已撤销"
	default:
		return "未知"
	}
}

func meshRouteDesiredClass(desired mesh.RouteDesired) string {
	switch desired {
	case mesh.RouteDesiredApproved:
		return "badge accent"
	case mesh.RouteDesiredRevoked:
		return "badge failure"
	default:
		return "badge"
	}
}

func meshRouteObservedLabel(observed mesh.RouteObserved) string {
	switch observed {
	case mesh.RouteObservedAdvertised:
		return "已通告"
	case mesh.RouteObservedApproved:
		return "已批准"
	case mesh.RouteObservedServed:
		return "已服务"
	default:
		return "未上报"
	}
}

func meshRouteRecordTime(updatedAt int64) string {
	if updatedAt == 0 {
		return "—"
	}
	return time.Unix(updatedAt, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// meshOnlineState reports what the single Headscale read shows. Absence is a
// statement about the previous observation only: a device that never registered
// has no node id, and a failed read is "未核对", never "离线".
func meshOnlineState(record MeshDeviceRecord, present map[uint64]headscale.Node, readCode string) (string, string, string) {
	if readCode != "" {
		return "未核对", "badge", "—"
	}
	if record.HeadscaleNodeID == 0 {
		return "未注册", "badge", "—"
	}
	node, ok := present[record.HeadscaleNodeID]
	if !ok {
		return "未在 Headscale 中", "badge failure", "—"
	}
	address := "—"
	if len(node.IPAddresses) > 0 {
		address = node.IPAddresses[0]
	}
	if node.Online {
		return "在线", "badge accent", address
	}
	return "离线", "badge", address
}

// meshKeyState summarises the current key of one device. A live issued key wins
// over an older terminal one, and a record that lapsed but was not retired yet is
// reported as expired, because that is what it is.
func meshKeyState(keys []MeshEnrollmentKeyRecord, now time.Time) (string, string, string) {
	if len(keys) == 0 {
		return "尚无 Key", "badge", ""
	}
	var latest MeshEnrollmentKeyRecord
	for _, key := range keys {
		if key.State == mesh.KeyIssued {
			latest = key
			break
		}
		if key.IssuedAt >= latest.IssuedAt {
			latest = key
		}
	}
	switch latest.State {
	case mesh.KeyIssued:
		expires := time.Unix(latest.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		if !now.Before(time.Unix(latest.ExpiresAt, 0)) {
			return "已过期 · 待回收", "badge", expires
		}
		return "已签发 · 未使用", "badge accent", expires
	case mesh.KeyConsumed:
		return "已消费", "badge accent", ""
	case mesh.KeyExpired:
		return "已过期", "badge", ""
	case mesh.KeyRevoked:
		return "已撤销", "badge", ""
	default:
		return "状态未知", "badge", ""
	}
}

func meshPurposeLabel(purpose mesh.Purpose) string {
	switch purpose {
	case mesh.PurposeProxyMesh:
		return "代理 + Mesh"
	case mesh.PurposeMeshOnly:
		return "仅 Mesh"
	case mesh.PurposeSubnetRouter:
		return "子网路由"
	default:
		return "未知用途"
	}
}

func meshPlatformLabel(platform mesh.Platform) string {
	switch platform {
	case mesh.PlatformIOS:
		return "iOS"
	case mesh.PlatformAndroid:
		return "Android"
	case mesh.PlatformLinux:
		return "Linux"
	case mesh.PlatformNAS:
		return "NAS"
	default:
		return "其他"
	}
}

func meshStatusLabel(status mesh.Status) string {
	switch status {
	case mesh.StatusPending:
		return "待注册"
	case mesh.StatusRegistered:
		return "已注册"
	case mesh.StatusExpired:
		return "已过期"
	case mesh.StatusRevoking:
		return "注销中 · 等待远端确认"
	case mesh.StatusRevoked:
		return "已注销"
	case mesh.StatusFailed:
		return "注册失败"
	default:
		return "未知状态"
	}
}

func meshStatusClass(status mesh.Status) string {
	switch status {
	case mesh.StatusRegistered:
		return "badge accent"
	case mesh.StatusRevoking, mesh.StatusFailed:
		return "badge failure"
	default:
		return "badge"
	}
}

// meshErrorCode returns the stable code carried by a store, domain or adapter
// error, without its detail. Nothing else from the error value is logged or
// rendered: a Headscale refusal can quote a socket path and a store detail can
// quote a label. Only a registered code is returned; anything else collapses to
// codeMeshInternalError so a message can never become a code.
func meshErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var domain *mesh.DomainError
	if errors.As(err, &domain) {
		return meshCodeOrInternal(domain.Code)
	}
	var adapter *headscale.Error
	if errors.As(err, &adapter) {
		return meshCodeOrInternal(adapter.Code)
	}
	return meshCodeOrInternal(errorCodeOf(err))
}

// meshCodeOrInternal keeps a registered code and refuses everything else.
func meshCodeOrInternal(code string) string {
	if isMeshCode(code) {
		return code
	}
	return codeMeshInternalError
}

// meshFail maps one sanitized store or domain error onto the stable HTTP
// contract. A malformed identifier is a client error; a well-formed unknown one
// is 404. Headscale refusals keep their own stable code and are 503: the Hub
// cannot prove the control plane answered, so no change is claimed.
//
// The status is chosen from registered codes only. An unregistered value has
// already become codeMeshInternalError, so no prefix scan over free-form text
// decides an HTTP status here.
func (app *Server) meshFail(w http.ResponseWriter, r *http.Request, err error, fallback, message, next string) {
	code := meshErrorCode(err)
	if code == "" {
		code = meshCodeOrInternal(fallback)
	}
	app.fail(w, r, meshStatus(code), code, message, next)
}

// meshStatus is the HTTP class of one Mesh failure code. Everything not listed
// is a conflict: the request was well formed but the recorded state refused it.
func meshStatus(code string) int {
	if _, ok := headscaleCodes[code]; ok {
		return http.StatusServiceUnavailable
	}
	if _, ok := meshExportCodes[code]; ok {
		return http.StatusConflict
	}
	switch code {
	case codeDatabaseUnavailable:
		return http.StatusServiceUnavailable
	case codeMeshDeviceNotFound, codeMeshEnrollmentKeyNotFound, codeMeshClaimNodeNotFound,
		codeMeshRouteNotFound:
		return http.StatusNotFound
	case codeMeshDeviceCorrupt, codeMeshRouteCorrupt, codeMeshInternalError:
		return http.StatusInternalServerError
	case mesh.CodeDeviceIDInvalid, mesh.CodeDisplayNameInvalid, codeDisplayNameInvalid,
		mesh.CodePurposeInvalid, mesh.CodePlatformInvalid, mesh.CodeSubscriberBindingInvalid,
		mesh.CodeNodeNameInvalid, mesh.CodeHeadscaleUserInvalid,
		mesh.CodeRevokeReasonInvalid, mesh.CodeKeyIDInvalid, mesh.CodeKeyDeviceIDInvalid,
		mesh.CodeKeySecretInvalid, mesh.CodeKeyStateInvalid,
		mesh.CodeRoutePrefixInvalid, mesh.CodeRoutePrefixNotRoutable,
		mesh.CodeRouteDeclarationInvalid, mesh.CodeRouteDesiredInvalid,
		mesh.CodeRouteObservedInvalid, mesh.CodeRouteSourceInvalid:
		return http.StatusBadRequest
	}
	return http.StatusConflict
}

// meshControlPlaneFail reports a Headscale refusal with its own code. The code
// is the only detail that leaves the adapter, and only a registered one is
// forwarded: a foreign error goes through meshFail's sanitizing path.
func (app *Server) meshControlPlaneFail(w http.ResponseWriter, r *http.Request, err error, fallback, message, next string) {
	code := headscale.CodeOf(err)
	if _, ok := headscaleCodes[code]; !ok {
		app.meshFail(w, r, err, fallback, message, next)
		return
	}
	app.fail(w, r, http.StatusServiceUnavailable, code, message, next)
}
