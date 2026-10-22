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
//     a URL, a log line or a second response.
//
// A pending device never becomes registered through this page: registration
// needs an observed Headscale node id, which the enrollment consumer records
// together with the one-time key (that endpoint is a later slice). The list
// therefore renders "未注册" instead of guessing a node from a hostname.

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

// meshKeyDisclosure carries one plaintext enrollment key. It is filled only for
// the single POST response that issues it.
type meshKeyDisclosure struct {
	Device  string
	Secret  string
	Expires string
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
	CanRevoke      bool
	CanRetry       bool
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
		app.meshFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "设备名称不正确。", "请使用 1-80 个可打印字符。")
		return
	}
	purpose := mesh.Purpose(strings.TrimSpace(r.PostForm.Get("purpose")))
	platform := mesh.Platform(strings.TrimSpace(r.PostForm.Get("platform")))
	subscriberID := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	if err := mesh.ValidateSubscriberBinding(purpose, subscriberID); err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "用途与订阅用户绑定不一致。", "proxy_mesh 必须选择订阅用户；mesh_only 必须留空；subnet_router 可留空。")
		return
	}
	if err := platform.Validate(); err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "客户端平台不正确。", "请从页面提供的选项中选择。")
		return
	}
	user := strings.TrimSpace(r.PostForm.Get("headscale_user"))
	if user == "" {
		user = mesh.DefaultHeadscaleUser
	}
	user, err := mesh.NormalizeHeadscaleUser(user)
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "Headscale 用户不正确。", "请使用页面列出的 Headscale 用户。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	if err = app.ensureMeshUser(ctx, user); err != nil {
		app.meshControlPlaneFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "无法确认 Headscale 用户。", "请检查 Headscale 服务与 Web 服务组权限后重试。")
		return
	}
	record, err := app.createMeshDevice(mesh.DeviceSpec{
		DisplayName:   displayName,
		Purpose:       purpose,
		Platform:      platform,
		SubscriberID:  subscriberID,
		HeadscaleUser: user,
	}, app.now())
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_CREATE_FAILED", "无法创建 Mesh 设备。", "请检查名称、用途与所选订阅用户后重试。")
		return
	}
	app.event(r, "MESH_DEVICE_CREATED")
	// The device is durable at this point. A key that cannot be minted is
	// reported as its own failure with the device kept: the operator can re-sign
	// from the list, and hiding the created device would misstate the audit
	// trail.
	key, secret, err := app.store.issueMeshEnrollmentKey(record.ID, app.now())
	if err != nil {
		app.event(r, "MESH_DEVICE_KEY_ISSUE_FAILED")
		app.meshFail(w, r, err, "MESH_DEVICE_KEY_ISSUE_FAILED", "设备已创建，但一次性 Key 未签发。", "请在设备列表中重新签发 Key。")
		return
	}
	app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_ISSUED")
	app.renderMesh(w, r, sess, app.meshDisclosure(record, secret, key.ExpiresAt), "设备已创建。一次性 Key 只在本次响应中显示。", "notice")
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
// The Headscale pre-auth key is a separate artifact minted by the enrollment
// consumer when a device actually registers; this handler only manages the
// Hub-side one-time key and deliberately calls no Headscale key API.
func (app *Server) meshRekey(w http.ResponseWriter, r *http.Request, sess session) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	record, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_REKEY_FAILED", "无法读取 Mesh 设备。", "请刷新页面后重试。")
		return
	}
	now := app.now()
	if record.Status != mesh.StatusPending && record.Status != mesh.StatusExpired {
		app.fail(w, r, 409, "MESH_DEVICE_NOT_REENROLLABLE", "当前状态不能签发一次性 Key。", "只有待注册或已过期设备可以重新签发。")
		return
	}
	keys, err := app.store.listMeshEnrollmentKeys(deviceID)
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_REKEY_FAILED", "无法读取 Key 记录。", "请检查数据库后重试。")
		return
	}
	for _, key := range keys {
		if key.State != mesh.KeyIssued || !now.Before(time.Unix(key.ExpiresAt, 0)) {
			// Lapsed keys are retired by the issue path as expired; revoking one
			// here would report an early withdrawal that did not happen.
			continue
		}
		if _, err = app.store.revokeMeshEnrollmentKey(key.ID); err != nil {
			app.meshFail(w, r, err, "MESH_DEVICE_REKEY_FAILED", "无法作废旧的一次性 Key。", "请刷新页面确认 Key 状态后重试。")
			return
		}
		app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_REVOKED")
	}
	if record.Status == mesh.StatusExpired {
		record, err = app.store.reenrollMeshDevice(deviceID, now)
		if err != nil {
			app.meshFail(w, r, err, "MESH_DEVICE_REKEY_FAILED", "无法让设备重新入网。", "请确认设备已过期且节点名未被占用。")
			return
		}
		app.event(r, "MESH_DEVICE_REENROLLED")
	}
	key, secret, err := app.store.issueMeshEnrollmentKey(deviceID, now)
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_REKEY_FAILED", "无法签发新的一次性 Key。", "请确认设备仍为待注册状态。")
		return
	}
	app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_REISSUED")
	app.renderMesh(w, r, sess, app.meshDisclosure(record, secret, key.ExpiresAt), "旧 Key 已作废，新 Key 只在本次响应中显示。", "notice")
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
		app.meshControlPlaneFail(w, r, err, "MESH_RECONCILE_FAILED", "无法读取 Headscale 节点。", "请检查 Headscale 服务与 Web 服务组权限后重试。")
		return
	}
	present := make(map[uint64]struct{}, len(nodes))
	for _, node := range nodes {
		present[node.ID] = struct{}{}
	}
	records, err := app.store.listMeshDevices()
	if err != nil {
		app.meshFail(w, r, err, "MESH_RECONCILE_FAILED", "无法读取 Mesh 设备。", "请检查数据库后重试。")
		return
	}
	now := app.now()
	var checked, changed, failed int
	for _, record := range records {
		if record.Status == mesh.StatusRevoked {
			continue
		}
		observed := uint64(0)
		if record.HeadscaleNodeID != 0 {
			if _, ok := present[record.HeadscaleNodeID]; ok {
				observed = record.HeadscaleNodeID
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
	}
	app.event(r, "MESH_DEVICES_RECONCILED")
	message := fmt.Sprintf("已核对 %d 台设备，%d 台状态更新。在线与 Tailnet IP 来自本次 Headscale 读取。", checked, changed)
	class := "notice"
	if failed > 0 {
		message = fmt.Sprintf("已核对 %d 台设备，%d 台状态更新，%d 台记录无法核对（已记录稳定错误码）。", checked, changed, failed)
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
	record, _, err := app.store.requestMeshDeviceRevocation(deviceID, "USER_DELETE", now)
	if err != nil {
		app.meshFail(w, r, err, "MESH_DEVICE_REVOKE_FAILED", "无法记录注销意图。", "请刷新页面确认设备存在后重试。")
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
		app.meshFail(w, r, err, "MESH_DEVICE_REVOKE_FAILED", "注销意图已保存，但状态未确认。", "请稍后重试注销，或检查服务日志。")
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
func (app *Server) ensureMeshUser(ctx context.Context, user string) error {
	users, err := app.mesh.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, existing := range users {
		if existing.Name == user {
			return nil
		}
	}
	if user != mesh.DefaultHeadscaleUser {
		return meshError(codeMeshHeadscaleUserUnknown, "the named headscale user does not exist")
	}
	if _, err = app.mesh.CreateUser(ctx, user); err != nil {
		if headscale.CodeOf(err) == headscale.CodeAlreadyExists {
			return nil
		}
		return err
	}
	return nil
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
	return &meshKeyDisclosure{Device: record.DisplayName, Secret: secret, Expires: expires.UTC().Format("2006-01-02 15:04:05 UTC")}
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

	for _, record := range records {
		entry := meshDeviceView{
			ID: record.ID, DisplayName: record.DisplayName,
			PurposeLabel: meshPurposeLabel(record.Purpose), PlatformLabel: meshPlatformLabel(record.Platform),
			HeadscaleUser: record.HeadscaleUser, NodeName: record.NodeName,
			SubscriberID: record.SubscriberID, SubscriberName: names[record.SubscriberID],
			StatusLabel: meshStatusLabel(record.Status), StatusClass: meshStatusClass(record.Status),
			RevokeReason: record.RevokeReason,
			CanIssue:     record.Status == mesh.StatusPending || record.Status == mesh.StatusExpired,
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
		view.Devices = append(view.Devices, entry)
	}
	return view, nil
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
// quote a label.
func meshErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var domain *mesh.DomainError
	if errors.As(err, &domain) {
		return domain.Code
	}
	var adapter *headscale.Error
	if errors.As(err, &adapter) {
		return adapter.Code
	}
	message := err.Error()
	if i := strings.IndexByte(message, ':'); i > 0 {
		return message[:i]
	}
	return message
}

// meshFail maps one sanitized store or domain error onto the stable HTTP
// contract. A malformed identifier is a client error; a well-formed unknown one
// is 404. Headscale refusals keep their own stable code and are 503: the Hub
// cannot prove the control plane answered, so no change is claimed.
func (app *Server) meshFail(w http.ResponseWriter, r *http.Request, err error, fallback, message, next string) {
	code := meshErrorCode(err)
	status := http.StatusConflict
	switch {
	case code == "":
		code = fallback
	case code == "DATABASE_UNAVAILABLE":
		status = http.StatusServiceUnavailable
	case code == "MESH_DEVICE_NOT_FOUND":
		status = http.StatusNotFound
	case code == "MESH_DEVICE_CORRUPT":
		status = http.StatusInternalServerError
	case code == codeMeshHeadscaleUserUnknown:
		status = http.StatusConflict
	case strings.HasPrefix(code, "HEADSCALE_"):
		status = http.StatusServiceUnavailable
	case code == mesh.CodeDeviceIDInvalid, code == mesh.CodeDisplayNameInvalid,
		code == "DISPLAY_NAME_INVALID",
		code == mesh.CodePurposeInvalid, code == mesh.CodePlatformInvalid,
		code == mesh.CodeSubscriberBindingInvalid, code == mesh.CodeNodeNameInvalid,
		code == mesh.CodeHeadscaleUserInvalid, code == mesh.CodeRevokeReasonInvalid,
		code == mesh.CodeKeyIDInvalid, code == mesh.CodeKeyDeviceIDInvalid,
		code == mesh.CodeKeySecretInvalid, code == mesh.CodeKeyStateInvalid:
		status = http.StatusBadRequest
	}
	app.fail(w, r, status, code, message, next)
}

// meshControlPlaneFail reports a Headscale refusal with its own code. The code
// is the only detail that leaves the adapter.
func (app *Server) meshControlPlaneFail(w http.ResponseWriter, r *http.Request, err error, fallback, message, next string) {
	if headscale.CodeOf(err) == "" {
		app.meshFail(w, r, err, fallback, message, next)
		return
	}
	app.fail(w, r, http.StatusServiceUnavailable, headscale.CodeOf(err), message, next)
}
