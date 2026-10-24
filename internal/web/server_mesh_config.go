package web

// Device-scoped sing-box configuration and explicit Headscale node claiming.
//
// A proxy+mesh device is the only purpose that receives a combined document:
// the standard subscription outbounds plus one Tailscale endpoint. The chain is
// deliberately ordered and every step before the first key is read-only:
//
//  1. resolve the device and check the purpose;
//  2. resolve the subscriber through the same convergence gate a public
//     subscription download uses;
//  3. build the non-secret MeshConfigModel (the "view first" step);
//  4. mint one Headscale pre-auth key;
//  5. mint one Hub-side one-time enrollment key;
//  6. render the pure document;
//  7. return it in the one POST response with private, no-store headers.
//
// Nothing about the rendered document is stored: the Headscale key exists once
// in memory, the Hub key is stored only as a SHA-256 digest, and the page has
// no GET route that can replay either. A failure after step 4 compensates by
// expiring the Headscale key and revoking the Hub key.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/headscale"
	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

const (
	// codeMeshEndpointControlURLUnavailable: no Headscale origin was configured,
	// so no control_url can be emitted. The exporter never falls back to the
	// public Tailscale SaaS control plane.
	codeMeshEndpointControlURLUnavailable = "MESH_ENDPOINT_CONTROL_URL_UNAVAILABLE"
	// codeMeshEndpointPurposeUnsupported: only proxy_mesh combines a proxy
	// subscription with a Tailscale endpoint. Mesh-only and subnet-router
	// devices keep their standard Tailscale client instructions.
	codeMeshEndpointPurposeUnsupported = "MESH_ENDPOINT_PURPOSE_UNSUPPORTED"
	// codeMeshEndpointSubscriberUnavailable: the bound subscriber is not active,
	// has no credential, or at least one Line is not converged.
	codeMeshEndpointSubscriberUnavailable = "MESH_ENDPOINT_SUBSCRIBER_UNAVAILABLE"
	// codeMeshEndpointKeyIssueFailed: the Hub-side one-time key could not be
	// stored after the Headscale key was minted and compensated.
	codeMeshEndpointKeyIssueFailed = "MESH_ENDPOINT_KEY_ISSUE_FAILED"
	// codeMeshEndpointRenderFailed: the pure renderer refused after both keys
	// existed; both are compensated before the failure is reported.
	codeMeshEndpointRenderFailed = "MESH_ENDPOINT_RENDER_FAILED"
	// codeMeshClaimNodeNotFound: the requested Headscale node is not in the
	// current `nodes list` snapshot.
	codeMeshClaimNodeNotFound = "MESH_CLAIM_NODE_NOT_FOUND"
	// codeMeshClaimNodeMismatch: the node name or user does not match the
	// pending MeshMux device, so a hostname collision cannot steal a node.
	codeMeshClaimNodeMismatch = "MESH_CLAIM_NODE_MISMATCH"
	// codeMeshClaimNodeOccupied: another MeshMux device already owns the node.
	codeMeshClaimNodeOccupied = "MESH_CLAIM_NODE_OCCUPIED"
	// codeMeshClaimFailed: the device row could not record the observation.
	codeMeshClaimFailed = "MESH_CLAIM_FAILED"
)

// meshConfigPlan is the read-only result of resolving one device config. It
// contains no key material: the auth key is added only after this plan exists.
type meshConfigPlan struct {
	Record      MeshDeviceRecord
	Lines       []subscription.Line
	Credentials []subscription.Credential
	Model       subscription.MeshConfigModel
}

// meshConfigPreflight resolves every non-secret input and builds the view
// model. It performs database reads only; in particular it never calls
// CreatePreAuthKey, so a purpose, subscriber, Line or control URL refusal
// leaves the Headscale key count unchanged.
func (app *Server) meshConfigPreflight(record MeshDeviceRecord, now time.Time) (meshConfigPlan, error) {
	if record.Purpose != mesh.PurposeProxyMesh || record.SubscriberID == "" {
		return meshConfigPlan{}, meshError(codeMeshEndpointPurposeUnsupported,
			"only proxy_mesh devices combine a proxy subscription with a mesh endpoint")
	}
	if app.cfg.HeadscaleOrigin == "" {
		return meshConfigPlan{}, meshError(codeMeshEndpointControlURLUnavailable,
			"configure --headscale-origin before generating a mesh client config")
	}
	lines, credentials, err := app.store.subscriptionForSubscriber(record.SubscriberID, now)
	if err != nil {
		if errors.Is(err, errSubscriptionStoreUnavailable) {
			return meshConfigPlan{}, errors.New(codeDatabaseUnavailable)
		}
		return meshConfigPlan{}, meshError(codeMeshEndpointSubscriberUnavailable,
			"the bound subscriber cannot serve a mesh config")
	}
	input := subscription.MeshDeviceInput{
		DeviceID:    record.ID,
		DisplayName: record.DisplayName,
		Hostname:    record.NodeName,
		ControlURL:  app.cfg.HeadscaleOrigin,
		Lines:       lines,
		Credentials: credentials,
	}
	model, err := subscription.NewMeshConfigModel(input)
	if err != nil {
		return meshConfigPlan{}, err
	}
	return meshConfigPlan{Record: record, Lines: lines, Credentials: credentials, Model: model}, nil
}

// meshConfig issues one device-scoped document. The Headscale key is minted
// first and the Hub key second; any failure after the Headscale key exists
// compensates both keys before the error is returned.
func (app *Server) meshConfig(ctx context.Context, plan meshConfigPlan, user headscale.User, now time.Time) (*meshKeyDisclosure, error) {
	key, authKey, err := app.mesh.CreatePreAuthKey(ctx, headscale.PreAuthKeyRequest{
		UserID:   user.ID,
		Validity: mesh.KeyTTL,
	})
	if err != nil {
		return nil, err
	}
	hubKey, hubSecret, err := app.store.issueMeshEnrollmentKey(plan.Record.ID, now)
	if err != nil {
		app.compensateMeshConfig(ctx, key, "")
		return nil, fmt.Errorf("%s: %w", codeMeshEndpointKeyIssueFailed, err)
	}
	input := subscription.MeshDeviceInput{
		DeviceID:    plan.Record.ID,
		DisplayName: plan.Record.DisplayName,
		Hostname:    plan.Model.Hostname,
		ControlURL:  plan.Model.ControlURL,
		AuthKey:     authKey,
		Lines:       plan.Lines,
		Credentials: plan.Credentials,
	}
	body, err := subscription.ExportMeshDevice(input)
	if err != nil {
		app.compensateMeshConfig(ctx, key, hubKey.ID)
		return nil, fmt.Errorf("%s: %w", codeMeshEndpointRenderFailed, err)
	}
	disclosure := app.meshDisclosure(plan.Record, hubSecret, hubKey.ExpiresAt)
	disclosure.Config = string(body)
	return disclosure, nil
}

// meshCreateDisclosure issues the one-time material of a freshly created or
// re-enrolled device. A proxy+mesh device whose preconditions are all present
// receives the combined configuration and therefore does not mint a second
// Hub key. Every other case keeps the 9a behaviour: one Hub-side key, no
// Headscale key. A configuration refusal is returned as a stable code so the
// caller can show it next to the still-valid Hub key instead of hiding the
// created device.
func (app *Server) meshCreateDisclosure(ctx context.Context, record MeshDeviceRecord, user headscale.User, now time.Time) (*meshKeyDisclosure, string, error) {
	if record.Purpose == mesh.PurposeProxyMesh && app.cfg.HeadscaleOrigin != "" {
		plan, preflightErr := app.meshConfigPreflight(record, now)
		if preflightErr == nil {
			disclosure, configErr := app.meshConfig(ctx, plan, user, now)
			if configErr == nil {
				return disclosure, "", nil
			}
			return app.issueMeshKeyDisclosure(record.ID, now, meshErrorCode(configErr))
		}
		// A subscriber/Line/control-URL refusal is not a reason to lose the
		// device: issue the Hub key and report why the combined config was not
		// generated.
		return app.issueMeshKeyDisclosure(record.ID, now, meshErrorCode(preflightErr))
	}
	return app.issueMeshKeyDisclosure(record.ID, now, "")
}

// issueMeshKeyDisclosure mints only the Hub-side one-time key.
func (app *Server) issueMeshKeyDisclosure(deviceID string, now time.Time, noticeCode string) (*meshKeyDisclosure, string, error) {
	key, secret, err := app.store.issueMeshEnrollmentKey(deviceID, now)
	if err != nil {
		return nil, noticeCode, err
	}
	record, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		return nil, noticeCode, err
	}
	return app.meshDisclosure(record, secret, key.ExpiresAt), noticeCode, nil
}

// compensateMeshConfig withdraws the Headscale key and the Hub key that were
// minted for an attempt that did not produce a response. Compensation failures
// are ignored here: the caller reports the original failure, and the keys keep
// their fixed short lifetime.
func (app *Server) compensateMeshConfig(ctx context.Context, key headscale.PreAuthKey, hubKeyID string) {
	_ = app.mesh.ExpirePreAuthKey(ctx, key.ID)
	if hubKeyID != "" {
		_, _ = app.store.revokeMeshEnrollmentKey(hubKeyID)
	}
}

// meshConfigPage handles the explicit POST that issues one device-scoped
// configuration. There is no GET counterpart: the document contains a one-shot
// Headscale key and must never be replayed by a browser refresh, history entry,
// link or cache.
func (app *Server) meshConfigPage(w http.ResponseWriter, r *http.Request, sess session) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	record, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshEndpointRenderFailed, "无法读取 Mesh 设备。", "请刷新页面后重试。")
		return
	}
	if record.Status != mesh.StatusPending {
		app.fail(w, r, http.StatusConflict, codeMeshDeviceNotReenrollable,
			"只有待注册设备可以签发设备配置。", "请刷新页面确认状态；已过期设备需先重新签发一次性 Key。")
		return
	}
	now := app.now()
	plan, err := app.meshConfigPreflight(record, now)
	if err != nil {
		app.meshFail(w, r, err, codeMeshEndpointRenderFailed, "无法生成设备配置。", "请检查用途、订阅用户与 Line 状态后重试。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	user, err := app.ensureMeshUser(ctx, record.HeadscaleUser)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshEndpointRenderFailed, "无法确认 Headscale 用户。", "请检查 Headscale 服务后重试。")
		return
	}
	// The device normally already holds the Hub key issued at creation. A
	// re-generation must not leave two live keys: withdraw the current one
	// before the chain mints the replacement.
	keys, err := app.store.listMeshEnrollmentKeys(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshEndpointRenderFailed, "无法读取 Key 记录。", "请检查数据库后重试。")
		return
	}
	for _, key := range keys {
		if key.State != mesh.KeyIssued || !now.Before(time.Unix(key.ExpiresAt, 0)) {
			continue
		}
		if _, err = app.store.revokeMeshEnrollmentKey(key.ID); err != nil {
			app.meshFail(w, r, err, codeMeshEndpointRenderFailed, "无法作废旧的一次性 Key。", "请刷新页面后重试。")
			return
		}
		app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_REVOKED")
	}
	disclosure, err := app.meshConfig(ctx, plan, user, now)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshEndpointRenderFailed, "设备配置未生成。", "请检查 Headscale 服务、订阅用户与 Line 状态后重试。")
		return
	}
	app.event(r, "MESH_DEVICE_ENROLLMENT_KEY_ISSUED")
	app.event(r, "MESH_DEVICE_CONFIG_ISSUED")
	app.renderMesh(w, r, sess, disclosure,
		"设备配置已生成。配置中的 Headscale 入网 Key 与 Hub 一次性 Key 都只在本响应中显示一次。", "notice")
}

// meshClaim attaches one existing, unclaimed Headscale node to a pending
// MeshMux device after the operator explicitly confirms the match. It reuses
// recordMeshObservation, so the same evidence rule applies as a reconcile:
// registration needs an observed Headscale node id, never a hostname guess.
func (app *Server) meshClaim(w http.ResponseWriter, r *http.Request, sess session) {
	deviceID := strings.TrimSpace(r.PostForm.Get("device_id"))
	record, err := app.store.getMeshDevice(deviceID)
	if err != nil {
		app.meshFail(w, r, err, codeMeshClaimFailed, "无法读取 Mesh 设备。", "请刷新页面后重试。")
		return
	}
	nodeID, parseErr := strconv.ParseUint(strings.TrimSpace(r.PostForm.Get("node_id")), 10, 64)
	if parseErr != nil || nodeID == 0 {
		app.fail(w, r, http.StatusBadRequest, codeMeshClaimNodeNotFound,
			"待认领的 Headscale Node ID 不正确。", "请从设备卡中的待认领列表重新选择。")
		return
	}
	if record.Status == mesh.StatusRegistered && record.HeadscaleNodeID == nodeID {
		app.renderMesh(w, r, sess, nil, "该 Headscale 节点已经绑定到此设备，无需再次认领。", "notice")
		return
	}
	if record.Status != mesh.StatusPending {
		app.fail(w, r, http.StatusConflict, mesh.CodeStatusTransitionInvalid,
			"只有待注册设备可以认领 Headscale 节点。", "请刷新页面确认设备状态；已过期设备需先重新签发。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), meshControlPlaneTimeout)
	defer cancel()
	node, found, err := app.meshNode(ctx, nodeID)
	if err != nil {
		app.meshControlPlaneFail(w, r, err, codeMeshClaimFailed, "无法读取 Headscale 节点。", "请检查 Headscale 服务后重试。")
		return
	}
	if !found {
		app.fail(w, r, http.StatusConflict, codeMeshClaimNodeNotFound,
			"Headscale 当前未报告该节点。", "请重新核对后再认领；节点可能已离线、过期或被删除。")
		return
	}
	if !meshNodeMatchesName(node, record.NodeName) || (node.UserName != "" && node.UserName != record.HeadscaleUser) {
		app.fail(w, r, http.StatusConflict, codeMeshClaimNodeMismatch,
			"该节点的名称或 Headscale 用户与设备记录不一致。", "请使用设备卡中列出的同名待认领节点。")
		return
	}
	records, err := app.store.listMeshDevices()
	if err != nil {
		app.meshFail(w, r, err, codeMeshClaimFailed, "无法读取 Mesh 设备列表。", "请检查数据库后重试。")
		return
	}
	for _, other := range records {
		if other.ID == record.ID {
			continue
		}
		if other.HeadscaleNodeID == node.ID {
			app.fail(w, r, http.StatusConflict, codeMeshClaimNodeOccupied,
				"该 Headscale 节点已绑定到另一台 Mesh 设备。", "一个 Headscale 节点只能属于一台设备；请刷新页面确认。")
			return
		}
		if other.HeadscaleUser == record.HeadscaleUser && other.NodeName == record.NodeName && other.Status.OccupiesNodeName() {
			app.fail(w, r, http.StatusConflict, codeMeshClaimNodeOccupied,
				"该节点名称已被另一台 Mesh 设备占用。", "请先处理占用同名节点的设备，再认领。")
			return
		}
	}
	claimed, err := app.store.recordMeshObservation(record.ID, node.ID, app.now())
	if err != nil {
		app.meshFail(w, r, err, codeMeshClaimFailed, "无法记录认领结果。", "请检查数据库后重试。")
		return
	}
	app.event(r, "MESH_DEVICE_CLAIMED")
	app.renderMesh(w, r, sess, nil,
		"已认领 Headscale 节点 "+strconv.FormatUint(claimed.HeadscaleNodeID, 10)+"；注册证据来自本次显式确认的观测。", "notice")
}

// meshNodeMatchesName accepts the node name the list reports. GivenName is
// checked as a fallback because older Headscale listings split the name.
func meshNodeMatchesName(node headscale.Node, name string) bool {
	return node.Name == name || (node.GivenName != "" && node.GivenName == name)
}
