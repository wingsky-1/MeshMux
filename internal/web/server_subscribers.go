package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/compiler"
	"github.com/wingsky-1/MeshMux/internal/route"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The subscriber page keeps two states apart on purpose:
//
//   - intent: what the operator asked for on the Hub (this Line carries a
//     credential for this subscriber, or it was dropped);
//   - confirmed: what the Line itself proved (its own readback matches the
//     Line's latest immutable revision).
//
// A queued publication, a delivered task or a successful Hub write is never
// rendered as a confirmed remote state.

// registerSubscriberRoutes registers the admin subscriber and Line routes.
//
// The integrator calls this from newServer. The placeholder navigation loop in
// newServer must skip "/subscribers", otherwise the placeholder page competes
// with the real subscriber page for the same path.
func (app *Server) registerSubscriberRoutes(r chi.Router) {
	r.Get("/subscribers", app.authenticated(app.subscribersPage))
	r.Post("/subscribers", app.mutation(app.subscribersCreate, true))
	r.Post("/subscribers/rename", app.mutation(app.subscribersRename, true))
	r.Post("/subscribers/state", app.mutation(app.subscribersState, true))
	r.Post("/subscribers/lines", app.mutation(app.subscribersSelectLines, true))
	r.Post("/subscribers/token/rotate", app.mutation(app.subscribersRotateToken, true))
	r.Post("/subscribers/token/revoke", app.mutation(app.subscribersRevokeToken, true))
	r.Post("/subscribers/sync", app.mutation(app.subscribersSync, true))
	r.Get("/api/subscribers", app.authenticated(app.subscribersAPI))
	r.Post("/lines", app.mutation(app.linesSave, true))
}

// subscriberLineView is one Line as it is shown for one subscriber.
type subscriberLineView struct {
	NodeID      string
	DisplayName string
	Server      string
	Port        int
	SortOrder   int
	Selected    bool
	Intent      string
	SyncStatus  string
	SyncCode    string
	Confirmed   string
	ConfirmedOK bool
	ErrorCode   string
}

// subscriberLineSyncSnapshot is the precise convergence evidence of one Line
// for exactly one subscriber, as derived from the persisted intent and the
// Line's own immutable revision chain plus readback.
type subscriberLineSyncSnapshot struct {
	NodeID string
	Status string
	Code   string
}

// subscriberSyncSnapshot is the subscriber-level convergence summary together
// with the per-Line evidence it was aggregated from.
type subscriberSyncSnapshot struct {
	Status string
	Code   string
	Lines  []subscriberLineSyncSnapshot
}

// subscriberView is the management view of one subscription user.
type subscriberView struct {
	ID          string
	DisplayName string
	State       string
	StateLabel  string
	StateClass  string
	SyncStatus  string
	SyncLabel   string
	SyncClass   string
	SyncCode    string
	Lines       []subscriberLineView
	Confirmed   int
	Total       int
	Credentials int
}

// lineView is one configured Line transport. It never carries the REALITY
// private key, the short ID or any credential.
type lineView struct {
	NodeID        string
	DisplayName   string
	Server        string
	Port          int
	SortOrder     int
	ServerName    string
	Handshake     string
	HandshakePort int
	Local         bool
}

// subscriberPageView is the complete page model.
type subscriberPageView struct {
	Subscribers []subscriberView
	Lines       []lineView
	EdgeNodes   []Node
	Token       string
	TokenOwner  string
	Origin      string
}

// tokenDisclosure carries a plaintext subscription bearer. It is only ever
// filled for the single response that issues it.
type tokenDisclosure struct {
	Subscriber string
	Token      string
}

// subscribersPage renders the subscriber management workspace.
func (app *Server) subscribersPage(w http.ResponseWriter, r *http.Request, sess session) {
	view, err := app.subscriberViewModel()
	if err != nil {
		app.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取订阅用户。", "请检查数据库和服务日志。")
		return
	}
	app.render(w, r, 200, SubscribersPage(pageData{Title: "订阅用户", Path: "/subscribers", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, view))
}

// subscribersAPI exposes the same non-secret projection as the page: no
// bearer, no VLESS UUID and no REALITY key ever leaves through this endpoint.
func (app *Server) subscribersAPI(w http.ResponseWriter, r *http.Request, _ session) {
	view, err := app.subscriberViewModel()
	if err != nil {
		app.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取订阅用户。", "请检查数据库和服务日志。")
		return
	}
	type lineProjection struct {
		NodeID        string `json:"node_id"`
		DisplayName   string `json:"display_name"`
		Server        string `json:"server"`
		Port          int    `json:"port"`
		SortOrder     int    `json:"sort_order"`
		ServerName    string `json:"server_name"`
		Handshake     string `json:"handshake_server"`
		HandshakePort int    `json:"handshake_port"`
		Local         bool   `json:"local"`
	}
	type subscriberLineProjection struct {
		NodeID      string `json:"node_id"`
		DisplayName string `json:"display_name"`
		Intent      string `json:"intent"`
		SyncStatus  string `json:"sync_status"`
		SyncCode    string `json:"sync_code"`
		Confirmed   string `json:"confirmed"`
	}
	type subscriberProjection struct {
		ID          string                     `json:"id"`
		DisplayName string                     `json:"display_name"`
		State       string                     `json:"state"`
		SyncStatus  string                     `json:"sync_status"`
		SyncCode    string                     `json:"sync_code"`
		SyncLabel   string                     `json:"sync_label"`
		Lines       []subscriberLineProjection `json:"lines"`
		Confirmed   int                        `json:"confirmed_lines"`
		Total       int                        `json:"total_lines"`
	}
	projection := struct {
		Subscribers []subscriberProjection `json:"subscribers"`
		Lines       []lineProjection       `json:"lines"`
		OperationID string                 `json:"operation_id"`
	}{Subscribers: []subscriberProjection{}, Lines: []lineProjection{}, OperationID: operation(r)}
	for _, sub := range view.Subscribers {
		entry := subscriberProjection{ID: sub.ID, DisplayName: sub.DisplayName, State: sub.State,
			SyncStatus: sub.SyncStatus, SyncCode: sub.SyncCode, SyncLabel: sub.SyncLabel,
			Confirmed: sub.Confirmed, Total: sub.Total, Lines: []subscriberLineProjection{}}
		for _, line := range sub.Lines {
			entry.Lines = append(entry.Lines, subscriberLineProjection{
				NodeID: line.NodeID, DisplayName: line.DisplayName, Intent: line.Intent,
				SyncStatus: line.SyncStatus, SyncCode: line.SyncCode, Confirmed: line.Confirmed,
			})
		}
		projection.Subscribers = append(projection.Subscribers, entry)
	}
	for _, line := range view.Lines {
		projection.Lines = append(projection.Lines, lineProjection(line))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(projection)
}

// subscribersCreate creates one subscription user with its per-Line
// credentials and its first subscription token.
func (app *Server) subscribersCreate(w http.ResponseWriter, r *http.Request, sess session) {
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	lineIDs := selectedLineIDs(r)
	now := app.now()
	sub, token, err := app.store.createSubscriber(displayName, lineIDs, now)
	if err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_CREATE_FAILED", "无法创建订阅用户。", "请检查名称与所选线路后重试。")
		return
	}
	app.event(r, "SUBSCRIBER_CREATED")
	// The bearer was already issued and is shown exactly once below. A failed
	// publication must not replace that response: the token stays visible and
	// the page renders the pending synchronization instead.
	if err := app.store.prepareSubscriberSync(sub.ID, now); err != nil {
		app.event(r, sanitizeSubscriberSyncCode(err.Error()))
	}
	app.renderSubscribers(w, r, sess, &tokenDisclosure{Subscriber: sub.DisplayName, Token: token})
}

// subscribersRename changes only the mutable display name. The subscriber ID,
// the credentials and every token stay exactly as they were.
func (app *Server) subscribersRename(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	if _, err := app.store.renameSubscriber(id, displayName, app.now()); err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_UPDATE_FAILED", "无法修改订阅用户名称。", "请检查名称后重试。")
		return
	}
	app.event(r, "SUBSCRIBER_RENAMED")
	app.renderSubscribers(w, r, sess, nil)
}

// subscribersState moves one subscriber through its lifecycle. Pausing or
// deleting revokes every subscription token in the same transaction, so the
// public download URL stops working immediately. The VLESS UUIDs of a Line
// stay authorized until the Line confirmed the revocation by readback.
func (app *Server) subscribersState(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	action := strings.TrimSpace(r.PostForm.Get("action"))
	var state subscription.State
	switch action {
	case "pause":
		state = subscription.StatePaused
	case "resume":
		state = subscription.StateActive
	case "delete":
		state = subscription.StateDeleting
	default:
		app.fail(w, r, 400, "SUBSCRIBER_ACTION_INVALID", "状态操作不正确。", "请使用页面上的暂停、恢复或删除操作。")
		return
	}
	if _, err := app.store.setSubscriberState(id, state, app.now()); err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_STATE_FAILED", "无法变更订阅用户状态。", "确认订阅用户存在且状态转换合法后重试。")
		return
	}
	app.event(r, "SUBSCRIBER_STATE_CHANGED")
	// The state change is already durable. A Line that cannot be reached now
	// keeps the intent; the page renders it as pending instead of hiding the
	// failed publication.
	if err := app.store.prepareSubscriberSync(id, app.now()); err != nil {
		app.event(r, sanitizeSubscriberSyncCode(err.Error()))
	}
	app.renderSubscribers(w, r, sess, nil)
}

// subscribersSelectLines replaces the Line selection of one subscriber. A Line
// that stays selected keeps its historical UUID, a newly selected Line gets a
// fresh credential and a dropped Line is only deactivated.
func (app *Server) subscribersSelectLines(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	lineIDs := selectedLineIDs(r)
	if _, err := app.store.selectLines(id, lineIDs, app.now()); err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_LINES_FAILED", "无法更新订阅用户的线路选择。", "请确认线路已配置且订阅用户处于生效状态。")
		return
	}
	app.event(r, "SUBSCRIBER_LINES_CHANGED")
	// The selection is durable; the publication follows immediately. A failed
	// publication leaves the page in its pending state instead of claiming a
	// convergence that did not happen.
	if err := app.store.prepareSubscriberSync(id, app.now()); err != nil {
		app.event(r, sanitizeSubscriberSyncCode(err.Error()))
	}
	app.renderSubscribers(w, r, sess, nil)
}

// subscribersRotateToken issues a fresh bearer and revokes the previous ones.
// The new bearer is independent of every VLESS UUID; rotating it never changes
// a credential that a client already downloaded.
func (app *Server) subscribersRotateToken(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	token, err := app.store.rotateToken(id, app.now())
	if err != nil {
		app.subscriberFail(w, r, err, "TOKEN_ROTATE_FAILED", "无法轮换订阅 Token。", "确认订阅用户处于生效状态后重试。")
		return
	}
	owner := id
	if sub, sErr := app.store.getSubscriber(id); sErr == nil {
		owner = sub.DisplayName
	}
	app.event(r, "SUBSCRIBER_TOKEN_ROTATED")
	app.renderSubscribers(w, r, sess, &tokenDisclosure{Subscriber: owner, Token: token})
}

// subscribersRevokeToken revokes every active token of one subscriber without
// touching its VLESS credentials.
func (app *Server) subscribersRevokeToken(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	if err := app.store.revokeTokens(id, app.now()); err != nil {
		app.subscriberFail(w, r, err, "TOKEN_REVOKE_FAILED", "无法吊销订阅 Token。", "确认订阅用户存在后重试。")
		return
	}
	app.event(r, "SUBSCRIBER_TOKEN_REVOKED")
	app.renderSubscribers(w, r, sess, nil)
}

// subscribersSync asks the store to publish the complete credential set of one
// subscriber to every selected Line.
func (app *Server) subscribersSync(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	if _, err := app.store.getSubscriber(id); err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_NOT_FOUND", "订阅用户不存在。", "请刷新页面后重试。")
		return
	}
	action := strings.TrimSpace(r.PostForm.Get("action"))
	var err error
	if action == "retry" {
		err = app.store.retrySubscriberSync(id, app.now())
	} else {
		err = app.store.prepareSubscriberSync(id, app.now())
	}
	if err != nil {
		app.subscriberFail(w, r, err, "SUBSCRIBER_SYNC_FAILED", "无法发布订阅凭据。", "确认订阅用户与线路状态后重试。")
		return
	}
	app.event(r, "SUBSCRIBER_SYNC_QUEUED")
	app.renderSubscribers(w, r, sess, nil)
}

// linesSave stores the transport of one Line. The REALITY key pair and the
// short ID are generated on the server and never leave it: the page shows no
// key material at all.
func (app *Server) linesSave(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := strings.TrimSpace(r.PostForm.Get("node_id"))
	port, err := integerForm(r.PostForm.Get("port"), 1, 65535)
	if err != nil {
		app.fail(w, r, 400, "LINE_INPUT_INVALID", "端口不正确。", "请填写 1-65535 之间的端口。")
		return
	}
	handshakePort, err := integerForm(r.PostForm.Get("handshake_port"), 1, 65535)
	if err != nil {
		app.fail(w, r, 400, "LINE_INPUT_INVALID", "握手端口不正确。", "请填写 1-65535 之间的端口。")
		return
	}
	sortOrder, err := integerForm(r.PostForm.Get("sort_order"), 0, 65535)
	if err != nil {
		app.fail(w, r, 400, "LINE_INPUT_INVALID", "排序值不正确。", "请填写 0 以上的整数。")
		return
	}
	pair, err := subscription.NewRealityKeyPair()
	if err != nil {
		app.fail(w, r, 500, "REALITY_KEY_GENERATION_FAILED", "无法生成线路密钥。", "请稍后重试并检查服务日志。")
		return
	}
	shortID, err := subscription.NewShortID()
	if err != nil {
		app.fail(w, r, 500, "SHORT_ID_GENERATION_FAILED", "无法生成线路 short id。", "请稍后重试并检查服务日志。")
		return
	}
	line := subscription.Line{
		NodeID:          nodeID,
		DisplayName:     strings.TrimSpace(r.PostForm.Get("display_name")),
		Server:          strings.TrimSpace(r.PostForm.Get("server")),
		Port:            port,
		SortOrder:       sortOrder,
		ServerName:      strings.TrimSpace(r.PostForm.Get("server_name")),
		HandshakeServer: strings.TrimSpace(r.PostForm.Get("handshake_server")),
		HandshakePort:   handshakePort,
		PrivateKey:      pair.PrivateKey,
		PublicKey:       pair.PublicKey,
		ShortID:         shortID,
	}
	if _, err = app.store.setLine(line, app.now()); err != nil {
		app.subscriberFail(w, r, err, "LINE_SETTINGS_FAILED", "无法保存线路参数。", "请确认节点已纳管且参数完整后重试。")
		return
	}
	app.event(r, "LINE_SETTINGS_SAVED")
	// The transport is durable and it is also the Out authorization source: a
	// bound Out authorizes the Line by the address stored here, so a changed
	// address has to be republished at every Out that serves this Line. Without
	// this step the Out would keep accepting the old source while denying the
	// new one, which is exactly the stale-accept case the allowlist must never
	// leave behind.
	//
	// This runs before the subscriber fan-out: the Line's own publication is
	// gated on the Out confirming the new authorization, so the Out has to be
	// given its chance first.
	app.store.drainOutsForLine(nodeID, app.now())
	// Every subscriber that ever held a credential on this Line now has a stale
	// snapshot and has to republish it, so each one is queued here. setLine
	// already committed its own transaction, and the subscriber IDs are
	// collected and the rows closed BEFORE the first prepareSubscriberSync call:
	// the store runs on a single connection (SetMaxOpenConns(1)), so a nested
	// read inside a tx would deadlock.
	// A failed fan-out never fails the save; the page renders the pending
	// state instead of claiming a convergence that did not happen.
	app.fanOutLineChange(r, nodeID)
	app.renderSubscribers(w, r, sess, nil)
}

// fanOutLineChange queues a new publication for every subscriber that ever
// held a credential on one Line. It is called after the caller's own store
// write has committed, so each prepareSubscriberSync starts from a consistent
// state. Errors are logged as stable codes and never abort the caller.
func (app *Server) fanOutLineChange(r *http.Request, nodeID string) {
	subscriberIDs, err := app.lineCredentialSubscriberIDs(nodeID)
	if err != nil {
		app.event(r, sanitizeSubscriberSyncCode(err.Error()))
		return
	}
	for _, subscriberID := range subscriberIDs {
		if err := app.store.prepareSubscriberSync(subscriberID, app.now()); err != nil {
			app.event(r, sanitizeSubscriberSyncCode(err.Error()))
		}
	}
}

// lineCredentialSubscriberIDs returns every subscriber that ever held a
// credential on one Line. The rows are fully drained and closed before this
// function returns, so the single store connection is free for the caller's
// follow-up writes.
func (app *Server) lineCredentialSubscriberIDs(nodeID string) ([]string, error) {
	rows, err := app.store.db.Query(`SELECT DISTINCT subscriber_id FROM proxy_credentials WHERE node_id=? ORDER BY subscriber_id`, nodeID)
	if err != nil {
		return nil, err
	}
	subscriberIDs := []string{}
	for rows.Next() {
		var subscriberID string
		if err = rows.Scan(&subscriberID); err != nil {
			break
		}
		subscriberIDs = append(subscriberIDs, subscriberID)
	}
	if err == nil {
		err = rows.Err()
	}
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	return subscriberIDs, nil
}

// selectedLineIDs reads the checked Line checkboxes of one form.
//
// The mutation boundary rejects repeated form fields, so every Line uses its
// own field name "line_<32 hex node id>" instead of one repeated field.
func selectedLineIDs(r *http.Request) []string {
	var ids []string
	for key, values := range r.PostForm {
		if !strings.HasPrefix(key, "line_") {
			continue
		}
		if len(values) != 1 || values[0] != "1" {
			continue
		}
		id := strings.TrimPrefix(key, "line_")
		if subscription.ValidateID(id) != nil {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// integerForm parses one bounded integer form field.
func integerForm(raw string, min, max int) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < min || value > max {
		return 0, errLineInput
	}
	return value, nil
}

// errLineInput marks a rejected numeric form field.
var errLineInput = &lineInputError{}

type lineInputError struct{}

func (e *lineInputError) Error() string { return "LINE_INPUT_INVALID" }

// subscriberFail maps a store error onto a stable error code, an HTTP status
// and a next action. The raw error is never rendered or logged.
func (app *Server) subscriberFail(w http.ResponseWriter, r *http.Request, err error, fallback, message, next string) {
	code, status := fallback, http.StatusConflict
	switch {
	case strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE"):
		code, status = "DATABASE_UNAVAILABLE", http.StatusServiceUnavailable
	case strings.HasPrefix(err.Error(), "SUBSCRIBER_NOT_FOUND"):
		code, status = "SUBSCRIBER_NOT_FOUND", http.StatusNotFound
	case strings.HasPrefix(err.Error(), "SUBSCRIBER_TRANSITION_INVALID"):
		code, status = "SUBSCRIBER_TRANSITION_INVALID", http.StatusConflict
	case strings.HasPrefix(err.Error(), "SUBSCRIBER_NOT_ACTIVE"):
		code, status = "SUBSCRIBER_NOT_ACTIVE", http.StatusConflict
	case strings.HasPrefix(err.Error(), "SUBSCRIBER_ID_INVALID"),
		strings.HasPrefix(err.Error(), "DISPLAY_NAME_INVALID"),
		strings.HasPrefix(err.Error(), "LINES_REQUIRED"),
		strings.HasPrefix(err.Error(), "LINES_TOO_MANY"),
		strings.HasPrefix(err.Error(), "LINE_ID_INVALID"),
		strings.HasPrefix(err.Error(), "LINE_ROLE_INVALID"):
		code, status = "SUBSCRIBER_INPUT_INVALID", http.StatusBadRequest
	case strings.HasPrefix(err.Error(), "LINE_NOT_FOUND"):
		code, status = "LINE_NOT_FOUND", http.StatusNotFound
	case strings.HasPrefix(err.Error(), "LINE_NOT_CONFIGURED"):
		code, status = "LINE_NOT_CONFIGURED", http.StatusConflict
	// A subscriber publication re-derives the Line route from the live server
	// policy, so it can refuse on the same Out contract as a policy
	// publication. The operator sees the real reason instead of a generic sync
	// failure, and the previous revision stays live.
	case strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID"):
		code, status = "OUT_BINDING_INVALID", http.StatusConflict
	case strings.HasPrefix(err.Error(), route.CodeOutOfflineFailClosed):
		code, status = route.CodeOutOfflineFailClosed, http.StatusConflict
	case strings.HasPrefix(err.Error(), codeOutNotAuthorized):
		code, status = codeOutNotAuthorized, http.StatusConflict
	case strings.HasPrefix(err.Error(), "POLICY_CORRUPT"):
		code, status = "POLICY_CORRUPT", http.StatusConflict
	case strings.HasPrefix(err.Error(), "POLICY_PINS_INVALID"):
		code, status = "POLICY_PINS_INVALID", http.StatusConflict
	case strings.HasPrefix(err.Error(), compiler.CodePolicyInvalid):
		code, status = compiler.CodePolicyInvalid, http.StatusConflict
	case strings.HasPrefix(err.Error(), compiler.CodePolicyConflict):
		code, status = compiler.CodePolicyConflict, http.StatusConflict
	case strings.HasPrefix(err.Error(), compiler.CodeRulesetUnpinned):
		code, status = compiler.CodeRulesetUnpinned, http.StatusConflict
	}
	app.fail(w, r, status, code, message, next)
}
