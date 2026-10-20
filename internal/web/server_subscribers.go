package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
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
		projection.Lines = append(projection.Lines, lineProjection{
			NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server, Port: line.Port,
			SortOrder: line.SortOrder, ServerName: line.ServerName, Handshake: line.Handshake,
			HandshakePort: line.HandshakePort, Local: line.Local,
		})
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
	// The transport is durable. Every subscriber that ever held a credential
	// on this Line now has a stale snapshot and has to republish it, so each
	// one is queued here. setLine already committed its own transaction, and
	// the subscriber IDs are collected and the rows closed BEFORE the first
	// prepareSubscriberSync call: the store runs on a single connection
	// (SetMaxOpenConns(1)), so a nested read inside a tx would deadlock.
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

// renderSubscribers renders the subscriber page, optionally with a one-time
// plaintext bearer.
func (app *Server) renderSubscribers(w http.ResponseWriter, r *http.Request, sess session, disclosure *tokenDisclosure) {
	view, err := app.subscriberViewModel()
	if err != nil {
		app.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取订阅用户。", "请检查数据库和服务日志。")
		return
	}
	if disclosure != nil {
		view.Token = disclosure.Token
		view.TokenOwner = disclosure.Subscriber
	}
	app.render(w, r, 200, SubscribersPage(pageData{Title: "订阅用户", Path: "/subscribers", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, view))
}

// subscriberViewModel builds the complete page model from the store.
//
// Every confirmation shown here is derived from the same precise evidence the
// publication path uses: for each subscriber, one read-only transaction walks
// every historical Line and evaluates the persisted desired snapshot against
// the Line's immutable revision chain and its own readback. A merely delivered
// task, a healthy node revision or a Hub-side write is never rendered as a
// confirmed subscriber state.
func (app *Server) subscriberViewModel() (subscriberPageView, error) {
	view := subscriberPageView{Subscribers: []subscriberView{}, Lines: []lineView{}, EdgeNodes: []Node{}}
	now := app.now()
	nodes, err := app.store.listNodesAt(now)
	if err != nil {
		return view, err
	}
	for _, node := range nodes {
		if node.Role == "edge" {
			view.EdgeNodes = append(view.EdgeNodes, node)
		}
	}
	lines, err := app.store.listLines()
	if err != nil {
		return view, err
	}
	for _, line := range lines {
		view.Lines = append(view.Lines, lineView{
			NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server, Port: line.Port,
			SortOrder: line.SortOrder, ServerName: line.ServerName, Handshake: line.HandshakeServer,
			HandshakePort: line.HandshakePort, Local: line.Local,
		})
	}
	subscribers, err := app.store.listSubscribers()
	if err != nil {
		return view, err
	}
	for _, sub := range subscribers {
		selected, err := app.subscriberSelectedLineIDs(sub.ID)
		if err != nil {
			return view, err
		}
		selectedSet := make(map[string]bool, len(selected))
		for _, id := range selected {
			selectedSet[id] = true
		}
		credentials, err := app.store.listSubscriberCredentials(sub.ID)
		if err != nil {
			return view, err
		}
		evidence, err := app.store.subscriberSyncView(sub.ID, now)
		if err != nil {
			return view, err
		}
		lineEvidence := make(map[string]subscriberLineSyncSnapshot, len(evidence.Lines))
		for _, line := range evidence.Lines {
			lineEvidence[line.NodeID] = line
		}
		entry := subscriberView{
			ID: sub.ID, DisplayName: sub.DisplayName, State: string(sub.State),
			StateLabel: subscriberStateLabel(sub.State), StateClass: subscriberStateClass(sub.State),
			SyncStatus: evidence.Status, SyncCode: evidence.Code,
			SyncLabel: subscriberSyncLabel(evidence.Status), SyncClass: subscriberSyncClass(evidence.Status),
			Lines: []subscriberLineView{}, Credentials: len(credentials),
		}
		for _, line := range lines {
			row := subscriberLineView{
				NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server,
				Port: line.Port, SortOrder: line.SortOrder, Selected: selectedSet[line.NodeID],
			}
			row.Intent = subscriberLineIntent(row.Selected)
			lineState, hasEvidence := lineEvidence[line.NodeID]
			switch {
			case hasEvidence:
				row.SyncStatus, row.SyncCode = lineState.Status, lineState.Code
				row.Confirmed, row.ConfirmedOK, row.ErrorCode = subscriberLineSyncState(lineState)
			case row.Selected:
				// An active credential is always part of the historical Line
				// set. Missing evidence is inconsistent state, so it fails
				// closed instead of being rendered as confirmed.
				row.SyncStatus, row.SyncCode = subscriberSyncPartial, "SYNC_UNKNOWN"
				row.Confirmed, row.ConfirmedOK, row.ErrorCode = "未收敛 · SYNC_UNKNOWN", false, "SYNC_UNKNOWN"
			default:
				// The subscriber never held a credential on this Line, so
				// there is no subscriber-specific evidence to report.
				row.Confirmed = "未纳入 · 无同步记录"
			}
			entry.Lines = append(entry.Lines, row)
			if row.Selected {
				entry.Total++
				if row.ConfirmedOK {
					entry.Confirmed++
				}
			}
		}
		view.Subscribers = append(view.Subscribers, entry)
	}
	view.Origin = app.subscriptionOrigin()
	return view, nil
}

// subscriberSelectedLineIDs returns the Lines that currently carry an active
// credential for one subscriber.
//
// The store API exposes the credential inventory including historical,
// deactivated rows, so the active selection is read from the same table with
// an explicit active filter. The read is read-only and never touches a Line.
func (app *Server) subscriberSelectedLineIDs(subscriberID string) ([]string, error) {
	rows, err := app.store.db.Query(`SELECT node_id FROM proxy_credentials WHERE subscriber_id=? AND active=1 ORDER BY node_id ASC`, subscriberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var nodeID string
		if err = rows.Scan(&nodeID); err != nil {
			return nil, err
		}
		out = append(out, nodeID)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// subscriberLineIntent renders the operator intent for one Line.
func subscriberLineIntent(selected bool) string {
	if selected {
		return "期望：纳入该 Line"
	}
	return "期望：不纳入该 Line"
}

// subscriberSyncView evaluates the subscriber's convergence against every
// historical Line and returns the per-Line evidence it aggregated.
//
// The snapshot is read-only. Exactly one transaction is opened, so the desired
// snapshot, the immutable revision chain and the local readback are all read
// from one consistent view. getSubscriberTx and every per-Line query run in
// that transaction: the store uses a single connection (SetMaxOpenConns(1)),
// so a nested store call here would deadlock.
//
// The aggregation mirrors subscriberSyncStatus (see store_subscriber_sync.go),
// including its known quirk: a later partial Line does not overwrite a code
// that an earlier pending Line already set. The quirk is intentionally
// reproduced so the page and the store summary can never disagree; fixing it
// belongs to store_subscriber_sync.go, not to this projection.
func (s *store) subscriberSyncView(subscriberID string, now time.Time) (subscriberSyncSnapshot, error) {
	snapshot := subscriberSyncSnapshot{Lines: []subscriberLineSyncSnapshot{}}
	if err := subscription.ValidateID(subscriberID); err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = "SUBSCRIBER_ID_INVALID"
		return snapshot, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return snapshot, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = sanitizeSubscriberSyncCode(err.Error())
		return snapshot, err
	}
	lineIDs, err := subscriberHistoricalLineIDsTx(tx, subscriberID)
	if err != nil {
		snapshot.Status = subscriberSyncPending
		snapshot.Code = "DATABASE_UNAVAILABLE"
		return snapshot, err
	}
	snapshot.Status = subscriberSyncHealthy
	for _, nodeID := range lineIDs {
		lineStatus, lineCode, err := subscriberLineSyncViewTx(tx, nodeID, now)
		if err != nil {
			snapshot.Status = subscriberSyncPending
			snapshot.Code = "DATABASE_UNAVAILABLE"
			return snapshot, err
		}
		snapshot.Lines = append(snapshot.Lines, subscriberLineSyncSnapshot{
			NodeID: nodeID, Status: lineStatus, Code: lineCode,
		})
		// TODO(#7): this aggregation intentionally copies the quirk of
		// subscriberSyncStatus at store_subscriber_sync.go:697-718, where a
		// partial Line keeps an earlier pending code. Fix both together.
		if lineStatus == subscriberSyncPartial {
			snapshot.Status = subscriberSyncPartial
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
			continue
		}
		if lineStatus == subscriberSyncPending && snapshot.Status != subscriberSyncPartial {
			snapshot.Status = subscriberSyncPending
			if snapshot.Code == "" {
				snapshot.Code = lineCode
			}
		}
	}
	return snapshot, nil
}

// subscriberSyncLabel renders the convergence summary of one subscriber.
func subscriberSyncLabel(status string) string {
	switch status {
	case subscriberSyncHealthy:
		return "已确认 · 本机回读与最新修订一致"
	case subscriberSyncPending:
		return "待同步 · 尚未确认"
	case subscriberSyncPartial:
		return "未收敛 · 需要处理"
	default:
		return "状态未知"
	}
}

// subscriberSyncClass maps the convergence summary onto the badge palette.
func subscriberSyncClass(status string) string {
	switch status {
	case subscriberSyncHealthy:
		return "badge accent"
	case subscriberSyncPartial:
		return "badge failure"
	default:
		return "badge"
	}
}

// subscriberLineSyncState renders one Line's precise evidence for a subscriber.
//
// ConfirmedOK is true only for a healthy Line. A pending Line never carries an
// error code into the legacy ErrorCode field (pending is not a failure); its
// code stays in SyncCode. A partial Line is rendered as failed with its code.
func subscriberLineSyncState(line subscriberLineSyncSnapshot) (string, bool, string) {
	switch line.Status {
	case subscriberSyncHealthy:
		return "本机已确认 · 该 Line 最新修订一致", true, ""
	case subscriberSyncPending:
		return "待同步 · 尚未确认", false, ""
	case subscriberSyncPartial:
		return "未收敛 · " + line.Code, false, line.Code
	default:
		return "状态未知 · 未确认", false, line.Code
	}
}

// subscriberStateLabel renders the lifecycle state of one subscriber.
func subscriberStateLabel(state subscription.State) string {
	switch state {
	case subscription.StateActive:
		return "生效中"
	case subscription.StatePaused:
		return "已暂停"
	case subscription.StateDeleting:
		return "删除中 · 等待远端确认"
	case subscription.StateDeleted:
		return "已删除"
	default:
		return "未知状态"
	}
}

// subscriberStateClass maps the lifecycle state onto the existing badge
// palette of the console.
func subscriberStateClass(state subscription.State) string {
	switch state {
	case subscription.StateActive:
		return "badge accent"
	case subscription.StatePaused, subscription.StateDeleting:
		return "badge failure"
	default:
		return "badge"
	}
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
	}
	app.fail(w, r, status, code, message, next)
}
