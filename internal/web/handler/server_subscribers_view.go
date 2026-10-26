package handler

// Subscriber view model and page rendering.
//
// This file holds the read-only projection of the subscriber domain: the page
// model built from the store, the per-Line intent/confirmation labels and the
// badge palette mapping. It performs no writes and opens no transaction of its
// own.

import (
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"net/http"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// renderSubscribers renders the subscriber page, optionally with a one-time
// plaintext bearer.
func (app *Server) renderSubscribers(w http.ResponseWriter, r *http.Request, sess session, disclosure *tokenDisclosure) {
	page, err := app.subscriberViewModel()
	if err != nil {
		app.fail(w, r, 503, store.CodeDatabaseUnavailable, "无法读取订阅用户。", "请检查数据库和服务日志。")
		return
	}
	if disclosure != nil {
		page.Token = disclosure.Token
		page.TokenOwner = disclosure.Subscriber
	}
	app.render(w, r, 200, view.SubscribersPage(view.PageData{Title: "订阅用户", Path: "/subscribers", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP}, page))
}

// subscriberViewModel builds the complete page model from the store.
//
// Every confirmation shown here is derived from the same precise evidence the
// publication path uses: for each subscriber, one read-only transaction walks
// every historical Line and evaluates the persisted desired snapshot against
// the Line's immutable revision chain and its own readback. A merely delivered
// task, a healthy node revision or a Hub-side write is never rendered as a
// confirmed subscriber state.
func (app *Server) subscriberViewModel() (view.SubscriberPageView, error) {
	page := view.SubscriberPageView{Subscribers: []view.SubscriberView{}, Lines: []view.LineView{}, EdgeNodes: []store.Node{}}
	now := app.now()
	nodes, err := app.store.ListNodesAt(now)
	if err != nil {
		return page, err
	}
	for _, node := range nodes {
		if node.Role == nodeRoleEdge {
			page.EdgeNodes = append(page.EdgeNodes, node)
		}
	}
	lines, err := app.store.ListLines()
	if err != nil {
		return page, err
	}
	for _, line := range lines {
		page.Lines = append(page.Lines, view.LineView{
			NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server, Port: line.Port,
			SortOrder: line.SortOrder, ServerName: line.ServerName, Handshake: line.HandshakeServer,
			HandshakePort: line.HandshakePort, Local: line.Local,
		})
	}
	subscribers, err := app.store.ListSubscribers()
	if err != nil {
		return page, err
	}
	for _, sub := range subscribers {
		selected, err := app.subscriberSelectedLineIDs(sub.ID)
		if err != nil {
			return page, err
		}
		selectedSet := make(map[string]bool, len(selected))
		for _, id := range selected {
			selectedSet[id] = true
		}
		credentials, err := app.store.ListSubscriberCredentials(sub.ID)
		if err != nil {
			return page, err
		}
		evidence, err := app.store.SubscriberSyncView(sub.ID, now)
		if err != nil {
			return page, err
		}
		lineEvidence := make(map[string]store.SubscriberLineSyncSnapshot, len(evidence.Lines))
		for _, line := range evidence.Lines {
			lineEvidence[line.NodeID] = line
		}
		entry := view.SubscriberView{
			ID: sub.ID, DisplayName: sub.DisplayName, State: string(sub.State),
			StateLabel: subscriberStateLabel(sub.State), StateClass: subscriberStateClass(sub.State),
			SyncStatus: evidence.Status, SyncCode: evidence.Code,
			SyncLabel: subscriberSyncLabel(evidence.Status), SyncClass: subscriberSyncClass(evidence.Status),
			Lines: []view.SubscriberLineView{}, Credentials: len(credentials),
		}
		for _, line := range lines {
			row := view.SubscriberLineView{
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
				row.SyncStatus, row.SyncCode = store.SubscriberSyncPartial, "SYNC_UNKNOWN"
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
		page.Subscribers = append(page.Subscribers, entry)
	}
	page.Origin = app.subscriptionOrigin()
	return page, nil
}

// subscriberSelectedLineIDs returns the Lines that currently carry an active
// credential for one subscriber.
//
// The store API exposes the credential inventory including historical,
// deactivated rows, so the active selection is read from the same table with
// an explicit active filter. The read is read-only and never touches a Line.
func (app *Server) subscriberSelectedLineIDs(subscriberID string) ([]string, error) {
	rows, err := app.store.DB.Query(`SELECT node_id FROM proxy_credentials WHERE subscriber_id=? AND active=1 ORDER BY node_id ASC`, subscriberID)
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

// subscriberSyncLabel renders the convergence summary of one subscriber.
func subscriberSyncLabel(status string) string {
	switch status {
	case store.SubscriberSyncHealthy:
		return "已确认 · 本机回读与最新修订一致"
	case store.SubscriberSyncPending:
		return "待同步 · 尚未确认"
	case store.SubscriberSyncPartial:
		return "未收敛 · 需要处理"
	default:
		return "状态未知"
	}
}

// subscriberSyncClass maps the convergence summary onto the badge palette.
func subscriberSyncClass(status string) string {
	switch status {
	case store.SubscriberSyncHealthy:
		return "badge accent"
	case store.SubscriberSyncPartial:
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
func subscriberLineSyncState(line store.SubscriberLineSyncSnapshot) (string, bool, string) {
	switch line.Status {
	case store.SubscriberSyncHealthy:
		return "本机已确认 · 该 Line 最新修订一致", true, ""
	case store.SubscriberSyncPending:
		return "待同步 · 尚未确认", false, ""
	case store.SubscriberSyncPartial:
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
