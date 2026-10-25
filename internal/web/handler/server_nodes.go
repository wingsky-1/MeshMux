package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// agentAPI reports whether the path is an outbound-Agent endpoint. These
// endpoints use Bearer identity instead of admin session + Origin, because
// the Agent connects from a remote host over HTTPS without a browser.
func agentAPI(path string) bool { return strings.HasPrefix(path, "/api/agent/") }

func (s *Server) agentFail(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	s.agentFailWithReason(w, r, status, code, code, message, next)
}

// agentFailWithReason writes one failure whose body names code, while the Hub
// log records reason. The two differ only where the response must not say what
// the log may: an unauthenticated caller must not be able to tell two refusals
// apart by their status or body, but an operator reading the operation_id must.
func (s *Server) agentFailWithReason(w http.ResponseWriter, r *http.Request, status int, code, reason, message, next string) {
	s.event(r, reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code, "operation_id": operation(r), "stage": "agent", "message": message, "next_action": next})
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
}

func decodeAgentJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// nodesPage renders the pending-node workspace. created + pairingCode are set
// only immediately after creation so the one-time code is shown once.
func (s *Server) nodesPage(w http.ResponseWriter, r *http.Request, sess session, created *store.Node, pairingCode string) {
	s.nodesPageFull(w, r, sess, created, "", pairingCode, view.NodesData{})
}

func (s *Server) nodesList(w http.ResponseWriter, r *http.Request, _ session) {
	nodes, err := s.store.ListNodesAt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	if nodes == nil {
		nodes = []store.Node{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"nodes": nodes, "operation_id": operation(r)})
}

func (s *Server) nodesCreate(w http.ResponseWriter, r *http.Request, sess session) {
	role := strings.TrimSpace(r.PostForm.Get("role"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	if role == string(nodedomain.RoleHTTP) {
		// Ruling R11: an external HTTP proxy is a Hub-only egress node. It has
		// no ports, no pairing code, no Agent and no candidate: only its URL
		// is validated and stored.
		proxyURL := strings.TrimSpace(r.PostForm.Get("proxy_url"))
		if _, err := s.store.CreateHTTPProxyNode(displayName, proxyURL, s.now()); err != nil {
			s.event(r, "NODE_CREATE_FAILED")
			status, code, message, next := httpProxyCreateFailure(err)
			s.fail(w, r, status, code, message, next)
			return
		}
		s.event(r, "HTTP_PROXY_CREATED")
		s.nodesPageFull(w, r, sess, nil, "", "", view.NodesData{Notice: "HTTP 代理节点已创建：外部出口无需配对或安装，可直接在订阅向导中选择。"})
		return
	}
	vless, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("vless_port")))
	ssh, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("ssh_port")))
	if err := protocol.ValidateNodeInputs(role, displayName, vless, ssh); err != nil {
		s.fail(w, r, 400, "NODE_INVALID", "节点参数不正确。", "请检查角色、名称与端口后重试。")
		return
	}
	node, code, err := s.store.CreateNode(role, displayName, vless, ssh, s.now())
	if err != nil {
		s.event(r, "NODE_CREATE_FAILED")
		s.fail(w, r, 400, "NODE_CREATE_FAILED", "无法创建待纳管节点。", "请检查输入并重试。")
		return
	}
	s.event(r, "NODE_CREATED")
	created := node
	s.nodesPageWithCode(w, r, sess, &created, "created", code)
}

// httpProxyCreateFailure maps one HTTP proxy create refusal onto the stable
// HTTP contract. The response never echoes the submitted URL or its userinfo.
func httpProxyCreateFailure(err error) (status int, code, message, next string) {
	switch {
	case strings.HasPrefix(err.Error(), "HTTP_PROXY_INVALID"):
		return 400, "HTTP_PROXY_INVALID", "HTTP 代理 URL 不正确。", "请填写一个 http://主机:端口 的 URL，可带用户名与密码，不要带路径或查询参数。"
	case strings.HasPrefix(err.Error(), "DISPLAY_NAME_INVALID"):
		return 400, "DISPLAY_NAME_INVALID", "展示名不正确。", "请使用 1-64 个可打印字符。"
	case strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE"):
		return 503, "DATABASE_UNAVAILABLE", "暂时无法创建节点。", "请检查数据库与服务日志后重试。"
	default:
		return 500, "NODE_CREATE_FAILED", "无法创建 HTTP 代理节点。", "请凭操作编号检查服务日志后重试。"
	}
}

func (s *Server) nodesReconcile(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	candidate, tasks, err := s.store.ReconcileNode(nodeID, s.now())
	if err != nil {
		if strings.HasPrefix(err.Error(), "TASKS_IN_PROGRESS") {
			s.fail(w, r, 409, "TASKS_IN_PROGRESS", "当前复核任务尚未结束。", "完成或失败后再次提交固定复核。")
			return
		}
		code := "RECONCILE_FAILED"
		if strings.HasPrefix(err.Error(), "NODE_NOT_FOUND") {
			code = "NODE_NOT_FOUND"
		}
		s.event(r, code)
		s.fail(w, r, 409, code, "配置复核未发布。", "确认节点仍存在后重试。")
		return
	}
	s.event(r, "CONFIG_RECONCILE_QUEUED")
	s.render(w, r, 200, view.NodeActionPage(view.PageData{Title: "配置复核已排队", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP},
		nodeID, candidate.Revision, candidate.ConfigSHA256, len(tasks)))
}

// nodesRollbackLKG is the explicit LKG rollback action: republish the Agent's
// observed candidate revision through the fixed four-task chain, with no
// upgrade target stamp (spec §4.11 U5 exemption). The caller supplies no
// revision; the Hub uses the node's own readback.
func (s *Server) nodesRollbackLKG(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	candidate, tasks, err := s.store.RepublishLKG(nodeID, s.now())
	if err != nil {
		failure := lkgRollbackFailure(err)
		s.event(r, failure.code)
		s.fail(w, r, failure.status, failure.code, failure.message, failure.action)
		return
	}
	s.event(r, "LKG_ROLLBACK_QUEUED")
	s.render(w, r, 200, view.NodeActionPage(view.PageData{Title: "LKG 回退已排队", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP},
		nodeID, candidate.Revision, candidate.ConfigSHA256, len(tasks)))
}

// lkgFailure is the operator-facing outcome of one LKG rollback refusal. A
// post-commit readback failure must NOT claim the chain was not published: it
// was committed, and telling the operator otherwise invites a duplicate chain.
type lkgFailure struct {
	status  int
	code    string
	message string
	action  string
}

func lkgRollbackFailure(err error) lkgFailure {
	if err == nil {
		return lkgFailure{status: 500, code: "LKG_ROLLBACK_FAILED", message: "LKG 回退链未发布。",
			action: "确认节点已成功读取当前修订且没有进行中的任务后重试。"}
	}
	if strings.HasPrefix(err.Error(), "LKG_ROLLBACK_READBACK_FAILED") {
		return lkgFailure{status: 503, code: "LKG_ROLLBACK_READBACK_FAILED",
			message: "LKG 回退链已发布，但修订读取失败。",
			action:  "链已提交；刷新节点页确认修订，不要重复提交。"}
	}
	code := "LKG_ROLLBACK_FAILED"
	switch {
	case strings.HasPrefix(err.Error(), "TASKS_IN_PROGRESS"):
		code = "TASKS_IN_PROGRESS"
	case strings.HasPrefix(err.Error(), "LKG_UNAVAILABLE"):
		code = "LKG_UNAVAILABLE"
	case strings.HasPrefix(err.Error(), "NODE_NOT_FOUND"):
		code = "NODE_NOT_FOUND"
	}
	return lkgFailure{status: 409, code: code, message: "LKG 回退链未发布。",
		action: "确认节点已成功读取当前修订且没有进行中的任务后重试。"}
}

func (s *Server) nodesReissue(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	code, err := s.store.ReissuePairing(nodeID, s.now())
	if err != nil {
		s.event(r, "IDENTITY_REISSUE_FAILED")
		s.fail(w, r, 409, "IDENTITY_REISSUE_FAILED", "无法重签节点身份。", "确认节点存在后重试。")
		return
	}
	existing, err := s.store.GetNodeAt(nodeID, s.now())
	if err != nil {
		s.event(r, "IDENTITY_REISSUE_READBACK_FAILED")
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "身份已重签，但页面读取失败。", "配对码不会再次显示；如未保存请重新签发。")
		return
	}
	s.event(r, "IDENTITY_REISSUED")
	s.nodesPageWithCode(w, r, sess, &existing, "reissued", code)
}

func (s *Server) nodesRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	if err := s.store.RevokeIdentity(nodeID, s.now()); err != nil {
		code := "IDENTITY_REVOKE_FAILED"
		if strings.HasPrefix(err.Error(), "NODE_NOT_FOUND") {
			code = "NODE_NOT_FOUND"
		}
		s.event(r, code)
		s.fail(w, r, 409, code, "身份未吊销。", "确认节点存在后重试。")
		return
	}
	s.event(r, "IDENTITY_REVOKED")
	s.nodesPage(w, r, sess, nil, "")
}

func nodeIDFromRequest(r *http.Request) string {
	if nodeID := strings.TrimSpace(chi.URLParam(r, "nodeID")); nodeID != "" {
		return nodeID
	}
	return strings.TrimSpace(r.PostForm.Get("node_id"))
}

func (s *Server) nodesPageWithCode(w http.ResponseWriter, r *http.Request, sess session, created *store.Node, action, code string) {
	s.nodesPageFull(w, r, sess, created, action, code, view.NodesData{})
}

// nodesPageFull renders the nodes page with the Task 2 pool projection: the
// Out pool strip, the per-card transport and binding state, an optional
// one-shot notice and an optional pending delete confirm.
func (s *Server) nodesPageFull(w http.ResponseWriter, r *http.Request, sess session, created *store.Node, action, code string, data view.NodesData) {
	nodes, err := s.store.ListNodesAt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	pool, err := s.store.OutPool(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取 Out 池。", "请检查数据库。")
		return
	}
	data.Pool = pool
	data.ByOut = make(map[string]store.OutPoolEntry, len(pool))
	data.ByLine = make(map[string][]store.OutPoolEntry)
	for _, entry := range pool {
		data.ByOut[entry.OutID] = entry
		for _, lineID := range entry.LineIDs {
			data.ByLine[lineID] = append(data.ByLine[lineID], entry)
		}
	}
	s.render(w, r, 200, view.NodesPage(view.PageData{Title: "代理节点", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP}, nodes, data, created, action, code, s.cfg.Origin, s.cfg.InstallArtifact))
}

func (s *Server) agentMetadata(w http.ResponseWriter, r *http.Request) {
	n, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	metadata := nodedomain.Metadata{
		NodeID: n.ID, Role: nodedomain.Role(n.Role), VLESSPort: n.VlessPort, SSHPort: n.SSHPort,
	}
	if err := metadata.Validate(); err != nil {
		s.agentFail(w, r, 500, "METADATA_INVALID", "节点身份绑定无效。", "请在 Web 重签身份。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(metadata)
}

func (s *Server) agentCandidate(w http.ResponseWriter, r *http.Request) {
	n, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.agentFail(w, r, 400, "QUERY_REJECTED", "配置端点不接受查询参数。", "请使用固定 revision 路径。")
		return
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(chi.URLParam(r, "revision")), 10, 64)
	if err != nil || revision < 1 {
		s.agentFail(w, r, 400, "REVISION_INVALID", "配置修订不正确。", "请先拉取固定任务。")
		return
	}
	candidate, err := s.store.Candidate(n.ID, revision)
	if err != nil {
		code := "CANDIDATE_NOT_FOUND"
		status := 404
		if strings.HasPrefix(err.Error(), "CANDIDATE_CORRUPT") {
			code, status = "CANDIDATE_CORRUPT", 500
		}
		s.agentFail(w, r, status, code, "配置修订不可用。", "请重新从任务参数获取修订号。")
		return
	}
	if candidate.Document.NodeID != n.ID || string(candidate.Document.Role) != n.Role ||
		candidate.Document.VLESSPort != n.VlessPort || candidate.Document.KernelVersion != nodedomain.KernelVersion {
		s.agentFail(w, r, 500, "CANDIDATE_MISMATCH", "配置与节点身份不匹配。", "请在 Web 重新复核配置。")
		return
	}
	sum := sha256.Sum256(candidate.JSON)
	configHash, hashErr := store.CandidateSHA256(candidate.JSON)
	if hashErr != nil {
		s.agentFail(w, r, 500, "CANDIDATE_CORRUPT", "配置无法编译校验。", "请在 Web 重新复核配置。")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-MeshMux-Config-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("X-MeshMux-Config-Compiled-SHA256", configHash)
	_, _ = w.Write(candidate.JSON)
}

// pairAgent exchanges a one-time pairing code for a node-scoped identity.
// The code and the issued token never appear in logs; only operation_id and
// stable error codes are recorded.
//
// Two properties matter here beyond the exchange itself:
//
//   - The endpoint spends work before any session exists, so it carries its own
//     budget (pair_limiter.go). The refusal needs no database access, which keeps
//     an anonymous flood off the single SQLite connection.
//   - An unknown code, an expired code and an already-spent code all answer the
//     same 401 PAIRING_INVALID. The response is therefore not an oracle for a
//     code's history: a caller cannot learn from it whether a guessed code ever
//     existed, when it lapsed or that it was used. Only the Hub log keeps the
//     distinction (PAIRING_EXPIRED / PAIRING_CONSUMED), reachable through the
//     operation_id the response carries. A wrong role stays a distinct 403
//     because it is a fact about the caller's own configuration, not about a
//     secret, and an operator needs it to fix a wrong-role install.
func (s *Server) pairAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req protocol.PairingRequest
	if err := decodeAgentJSON(r, &req); err != nil {
		s.agentFail(w, r, 400, "PAIRING_INVALID", "配对请求不正确。", "请使用 Web 显示的一次性配对指令重试。")
		return
	}
	// Charge the budget before the store is touched. A malformed body costs no
	// budget (it never reaches the database either), while every well-formed
	// attempt is bounded before it can hash a code or open a transaction.
	if ok, retry := s.pairing.spend(s.now()); !ok {
		seconds := int((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		s.agentFail(w, r, 429, "PAIRING_RATE_LIMITED", "配对尝试过于频繁。",
			"配对预算为 "+strconv.Itoa(pairBudget)+" 次 / 分钟，约 "+retryText(seconds)+"后可再试；已配对身份、心跳与任务不受影响，请勿反复重试。")
		return
	}
	token, err := s.store.ConsumePairing(req.NodeID, req.Role, req.PairingCode, req.AgentVersion, req.KernelVersion, s.now())
	if err != nil {
		msg := err.Error()
		// Default: one neutral refusal, whatever the code's history. The log
		// reason is the precise one so the operator can still diagnose it.
		code, status, reason := "PAIRING_INVALID", 401, "PAIRING_INVALID"
		message, next := "配对被拒绝。", "请确认 Node ID、角色与未过期的一次性配对码。"
		switch {
		case strings.HasPrefix(msg, "ROLE_MISMATCH"):
			code, status, reason = "ROLE_MISMATCH", 403, "ROLE_MISMATCH"
		case strings.HasPrefix(msg, "PAIRING_EXPIRED"):
			reason = "PAIRING_EXPIRED"
		case strings.HasPrefix(msg, "PAIRING_CONSUMED"):
			reason = "PAIRING_CONSUMED"
		case strings.HasPrefix(msg, "VERSION_INVALID"):
			code, status, reason = "VERSION_INVALID", 400, "VERSION_INVALID"
		case strings.HasPrefix(msg, "DATABASE_UNAVAILABLE"):
			// A database outage is not a rejected credential. Reporting it as one
			// would send an operator to reissue a code that was never the problem.
			code, status, reason = "DATABASE_UNAVAILABLE", 503, "DATABASE_UNAVAILABLE"
			message, next = "暂时无法验证配对。", "请检查数据库与服务日志，稍后重试。"
		case strings.HasPrefix(msg, "IDENTITY_ISSUE_FAILED"):
			code, status, reason = "IDENTITY_ISSUE_FAILED", 500, "IDENTITY_ISSUE_FAILED"
			message, next = "无法签发节点身份。", "请凭操作编号检查服务日志后重试；配对码未被消费。"
		}
		// Never echo node IDs, roles or secrets in the error body beyond the code.
		s.agentFailWithReason(w, r, status, code, reason, message, next)
		return
	}
	// A spent code is the pairing analogue of a proven password: the exchange
	// succeeded, so the failures a flood produced no longer hold the budget.
	s.pairing.clear()
	s.event(r, "AGENT_PAIRED")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"node_id": req.NodeID, "identity_token": token, "operation_id": operation(r)})
}

func (s *Server) agentTasks(w http.ResponseWriter, r *http.Request) {
	node, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	if node.Offline {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{}, "operation_id": operation(r)})
		return
	}
	tasks, err := s.store.PendingTasksAt(node.ID, 8, s.now())
	if err != nil {
		s.agentFail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取任务。", "请稍后重试。")
		return
	}
	if tasks == nil {
		tasks = []protocol.Task{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "operation_id": operation(r)})
}

func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	node, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var body protocol.HeartbeatRequest
	if err := decodeAgentJSON(r, &body); err != nil {
		s.agentFail(w, r, 400, "HEARTBEAT_INVALID", "心跳格式不正确。", "请上报 agent 与内核版本。")
		return
	}
	if err := body.Validate(); err != nil {
		s.agentFail(w, r, 400, "HEARTBEAT_INVALID", "心跳缺少版本信息。", "请上报 agent 与内核版本。")
		return
	}
	if err := s.store.Heartbeat(node.ID, body.AgentVersion, body.KernelVersion, s.now()); err != nil {
		s.agentFail(w, r, 503, "DATABASE_UNAVAILABLE", "无法记录心跳。", "请稍后重试。")
		return
	}
	// A heartbeat is also a readback event: the node is reachable, so the Hub
	// can reconcile the authorization direction that starts here. The state is
	// logged with stable codes only and never echoes an address, an allowlist
	// entry or a node identifier.
	s.logCoordinationReadback(r, node.ID)
	s.event(r, "AGENT_HEARTBEAT")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "paired", "operation_id": operation(r)})
}

// The install artifact is served in fixed-size chunks, so one download holds a
// single chunk plus the hash state instead of the whole file. The previous
// io.ReadAll buffered up to 128 MiB per download, and its growing slice could
// briefly hold close to twice that; memory here is flat in the artifact size and
// grows only by the chunk per concurrent download.
//
// The file is read twice rather than buffered: the first pass verifies the
// pinned digest before any byte or Content-Length is promised to the client, so
// a changed artifact still gets its honest 503 refusal. The second pass sends
// the file while hashing it again, so a file rewritten between the two passes
// cannot be delivered as verified. Both passes share one chunk buffer.
const installArtifactChunkBytes = 32 << 10

// errInstallArtifactChanged separates "these bytes are not the pinned artifact"
// from a read or write failure. It is never sent: the first pass turns it into a
// 503 before the response starts, and the second pass aborts a response that has
// already started.
var errInstallArtifactChanged = errors.New("INSTALL_ARTIFACT_CHANGED")

// copyArtifactVerified copies exactly size bytes from r to w and hashes the same
// bytes in the same pass, in order. Memory is one chunk plus the hash state, so
// it does not follow the artifact size. A read or write failure is returned
// as-is, because the caller can no longer retract what was already sent; a copy
// that ended early is io.ErrUnexpectedEOF, and only a complete copy whose digest
// differs is errInstallArtifactChanged.
//
// Passing io.Discard as w runs the same verification without sending anything,
// which is how the handler checks the pinned digest before it promises a body.
func copyArtifactVerified(w io.Writer, r io.Reader, size int64, want string, chunk []byte) (int64, error) {
	hasher := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(w, hasher), io.LimitReader(r, size), chunk)
	if err != nil {
		return written, err
	}
	if written != size {
		return written, io.ErrUnexpectedEOF
	}
	if hex.EncodeToString(hasher.Sum(nil)) != want {
		return written, errInstallArtifactChanged
	}
	return written, nil
}

func (s *Server) installArtifactDownload(w http.ResponseWriter, r *http.Request, _ session) {
	artifact := s.cfg.InstallArtifact
	if artifact == nil {
		s.fail(w, r, 404, "INSTALL_ARTIFACT_UNAVAILABLE", "当前 Web 没有同源 CLI 安装制品。", "请通过已安装的 meshmux __internal-web 打开节点管理。")
		return
	}
	if r.URL.RawQuery != "" {
		s.fail(w, r, 400, "QUERY_REJECTED", "下载端点不接受查询参数。", "请使用固定下载入口。")
		return
	}
	f, err := os.Open(artifact.Path)
	if err != nil {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_UNAVAILABLE", "安装制品暂时不可读。", "请检查服务安装文件。")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > InstallArtifactMaxBytes {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_INVALID", "安装制品大小或类型不安全。", "请重新安装匹配版本。")
		return
	}
	// The size observed on the open descriptor bounds both passes: bytes
	// appended after Stat can neither extend the response nor the digest input.
	size := info.Size()
	chunk := make([]byte, installArtifactChunkBytes)
	if _, err := copyArtifactVerified(io.Discard, f, size, artifact.SHA256, chunk); err != nil {
		if errors.Is(err, errInstallArtifactChanged) {
			s.fail(w, r, 503, "INSTALL_ARTIFACT_CHANGED", "安装制品校验和不匹配。", "请重新安装匹配版本。")
			return
		}
		s.fail(w, r, 503, "INSTALL_ARTIFACT_UNAVAILABLE", "安装制品读取不完整。", "请重新安装匹配版本。")
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_UNAVAILABLE", "安装制品暂时不可读。", "请检查服务安装文件。")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="meshmux"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if _, err := copyArtifactVerified(w, f, size, artifact.SHA256, chunk); err != nil {
		if errors.Is(err, errInstallArtifactChanged) || errors.Is(err, io.ErrUnexpectedEOF) {
			// A file rewritten between the two passes. The bytes are already on the
			// wire, so no handler can take them back: the enforcement is the
			// installer's fixed sha256sum -c, which rejects the file. Abort so a
			// rewrite that also shortened the file cannot look like a complete
			// download, and record INSTALL_ARTIFACT_CHANGED for the operator instead
			// of letting the response end as if it were the pinned artifact.
			s.event(r, "INSTALL_ARTIFACT_CHANGED")
			panic(http.ErrAbortHandler)
		}
		// A read error or a client that stopped reading leaves the declared
		// Content-Length unfilled. HTTP clients and the installer's fixed
		// sha256sum both see a truncated download; there is no clean JSON status
		// left once bytes are on the wire.
	}
}

func (s *Server) agentResult(w http.ResponseWriter, r *http.Request) {
	node, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var res protocol.TaskResult
	if err := decodeAgentJSON(r, &res); err != nil {
		s.agentFail(w, r, 400, "RESULT_INVALID", "任务结果格式不正确。", "请按固定 task schema 上报。")
		return
	}
	changed, err := s.store.ReportResultAudited(node.ID, res, s.now())
	if err != nil {
		msg := err.Error()
		code := "RESULT_REJECTED"
		status := 400
		if strings.HasPrefix(msg, "TASK_NOT_FOUND") {
			code = "TASK_NOT_FOUND"
			status = 404
		} else if strings.HasPrefix(msg, "TASK_ALREADY_FINAL") {
			code = "TASK_ALREADY_FINAL"
			status = 409
		} else if strings.HasPrefix(msg, "TASK_STATE_INVALID") {
			code = "TASK_STATE_INVALID"
			status = 409
		} else if strings.HasPrefix(msg, "READBACK_") {
			code = strings.SplitN(msg, ":", 2)[0]
			status = 400
		} else if strings.HasPrefix(msg, "TASK_PARAMS_INVALID") {
			code = "TASK_PARAMS_INVALID"
			status = 400
		} else if strings.HasPrefix(msg, "DATABASE_UNAVAILABLE") {
			code = "DATABASE_UNAVAILABLE"
			status = 503
		}
		s.agentFail(w, r, status, code, "任务结果被拒绝。", "请确认 operation_id 与固定状态机。")
		return
	}
	if changed {
		// The request operation is deliberately separate from the task
		// operation. Only stable, already-validated fields are logged.
		s.log.Info("agent_task_result", "operation_id", res.OperationID,
			"request_operation_id", operation(r), "stage", "agent",
			"status", res.Status, "error_code", res.ErrorCode)
		// A recorded result is the readback event of the node: the Out side
		// proves its allowlist and releases the Lines it serves, while the Line
		// side reports its own inbound evidence. Each fact is logged with its
		// stable code so a partially converged pair is visible per fact.
		s.logCoordinationReadback(r, node.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded", "operation_id": operation(r)})
}

// logCoordinationReadback writes the per-fact readback of one node as an audit
// event. Only stable codes, the node's own operation and the non-secret
// confirmed revision/digest are logged: never an address, an allowlist entry, a
// subscriber identity or a credential.
//
// retry_pending is the operator-facing retry pointer. It is true only for a
// terminal failure; the affordance is the existing node retry route
// (POST /nodes/{nodeID}/retry), which republishes the node's authorization. A
// transition in progress is never retry-pending, because its own chain still has
// to finish.
//
// A readback failure never fails the request that triggered it: the evidence is
// informational, and the next heartbeat, poll or result recomputes it.
func (s *Server) logCoordinationReadback(r *http.Request, nodeID string) {
	readback, err := s.store.NodeCoordinationReadback(nodeID, s.now())
	if err != nil {
		s.log.Warn("out_readback_unavailable", "request_operation_id", operation(r),
			"stage", "web", "error_code", "DATABASE_UNAVAILABLE")
		return
	}
	s.log.Info("out_readback", "request_operation_id", operation(r), "stage", "web",
		"allowlist", readback.Allowlist, "allowlist_code", readback.AllowlistCode,
		"inbound", readback.Inbound, "inbound_code", readback.InboundCode,
		"reality", readback.Reality,
		"final_egress", readback.FinalEgress, "final_egress_code", readback.FinalEgressCode,
		"confirmed_revision", readback.ConfirmedRevision, "confirmed_digest", readback.ConfirmedDigest,
		"retry_pending", readback.RetryPending)
}

func (s *Server) agentAuth(w http.ResponseWriter, r *http.Request) (store.Node, bool) {
	token := bearerToken(r)
	node, err := s.store.AuthenticateAgentAt(token, s.now())
	if err != nil {
		s.agentFail(w, r, 401, "AGENT_UNAUTHORIZED", "节点身份无效或已撤销。", "请使用配对时配发的节点专属身份重试。")
		return store.Node{}, false
	}
	return node, true
}
