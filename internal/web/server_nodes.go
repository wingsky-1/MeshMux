package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	nodedomain "github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/protocol"
)

// agentAPI reports whether the path is an outbound-Agent endpoint. These
// endpoints use Bearer identity instead of admin session + Origin, because
// the Agent connects from a remote host over HTTPS without a browser.
func agentAPI(path string) bool { return strings.HasPrefix(path, "/api/agent/") }

// shellQuote renders one POSIX shell word. The command shown by Web remains
// copyable while local config values cannot break out into shell syntax.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (s *Server) agentFail(w http.ResponseWriter, r *http.Request, status int, code, message, next string) {
	s.event(r, code)
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
func (s *Server) nodesPage(w http.ResponseWriter, r *http.Request, sess session, created *Node, pairingCode string) {
	nodes, err := s.store.listNodesAt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	s.render(w, r, 200, NodesPage(pageData{Title: "代理节点", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP}, nodes, created, "", pairingCode, s.cfg.Origin, s.cfg.InstallArtifact))
}

func (s *Server) nodesList(w http.ResponseWriter, r *http.Request, _ session) {
	nodes, err := s.store.listNodesAt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	if nodes == nil {
		nodes = []Node{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"nodes": nodes, "operation_id": operation(r)})
}

func (s *Server) nodesCreate(w http.ResponseWriter, r *http.Request, sess session) {
	role := strings.TrimSpace(r.PostForm.Get("role"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	vless, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("vless_port")))
	ssh, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("ssh_port")))
	if err := protocol.ValidateNodeInputs(role, displayName, vless, ssh); err != nil {
		s.fail(w, r, 400, "NODE_INVALID", "节点参数不正确。", "请检查角色、名称与端口后重试。")
		return
	}
	node, code, err := s.store.createNode(role, displayName, vless, ssh, s.now())
	if err != nil {
		s.event(r, "NODE_CREATE_FAILED")
		s.fail(w, r, 400, "NODE_CREATE_FAILED", "无法创建待纳管节点。", "请检查输入并重试。")
		return
	}
	s.event(r, "NODE_CREATED")
	created := node
	s.nodesPageWithCode(w, r, sess, &created, "created", code)
}

func (s *Server) nodesReconcile(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	candidate, tasks, err := s.store.reconcileNode(nodeID, s.now())
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
	s.render(w, r, 200, NodeActionPage(pageData{Title: "配置复核已排队", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP},
		nodeID, candidate.Revision, candidate.ConfigSHA256, len(tasks)))
}

func (s *Server) nodesReissue(w http.ResponseWriter, r *http.Request, sess session) {
	nodeID := nodeIDFromRequest(r)
	code, err := s.store.reissuePairing(nodeID, s.now())
	if err != nil {
		s.event(r, "IDENTITY_REISSUE_FAILED")
		s.fail(w, r, 409, "IDENTITY_REISSUE_FAILED", "无法重签节点身份。", "确认节点存在后重试。")
		return
	}
	existing, err := s.store.getNodeAt(nodeID, s.now())
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
	if err := s.store.revokeIdentity(nodeID, s.now()); err != nil {
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

func (s *Server) nodesPageWithCode(w http.ResponseWriter, r *http.Request, sess session, created *Node, action, code string) {
	nodes, err := s.store.listNodesAt(s.now())
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	s.render(w, r, 200, NodesPage(pageData{Title: "代理节点", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP}, nodes, created, action, code, s.cfg.Origin, s.cfg.InstallArtifact))
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
	candidate, err := s.store.candidate(n.ID, revision)
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
	configHash, hashErr := candidateSHA256(candidate.JSON)
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
func (s *Server) pairAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req protocol.PairingRequest
	if err := decodeAgentJSON(r, &req); err != nil {
		s.agentFail(w, r, 400, "PAIRING_INVALID", "配对请求不正确。", "请使用 Web 显示的一次性配对指令重试。")
		return
	}
	token, err := s.store.consumePairing(req.NodeID, req.Role, req.PairingCode, req.AgentVersion, req.KernelVersion, s.now())
	if err != nil {
		msg := err.Error()
		code := "PAIRING_INVALID"
		status := 401
		switch {
		case strings.HasPrefix(msg, "ROLE_MISMATCH"):
			code = "ROLE_MISMATCH"
			status = 403
		case strings.HasPrefix(msg, "PAIRING_EXPIRED"):
			code = "PAIRING_EXPIRED"
			status = 410
		case strings.HasPrefix(msg, "PAIRING_CONSUMED"):
			code = "PAIRING_CONSUMED"
			status = 409
		case strings.HasPrefix(msg, "VERSION_INVALID"):
			code = "VERSION_INVALID"
			status = 400
		}
		// Never echo node IDs, roles or secrets in the error body beyond the code.
		s.agentFail(w, r, status, code, "配对被拒绝。", "请确认 Node ID、角色与未过期的一次性配对码。")
		return
	}
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
	tasks, err := s.store.pendingTasksAt(node.ID, 8, s.now())
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
	if err := s.store.heartbeat(node.ID, body.AgentVersion, body.KernelVersion, s.now()); err != nil {
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
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<20 {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_INVALID", "安装制品大小或类型不安全。", "请重新安装匹配版本。")
		return
	}
	body, err := io.ReadAll(io.LimitReader(f, 128<<20+1))
	if err != nil || int64(len(body)) != info.Size() || len(body) > 128<<20 {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_UNAVAILABLE", "安装制品读取不完整。", "请重新安装匹配版本。")
		return
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != artifact.SHA256 {
		s.fail(w, r, 503, "INSTALL_ARTIFACT_CHANGED", "安装制品校验和不匹配。", "请重新安装匹配版本。")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="meshmux"`)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = w.Write(body)
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
	changed, err := s.store.reportResultAudited(node.ID, res, s.now())
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
	readback, err := s.store.nodeCoordinationReadback(nodeID, s.now())
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

func (s *Server) agentAuth(w http.ResponseWriter, r *http.Request) (Node, bool) {
	token := bearerToken(r)
	node, err := s.store.authenticateAgentAt(token, s.now())
	if err != nil {
		s.agentFail(w, r, 401, "AGENT_UNAUTHORIZED", "节点身份无效或已撤销。", "请使用配对时配发的节点专属身份重试。")
		return Node{}, false
	}
	return node, true
}
