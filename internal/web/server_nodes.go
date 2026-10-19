package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/agent"
)

// agentAPI reports whether the path is an outbound-Agent endpoint. These
// endpoints use Bearer identity instead of admin session + Origin, because
// the Agent connects from a remote host over HTTPS without a browser.
func agentAPI(path string) bool { return strings.HasPrefix(path, "/api/agent/") }

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
	nodes, err := s.store.listNodes()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	s.render(w, r, 200, NodesPage(pageData{Title: "代理节点", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP}, nodes, created, pairingCode, s.cfg.Origin))
}

func (s *Server) nodesList(w http.ResponseWriter, r *http.Request, _ session) {
	nodes, err := s.store.listNodes()
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
	if err := agent.ValidateNodeInputs(role, displayName, vless, ssh); err != nil {
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
	s.nodesPageWithCode(w, r, sess, &created, code)
}

func (s *Server) nodesPageWithCode(w http.ResponseWriter, r *http.Request, sess session, created *Node, code string) {
	nodes, err := s.store.listNodes()
	if err != nil {
		s.fail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取节点列表。", "请检查数据库。")
		return
	}
	s.render(w, r, 200, NodesPage(pageData{Title: "代理节点", Path: "/nodes", CSRF: sess.CSRF, Dev: s.cfg.DevHTTP}, nodes, created, code, s.cfg.Origin))
}

// pairAgent exchanges a one-time pairing code for a node-scoped identity.
// The code and the issued token never appear in logs; only operation_id and
// stable error codes are recorded.
func (s *Server) pairAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req agent.PairingRequest
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
	tasks, err := s.store.pendingTasks(node.ID, 8)
	if err != nil {
		s.agentFail(w, r, 503, "DATABASE_UNAVAILABLE", "无法读取任务。", "请稍后重试。")
		return
	}
	if tasks == nil {
		tasks = []agent.Task{}
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
	var body struct {
		AgentVersion  string `json:"agent_version"`
		KernelVersion string `json:"kernel_version"`
	}
	if err := decodeAgentJSON(r, &body); err != nil {
		s.agentFail(w, r, 400, "HEARTBEAT_INVALID", "心跳格式不正确。", "请上报 agent 与内核版本。")
		return
	}
	req := agent.PairingRequest{
		NodeID:        strings.Repeat("0", 32),
		Role:          "edge",
		PairingCode:   strings.Repeat("A", 43),
		AgentVersion:  body.AgentVersion,
		KernelVersion: body.KernelVersion,
	}
	if err := agent.ValidatePairingRequest(req); err != nil {
		s.agentFail(w, r, 400, "HEARTBEAT_INVALID", "心跳缺少版本信息。", "请上报 agent 与内核版本。")
		return
	}
	if err := s.store.heartbeat(node.ID, body.AgentVersion, body.KernelVersion, s.now()); err != nil {
		s.agentFail(w, r, 503, "DATABASE_UNAVAILABLE", "无法记录心跳。", "请稍后重试。")
		return
	}
	s.event(r, "AGENT_HEARTBEAT")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "paired", "operation_id": operation(r)})
}

func (s *Server) agentResult(w http.ResponseWriter, r *http.Request) {
	node, ok := s.agentAuth(w, r)
	if !ok {
		return
	}
	_ = node
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var res agent.TaskResult
	if err := decodeAgentJSON(r, &res); err != nil {
		s.agentFail(w, r, 400, "RESULT_INVALID", "任务结果格式不正确。", "请按固定 task schema 上报。")
		return
	}
	if err := s.store.reportResult(node.ID, res); err != nil {
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
		}
		s.agentFail(w, r, status, code, "任务结果被拒绝。", "请确认 operation_id 与固定状态机。")
		return
	}
	s.event(r, "AGENT_RESULT_RECORDED")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded", "operation_id": operation(r)})
}

func (s *Server) agentAuth(w http.ResponseWriter, r *http.Request) (Node, bool) {
	token := bearerToken(r)
	node, err := s.store.authenticateAgent(token)
	if err != nil {
		s.agentFail(w, r, 401, "AGENT_UNAUTHORIZED", "节点身份无效或已撤销。", "请使用配对时配发的节点专属身份重试。")
		return Node{}, false
	}
	// Refresh heartbeat timestamp on every authenticated call so Hub can
	// report liveness without a separate polling loop in PR A.
	_ = s.store.heartbeat(node.ID, node.AgentVersion, node.KernelVersion, time.Now())
	return node, true
}
