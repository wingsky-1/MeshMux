package web

// Store half of the publication step: the gated assembly becomes one immutable
// candidate revision per Line, in one transaction.
//
// The transaction is the atomicity boundary. Either every Line receives its new
// revision and the fixed four-task chain, or nothing is stored at all, so a
// publication can never leave half the Lines on the new policy and half on the
// previous one.
//
// What happens after the transaction is the existing Agent contract and is not
// re-implemented here: the Agent pulls the chain, checks the staged bytes,
// applies them, reads them back and keeps its last-known-good configuration as
// the rollback target. A failure there is reported through the task rows and
// recovered by the Agent's own recover/LKG path, which is why this file never
// claims a Line is applied.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Stable publication-step refusals.
const (
	// codePublishRevisionChanged: another publication (or subscriber change)
	// advanced the candidate revision between the gate and the store. The
	// gated bytes are stale, so the publication is refused instead of storing
	// a document the gate never checked.
	codePublishRevisionChanged = "PUBLISH_REVISION_CHANGED"
	// codePublishTasksInProgress: a Line still has an unfinished chain, so a
	// new revision would replace work in flight.
	codePublishTasksInProgress = "TASKS_IN_PROGRESS"
	// codePublishCandidateChanged: rebuilding the candidate produced different
	// content than the gated document.
	codePublishCandidateChanged = "PUBLISH_CANDIDATE_CHANGED"
)

// policyPublication is the stored result of one publication.
type policyPublication struct {
	Lines     []policyLineEvidence
	FirstHash string
}

// publicationRollbackNote explains what a failure leaves behind. It is stable
// text, so an operator reads the same recovery contract every time.
const publicationRollbackNote = "失败不会写入半套修订：候选与四任务链在同一事务内提交或回滚；已下发链失败时 Agent 恢复上一份 LKG 配置并报告 partial/rolled_back。"

// publishPolicyAssembly stores the gated assembly. Every target is re-derived
// inside the transaction at its current revision and must reproduce the content
// the gate checked; a mismatch refuses the whole publication.
func (s *store) publishPolicyAssembly(assembly policyAssembly, now time.Time) (policyPublication, error) {
	if len(assembly.Targets) == 0 {
		// A client-only publication has no node candidate: its documents are
		// rendered and gated, and the subscription path renders the same active
		// revision on download. Nothing is stored, so nothing can be half-stored.
		if assembly.ClientRevision > 0 && assembly.ServerRevision == 0 {
			return policyPublication{}, nil
		}
		return policyPublication{}, errors.New(codePublishNoLines + ": the assembly has no target line")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return policyPublication{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	result := policyPublication{Lines: make([]policyLineEvidence, 0, len(assembly.Targets))}
	for _, target := range assembly.Targets {
		evidence, err := publishTargetTx(tx, target, now)
		if err != nil {
			return policyPublication{}, err
		}
		result.Lines = append(result.Lines, evidence)
		if result.FirstHash == "" {
			result.FirstHash = target.ConfigHash
		}
	}
	if err := tx.Commit(); err != nil {
		return policyPublication{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return result, nil
}

// publishTargetTx re-derives and stores one Line revision in the caller's
// transaction. A Line with work in flight is refused instead of replaced.
func publishTargetTx(tx *sql.Tx, target publishTarget, now time.Time) (policyLineEvidence, error) {
	var unfinished int
	if err := tx.QueryRow(`SELECT count(*) FROM agent_tasks
 WHERE node_id=? AND status IN ('pending','applying','verifying')`, target.LineID).Scan(&unfinished); err != nil {
		return policyLineEvidence{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if unfinished != 0 {
		return policyLineEvidence{}, errors.New(codePublishTasksInProgress + ": the line has an unfinished task chain; retry after it finishes")
	}
	revision, err := nextCandidateRevisionTx(tx, target.LineID)
	if err != nil {
		return policyLineEvidence{}, err
	}
	if revision != target.Candidate.Revision {
		return policyLineEvidence{}, errors.New(codePublishRevisionChanged + ": the candidate revision advanced after the gate; retry the publication")
	}
	if !sameSnapshotCandidateTx(tx, target) {
		return policyLineEvidence{}, errors.New(codePublishCandidateChanged + ": the line snapshot changed after the gate; retry the publication")
	}
	if _, err = publishCandidateTx(tx, target.LineID, target.Candidate, now); err != nil {
		return policyLineEvidence{}, err
	}
	return policyLineEvidence{
		LineID: target.LineID, Revision: revision, EgressState: target.Egress,
		EgressCode: target.EgressCode, Status: "queued",
	}, nil
}

// sameSnapshotCandidateTx rebuilds the Line snapshot inside the caller's
// transaction and compares it with the gated target. Only the route is allowed
// to differ, because the publication itself adds it.
func sameSnapshotCandidateTx(tx *sql.Tx, target publishTarget) bool {
	rebuilt, err := buildLineCandidateTx(tx, target.LineID, target.Candidate.Revision)
	if err != nil {
		return false
	}
	gated := target.Candidate
	gated.Route = nil
	return rebuilt.Equal(gated)
}

// publicationReceipt is the typed success receipt of one stored publication.
func publicationReceipt(assembly policyAssembly, publication policyPublication) policyPublishReceipt {
	lines := append([]policyLineEvidence(nil), publication.Lines...)
	receipt := policyPublishReceipt{
		OK:                   true,
		Status:               "queued",
		NextAction:           publicationRollbackNote,
		EgressState:          assembly.EgressState,
		EgressCode:           assembly.EgressCode,
		PolicySchema:         assembly.PolicySchema,
		RoutePolicyRevisions: assembly.RoutePolicyRevisions,
		Checks:               assembly.Checks,
		Lines:                lines,
	}
	if len(publication.Lines) > 0 {
		receipt.Revision = publication.Lines[0].Revision
		receipt.Candidate = &policyCandidateEvidence{
			Revision: publication.Lines[0].Revision,
			Lines:    len(publication.Lines),
			Config:   publication.FirstHash,
		}
		return receipt
	}
	// A client-only publication stores no node candidate: the client documents
	// are rendered per subscriber from the subscription path. The receipt names
	// the gated client revision and says so, instead of claiming a candidate
	// that does not exist.
	receipt.Status = "gated"
	receipt.Revision = assembly.ClientRevision
	receipt.NextAction = "客户端层已通过门禁并保持 active；订阅下载时按当前 active 版本渲染，无节点候选下发。" + publicationRollbackNote
	return receipt
}

func writePublicationReceipt(w http.ResponseWriter, status int, receipt policyPublishReceipt, operationID string) {
	receipt.OperationID = operationID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(receipt)
}

// publishRetryHint maps a publication refusal onto the operator's next step.
func publishRetryHint(err error) string {
	code := err.Error()
	switch {
	case strings.HasPrefix(code, codePublishRevisionChanged), strings.HasPrefix(code, codePublishCandidateChanged):
		return "策略发布期间快照已变化；请重新提交发布。"
	case strings.HasPrefix(code, codePublishTasksInProgress):
		return "等待当前配置任务结束后重新发布；已应用配置保持不变。"
	}
	return "请凭操作编号检查服务日志后重试；已应用配置保持不变。"
}
