package policy

// Store half of the publication step.
//
// A publication stores no node artifact any more: the server publishes proxy
// ports and credentials only, a Line candidate carries its listener and user
// set, and every routing rule lives in the client document a subscriber
// downloads. What a publication still does is exactly what the gate proved — the
// active intent is valid and the client preview documents pass their kernels —
// and the receipt says so. Nothing here executes or claims an apply: the Agent's
// own four-task chain and readback remain the only proof a host is converged.

import (
	"errors"
	"strings"
	"time"
)

// Stable publication-step refusals.
const (
	// CodePublishRevisionChanged: another publication advanced a revision
	// between the gate and the store. The gated bytes are stale, so the
	// publication is refused instead of reporting evidence it no longer has.
	CodePublishRevisionChanged = "PUBLISH_REVISION_CHANGED"
	// CodePublishTasksInProgress: a node still has an unfinished chain. It is
	// no longer produced by a publication (nothing is published) but stays
	// declared so an older receipt and the frozen vocabulary keep resolving.
	CodePublishTasksInProgress = "TASKS_IN_PROGRESS"
	// codePublishCandidateChanged: rebuilding a candidate produced different
	// content than the gated document. Retained for the same reason as above.
	codePublishCandidateChanged = "PUBLISH_CANDIDATE_CHANGED"
)

// PolicyPublication is the stored result of one publication.
type PolicyPublication struct {
	Lines     []PolicyLineEvidence
	FirstHash string
}

// publicationRollbackNote explains what a failure leaves behind. It is stable
// text, so an operator reads the same recovery contract every time.
const publicationRollbackNote = "失败不会写入任何修订：门禁拒绝时什么都不会存储；已下发链失败时 Agent 恢复上一份 LKG 配置并报告 partial/rolled_back。"

// clientPreviewNote explains what a gated client layer really is: a rendered,
// kernel-checked preview. The standard subscription exporter composes from the
// subscription selection, so no receipt may claim that a publication changes
// what a subscriber downloads.
const clientPreviewNote = "客户端层仅为预览与门禁校验：文档已渲染并通过 sing-box / Mihomo 检查，但不会写节点候选，也不改变订阅下载内容。"

// serverLayerRetiredNote explains the server layer's retirement: the Hub no
// longer renders or delivers routing rules.
const serverLayerRetiredNote = "服务端不再下发路由规则：分流全部在客户端生效，Line 只发布监听端口与用户凭据。"

// PublishPolicyAssembly completes one publication.
//
// Nothing is stored: the assembly is evidence (validated intent plus gated
// client documents) and the receipt reports exactly that. Targets are retired
// with the server-route delivery chain, so an assembly that still carries one
// (from an older caller) is refused instead of being written.
func (s *Store) PublishPolicyAssembly(assembly PolicyAssembly, now time.Time) (PolicyPublication, error) {
	if len(assembly.Targets) > 0 {
		return PolicyPublication{}, errors.New(CodePublishNoLines + ": the server no longer publishes line candidates")
	}
	if assembly.ClientRevision == 0 && assembly.ServerRevision == 0 {
		return PolicyPublication{}, errors.New(CodePublishNoPolicy + ": the assembly carries no active policy revision")
	}
	return PolicyPublication{}, nil
}

// publicationReceipt is the typed success receipt of one gated publication.
//
// It never claims a queued node revision: no candidate is written any more. The
// status is "gated", the revision is whichever layer the caller asked for, and
// the next action states that routing rules are client-side only.
func PublicationReceipt(assembly PolicyAssembly, publication PolicyPublication) PolicyPublishReceipt {
	lines := append([]PolicyLineEvidence(nil), publication.Lines...)
	receipt := PolicyPublishReceipt{
		OK:                   true,
		Status:               "gated",
		NextAction:           serverLayerRetiredNote + publicationRollbackNote,
		EgressState:          assembly.EgressState,
		EgressCode:           assembly.EgressCode,
		PolicySchema:         assembly.PolicySchema,
		RoutePolicyRevisions: assembly.RoutePolicyRevisions,
		Checks:               assembly.Checks,
		Lines:                lines,
	}
	switch {
	case assembly.ServerRevision > 0:
		receipt.Revision = assembly.ServerRevision
	case assembly.ClientRevision > 0:
		receipt.Revision = assembly.ClientRevision
	}
	if assembly.ClientRevision > 0 && assembly.ServerRevision == 0 {
		receipt.NextAction = clientPreviewNote + publicationRollbackNote
	}
	return receipt
}

// PublishRetryHint maps a publication refusal onto the operator's next step.
func PublishRetryHint(err error) string {
	code := err.Error()
	switch {
	case strings.HasPrefix(code, CodePublishRevisionChanged), strings.HasPrefix(code, codePublishCandidateChanged):
		return "策略发布期间快照已变化；请重新提交发布。"
	case strings.HasPrefix(code, CodePublishTasksInProgress):
		return "等待当前配置任务结束后重新发布；已应用配置保持不变。"
	}
	return "请凭操作编号检查服务日志后重试；已应用配置保持不变。"
}
