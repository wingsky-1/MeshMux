package upgrade

import (
	"errors"
	"regexp"
)

// This file is the release-target half of the package, merged from internal/jobs
// by the internal regroup (Task 6): the release a task record converges a node
// to, and the operation id that record carries. The manifest half (manifest.go)
// describes what this binary believes a release is; the two share the
// releaseVersion and digestSHA shapes so neither keeps a drifting copy.
//
// 职责：目标发行引用（SemVer 版本、manifest SHA-256、`policy_schema` 快照、
// candidate revision）与 `operation_id` 形状校验。升级任务的状态、修订与拉取
// 复用 internal/web 的既有 agent_tasks 列和固定四任务链，不在这里复制第二套
// 阶段机。
//
// 边界：不执行 I/O，不建表、不排队、不启动进程，也不 import internal/web 或
// internal/install 的特权动作；升级的执行器、apply 与回滚属 #11c 系。不扩展
// Agent allowlist，不支持任意 shell、路径或外部 URL。
//
// See ADR-0007 (修订记录 PR-11b 与 2026-10-26 Task 6); v1.0.0 deliberately
// ships without a generic task engine, queue or daemon.

// operationID is the correlation id shape: 32 lowercase hex characters, the same
// shape every other operation_id in MeshMux uses. It is a separate expression
// from the manifest validators below because those describe release documents,
// not task revisions.
var operationID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ValidateOperationID requires the correlation id every revision carries. An
// empty value is a missing correlation, never a valid default.
func ValidateOperationID(id string) error {
	if id == "" {
		return errors.New("OPERATION_ID_REQUIRED: every task revision needs an operation_id")
	}
	if !operationID.MatchString(id) {
		return errors.New("OPERATION_ID_INVALID: need 32 lowercase hex")
	}
	return nil
}

// Target names the release a task record converges a node to. ManifestSHA256
// pins the exact manifest document, so a record never trusts a mutable version
// string alone; CandidateRevision names the candidate revision it maps to.
type Target struct {
	Version           string
	ManifestSHA256    string
	PolicySchema      int
	CandidateRevision int64
}

// Validate refuses a target this binary cannot describe: a floating version, an
// unpinned manifest digest, a missing policy schema or a missing staged revision.
//
// releaseVersion and digestSHA are the manifest's own shapes (manifest.go): a
// target is an existing manifest projected onto a task, so accepting a version
// or a digest the manifest would refuse would only create a record nothing can
// act on.
func (t Target) Validate() error {
	switch {
	case !releaseVersion.MatchString(t.Version):
		return errors.New("TARGET_VERSION_INVALID: target is not a SemVer release")
	case !digestSHA.MatchString(t.ManifestSHA256):
		return errors.New("TARGET_MANIFEST_INVALID: manifest digest is not pinned")
	case t.PolicySchema < 1:
		return errors.New("TARGET_POLICY_SCHEMA_INVALID: policy schema must be positive")
	case t.CandidateRevision < 1:
		return errors.New("TARGET_REVISION_INVALID: target needs a staged candidate revision")
	}
	return nil
}
