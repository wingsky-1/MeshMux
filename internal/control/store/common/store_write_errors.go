package common

// Persistence refusals repeated by several writers of this package.
//
// A write failure is not a message: it is a stable code an operator page maps
// to a status and a next action. Three writers (subscriber creation, the wizard
// save, the node/HTTP-proxy create path) each emit the same handful of codes, so
// they are declared here once. No caller re-types the string, and a page that
// adds a case reads the same constant.
//
// Each value is a distinct error so callers may compare them with errors.Is; the
// code stays in front of the colon for the page mapping.

import "errors"

var (
	// ErrCredentialCreateFailed: the per-Line VLESS credential row was not
	// stored.
	ErrCredentialCreateFailed = errors.New("CREDENTIAL_CREATE_FAILED")
	// ErrCredentialUpdateFailed: an existing credential row could not be
	// reactivated or deactivated.
	ErrCredentialUpdateFailed = errors.New("CREDENTIAL_UPDATE_FAILED")
	// ErrTokenCreateFailed: the subscription bearer row was not stored.
	ErrTokenCreateFailed = errors.New("TOKEN_CREATE_FAILED")
	// ErrTokenRevokeFailed: a bearer could not be revoked.
	ErrTokenRevokeFailed = errors.New("TOKEN_REVOKE_FAILED")
	// ErrSubscriberCreateFailed: the subscriber row was not stored.
	ErrSubscriberCreateFailed = errors.New("SUBSCRIBER_CREATE_FAILED")
	// ErrSubscriberUpdateFailed: the subscriber revision bump was not stored.
	ErrSubscriberUpdateFailed = errors.New("SUBSCRIBER_UPDATE_FAILED")
	// ErrNodeCreateFailed: the node row was not stored.
	ErrNodeCreateFailed = errors.New("NODE_CREATE_FAILED")
	// ErrCandidateRenderFailed: the candidate document could not be encoded.
	ErrCandidateRenderFailed = errors.New("CANDIDATE_RENDER_FAILED")
	// ErrLineSettingsFailed: the Line transport row was not stored.
	ErrLineSettingsFailed = errors.New("LINE_SETTINGS_FAILED")
	// ErrPairingInvalid: a pairing code was refused.
	ErrPairingInvalid = errors.New("PAIRING_INVALID: pairing code rejected")

	// ErrLineRoleInvalid says only an edge node can serve a proxy Line.
	ErrLineRoleInvalid = errors.New("LINE_ROLE_INVALID: only edge nodes can serve proxy lines")
	// ErrLineSettingsCorrupt marks a stored Line that does not satisfy the
	// domain contract. The message carries the stable code only, never the
	// stored values.
	ErrLineSettingsCorrupt = errors.New("LINE_SETTINGS_CORRUPT: stored line settings are invalid")
	// ErrOutRoleInvalidSource says only an Out carries a source authorization.
	ErrOutRoleInvalidSource = errors.New("OUT_ROLE_INVALID: only out nodes carry a source authorization")
	// ErrUpgradeRecordCorrupt says a persisted upgrade target is not actionable.
	ErrUpgradeRecordCorrupt = errors.New("UPGRADE_RECORD_CORRUPT: the persisted upgrade target is not actionable")
)
