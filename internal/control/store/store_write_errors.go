package store

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
	// errCredentialCreateFailed: the per-Line VLESS credential row was not
	// stored.
	errCredentialCreateFailed = errors.New("CREDENTIAL_CREATE_FAILED")
	// errCredentialUpdateFailed: an existing credential row could not be
	// reactivated or deactivated.
	errCredentialUpdateFailed = errors.New("CREDENTIAL_UPDATE_FAILED")
	// errTokenCreateFailed: the subscription bearer row was not stored.
	errTokenCreateFailed = errors.New("TOKEN_CREATE_FAILED")
	// errTokenRevokeFailed: a bearer could not be revoked.
	errTokenRevokeFailed = errors.New("TOKEN_REVOKE_FAILED")
	// errSubscriberCreateFailed: the subscriber row was not stored.
	errSubscriberCreateFailed = errors.New("SUBSCRIBER_CREATE_FAILED")
	// errSubscriberUpdateFailed: the subscriber revision bump was not stored.
	errSubscriberUpdateFailed = errors.New("SUBSCRIBER_UPDATE_FAILED")
	// errNodeCreateFailed: the node row was not stored.
	errNodeCreateFailed = errors.New("NODE_CREATE_FAILED")
	// errCandidateRenderFailed: the candidate document could not be encoded.
	errCandidateRenderFailed = errors.New("CANDIDATE_RENDER_FAILED")
	// errLineSettingsFailed: the Line transport row was not stored.
	errLineSettingsFailed = errors.New("LINE_SETTINGS_FAILED")
	// errPairingInvalid: a pairing code was refused.
	errPairingInvalid = errors.New("PAIRING_INVALID: pairing code rejected")

	// errLineRoleInvalid says only an edge node can serve a proxy Line.
	errLineRoleInvalid = errors.New("LINE_ROLE_INVALID: only edge nodes can serve proxy lines")
	// errLineSettingsCorrupt marks a stored Line that does not satisfy the
	// domain contract. The message carries the stable code only, never the
	// stored values.
	errLineSettingsCorrupt = errors.New("LINE_SETTINGS_CORRUPT: stored line settings are invalid")
	// errOutRoleInvalidSource says only an Out carries a source authorization.
	errOutRoleInvalidSource = errors.New("OUT_ROLE_INVALID: only out nodes carry a source authorization")
	// errUpgradeRecordCorrupt says a persisted upgrade target is not actionable.
	errUpgradeRecordCorrupt = errors.New("UPGRADE_RECORD_CORRUPT: the persisted upgrade target is not actionable")
)
