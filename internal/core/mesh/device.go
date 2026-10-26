package mesh

import (
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// The stable codes this package reports. They are part of the diagnostic
// contract: a caller logs the code and the operation id, and never a
// plaintext enrollment secret, a subscriber secret or free-form Headscale
// text. Every refusal is a *DomainError carrying one of these codes.
const (
	// CodeIDGenerationFailed: crypto/rand was unavailable while minting an
	// identity. The caller reports failure instead of degrading the identity.
	CodeIDGenerationFailed = "MESH_ID_GENERATION_FAILED"

	// CodeDeviceIDInvalid: the mesh device record id is not canonical.
	CodeDeviceIDInvalid = "MESH_DEVICE_ID_INVALID"
	// CodeDisplayNameInvalid: the display label is empty, too long or not
	// printable. It is a label only and never an identity.
	CodeDisplayNameInvalid = "MESH_DISPLAY_NAME_INVALID"
	// CodePurposeInvalid: the purpose is not proxy_mesh, mesh_only or
	// subnet_router.
	CodePurposeInvalid = "MESH_PURPOSE_INVALID"
	// CodePlatformInvalid: the platform is not a defined display hint.
	CodePlatformInvalid = "MESH_PLATFORM_INVALID"
	// CodeSubscriberBindingInvalid: the purpose and the subscriber binding
	// contradict each other, or the subscriber id is malformed.
	CodeSubscriberBindingInvalid = "MESH_SUBSCRIBER_BINDING_INVALID"
	// CodeNodeNameInvalid: the MeshMux-assigned node name is not a canonical
	// lowercase label.
	CodeNodeNameInvalid = "MESH_NODE_NAME_INVALID"
	// CodeNodeNameDuplicate: two devices that still occupy a name share it
	// inside one Headscale user.
	CodeNodeNameDuplicate = "MESH_NODE_NAME_DUPLICATE"
	// CodeHeadscaleUserInvalid: the Headscale user snapshot is malformed. The
	// snapshot is a label; this package never creates or edits the user.
	CodeHeadscaleUserInvalid = "MESH_HEADSCALE_USER_INVALID"
	// CodeHeadscaleNodeIDInvalid: an observed Headscale node id is missing for
	// a registered device, or present on a device that never registered.
	CodeHeadscaleNodeIDInvalid = "MESH_HEADSCALE_NODE_ID_INVALID"
	// CodeStatusInvalid: the device status is not a defined value.
	CodeStatusInvalid = "MESH_STATUS_INVALID"
	// CodeStatusTransitionInvalid: the requested lifecycle edge is not in the
	// transition table, or registration was attempted without observed
	// evidence.
	CodeStatusTransitionInvalid = "MESH_STATUS_TRANSITION_INVALID"
	// CodeRevokeDeviceMismatch: a revoke intent names a different device, so it
	// is refused instead of applied to the wrong record.
	CodeRevokeDeviceMismatch = "MESH_REVOKE_DEVICE_MISMATCH"
	// CodeRevokeReasonInvalid: the revoke reason is not a stable uppercase
	// code, so it could not be logged safely.
	CodeRevokeReasonInvalid = "MESH_REVOKE_REASON_INVALID"
)

// DomainError is a stable, log-safe refusal. Code is one of the constants
// above and Detail explains the violated rule without echoing labels, ids or
// secrets.
type DomainError struct {
	Code   string
	Detail string
}

func (e *DomainError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func failure(code, detail string) error { return &DomainError{Code: code, Detail: detail} }

// DefaultHeadscaleUser is the idempotent shared Headscale user of D2. This
// package only records the user name as a snapshot on the device; creating the
// user and any CLI or API call happen outside this package.
const DefaultHeadscaleUser = "meshmux"

// Purpose is what a mesh device is for. It decides the subscriber binding, not
// the client platform.
type Purpose string

// The stored purpose spellings are owned by the subscription IR, the lower
// layer both this domain and the device exporter read; the lifecycle meaning
// stays here.
const (
	// PurposeProxyMesh: the device also consumes the proxy subscription, so it
	// must be bound to a Subscriber.
	PurposeProxyMesh Purpose = ir.MeshPurposeProxyMesh
	// PurposeMeshOnly: a stock Tailscale client with no proxy subscription and
	// no subscriber; binding one would misstate the model.
	PurposeMeshOnly Purpose = ir.MeshPurposeMeshOnly
	// PurposeSubnetRouter: a Tailscale client or NAS that advertises LAN
	// prefixes. It may be bound to a Subscriber but does not need one.
	PurposeSubnetRouter Purpose = ir.MeshPurposeSubnetRouter
)

// Validate accepts only the three defined purposes.
func (p Purpose) Validate() error {
	switch p {
	case PurposeProxyMesh, PurposeMeshOnly, PurposeSubnetRouter:
		return nil
	default:
		return failure(CodePurposeInvalid, "purpose must be proxy_mesh, mesh_only or subnet_router")
	}
}

// Platform is a display hint for choosing the client template. It is never a
// device kind, a Headscale identity, a uniqueness key or a state-machine input:
// an iOS phone and a NAS with the same purpose and node name follow exactly the
// same lifecycle and binding rules. See ADR-0004.
type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
	PlatformLinux   Platform = "linux"
	PlatformNAS     Platform = "nas"
	PlatformOther   Platform = "other"
)

// Validate accepts only the five defined display hints.
func (p Platform) Validate() error {
	switch p {
	case PlatformIOS, PlatformAndroid, PlatformLinux, PlatformNAS, PlatformOther:
		return nil
	default:
		return failure(CodePlatformInvalid, "platform must be ios, android, linux, nas or other")
	}
}

// Status is the mesh device lifecycle state.
//
//	pending    → failed | revoking
//	registered → revoking | expired
//	expired    → pending | revoking
//	failed     → revoking
//	revoking   → revoked
//	revoked    → (terminal)
//
// A same-status transition is an idempotent no-op. revoked is the only terminal
// status and never transitions again. Registration is not an edge of this table:
// it needs observed evidence, see MeshDevice.MarkRegistered.
//
// The states answer one question: does the record have a live Headscale node?
// pending and failed have none; registered has one; expired means a node was
// registered and Headscale confirmed it is gone; revoking means the removal was
// requested and is not confirmed; revoked means it is confirmed gone.
//
// The enrollment window belongs to the key, not to the device: a key that
// lapses leaves the device pending ("registration not proven yet"), which is
// exactly what ADR-0004 asks for, instead of retiring the device. expired is
// therefore only reachable from registered, and a new enrollment goes
// expired → pending.
//
// failed is a settled enrollment failure with no Headscale node: a retried
// removal of a node Headscale already confirms gone is not a failure, and a
// remote revocation that fails keeps the device in revoking so the removal can
// be retried instead of inventing a state that hides a node. failed only leaves
// through revoking, so the caller either cleans up or retries the removal; it
// never returns to pending or registered, and a retried enrollment is a new
// device record, which is possible because failed releases the node name.
type Status string

const (
	// StatusPending: the device was created and no observed Headscale node
	// proves enrollment yet. A lapsed key does not move the device out of here.
	StatusPending Status = "pending"
	// StatusRegistered: the Headscale node id was observed after enrollment.
	StatusRegistered Status = "registered"
	// StatusExpired: the device was registered and Headscale confirmed its node
	// is no longer present. It keeps the last observed node id for display and
	// may re-enroll through pending.
	StatusExpired Status = "expired"
	// StatusRevoking: a revocation intent was accepted and the remote effect is
	// not confirmed yet.
	StatusRevoking Status = "revoking"
	// StatusRevoked: the device is confirmed gone from Headscale. Terminal.
	StatusRevoked Status = "revoked"
	// StatusFailed: a definite enrollment failure with no Headscale node; only
	// cleanup may follow.
	StatusFailed Status = "failed"
)

// Validate accepts only the six defined statuses.
func (s Status) Validate() error {
	switch s {
	case StatusPending, StatusRegistered, StatusExpired, StatusRevoking, StatusRevoked, StatusFailed:
		return nil
	default:
		return failure(CodeStatusInvalid, "status must be pending, registered, expired, revoking, revoked or failed")
	}
}

// OccupiesNodeName reports whether the status still reserves the device's node
// name. pending, registered and revoking exist (or may exist) in Headscale, so
// the name stays unique. expired releases it because Headscale confirmed the
// node is gone, failed never had one, and revoked removed it.
func (s Status) OccupiesNodeName() bool {
	switch s {
	case StatusPending, StatusRegistered, StatusRevoking:
		return true
	default:
		return false
	}
}

// TransitionAllowed reports whether from may move to to. A same-status
// transition is allowed as a no-op; registration is not an edge here because it
// requires observed evidence, see MeshDevice.MarkRegistered.
func TransitionAllowed(from, to Status) bool {
	if from == to {
		return from.Validate() == nil
	}
	switch from {
	case StatusPending:
		return to == StatusFailed || to == StatusRevoking
	case StatusRegistered:
		return to == StatusRevoking || to == StatusExpired
	case StatusExpired:
		// Re-enrollment starts a fresh attempt; the caller keeps the audit
		// history of the node that disappeared.
		return to == StatusPending || to == StatusRevoking
	case StatusFailed:
		return to == StatusRevoking
	case StatusRevoking:
		// A remote revocation is only settled by confirmed removal. A failed
		// removal keeps the device in revoking and reports partial/failed with a
		// stable code; it must not become failed, which would hide a node that
		// may still exist in Headscale.
		return to == StatusRevoked
	default:
		// revoked is terminal; an undefined status allows nothing.
		return false
	}
}

// MeshDevice is one Headscale-side device identity. ID is MeshMux's immutable
// record id; HeadscaleNodeID is the stable reference to the node Headscale
// owns. DisplayName is a mutable label while NodeName is the MeshMux-assigned
// name whose uniqueness the persistence layer must enforce while the status
// occupies it.
type MeshDevice struct {
	ID              string
	DisplayName     string
	Purpose         Purpose
	Platform        Platform
	SubscriberID    string
	HeadscaleUser   string
	NodeName        string
	HeadscaleNodeID uint64
	Status          Status
}

// DeviceSpec is the creation input. HeadscaleUser is optional and defaults to
// DefaultHeadscaleUser. DeclaredRoutes are subnet prefixes pre-declared while a
// subnet_router device is created; the store writes them as advertised routes
// with source=device, so the operator does not have to declare them twice.
type DeviceSpec struct {
	DisplayName    string
	Purpose        Purpose
	Platform       Platform
	NodeName       string
	SubscriberID   string
	HeadscaleUser  string
	DeclaredRoutes []string
}

// NewMeshDevice creates a pending device with a fresh random identity. It
// validates the purpose×subscriber binding, the node name and the Headscale
// user snapshot without performing any Headscale call. A caller that persists
// the device must still enforce node-name uniqueness while the status occupies
// the name; the store's unique index expresses the same rule.
func NewMeshDevice(spec DeviceSpec) (MeshDevice, error) {
	displayName, err := subscription.NormalizeDisplayName(spec.DisplayName)
	if err != nil {
		return MeshDevice{}, failure(CodeDisplayNameInvalid, "use 1-80 normalized printable characters")
	}
	if err := spec.Purpose.Validate(); err != nil {
		return MeshDevice{}, err
	}
	if err := spec.Platform.Validate(); err != nil {
		return MeshDevice{}, err
	}
	if err := ValidateSubscriberBinding(spec.Purpose, spec.SubscriberID); err != nil {
		return MeshDevice{}, err
	}
	// Pre-declared subnet routes are checked here so a malformed prefix refuses
	// the creation before any row is written. Only a subnet_router may declare
	// them, and the store persists the canonical form.
	if _, err := NormalizeDeclaredPrefixes(spec.Purpose, spec.DeclaredRoutes); err != nil {
		return MeshDevice{}, err
	}
	nodeName, err := NormalizeNodeName(spec.NodeName)
	if err != nil {
		return MeshDevice{}, err
	}
	user := spec.HeadscaleUser
	if user == "" {
		user = DefaultHeadscaleUser
	}
	user, err = NormalizeHeadscaleUser(user)
	if err != nil {
		return MeshDevice{}, err
	}
	id, err := subscription.NewID()
	if err != nil {
		return MeshDevice{}, failure(CodeIDGenerationFailed, "the mesh device identity could not be generated")
	}
	device := MeshDevice{
		ID:            id,
		DisplayName:   displayName,
		Purpose:       spec.Purpose,
		Platform:      spec.Platform,
		SubscriberID:  spec.SubscriberID,
		HeadscaleUser: user,
		NodeName:      nodeName,
		Status:        StatusPending,
	}
	if err := device.Validate(); err != nil {
		return MeshDevice{}, err
	}
	return device, nil
}

// ValidateSubscriberBinding is the purpose×subscriber CHECK rule on its own, so
// the creation form and the stored record share one implementation:
//
//	proxy_mesh    requires a valid subscriber id;
//	mesh_only     forbids any subscriber id;
//	subnet_router may carry a subscriber id, and a valid one when present.
func ValidateSubscriberBinding(purpose Purpose, subscriberID string) error {
	if err := purpose.Validate(); err != nil {
		return err
	}
	if subscriberID == "" {
		if purpose == PurposeProxyMesh {
			return failure(CodeSubscriberBindingInvalid, "proxy_mesh requires a subscriber id")
		}
		return nil
	}
	if purpose == PurposeMeshOnly {
		return failure(CodeSubscriberBindingInvalid, "mesh_only must not be bound to a subscriber")
	}
	if err := subscription.ValidateID(subscriberID); err != nil {
		return failure(CodeSubscriberBindingInvalid, "the subscriber id needs 32 lowercase hex characters")
	}
	return nil
}

// Validate checks the record without any I/O. It does not check uniqueness
// against other devices; the persistence layer enforces that while the status
// occupies the name.
func (d MeshDevice) Validate() error {
	if err := subscription.ValidateID(d.ID); err != nil {
		return failure(CodeDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	if err := subscription.ValidateDisplayName(d.DisplayName); err != nil {
		return failure(CodeDisplayNameInvalid, "use 1-80 normalized printable characters")
	}
	if err := d.Purpose.Validate(); err != nil {
		return err
	}
	if err := d.Platform.Validate(); err != nil {
		return err
	}
	if err := ValidateSubscriberBinding(d.Purpose, d.SubscriberID); err != nil {
		return err
	}
	if err := ValidateHeadscaleUser(d.HeadscaleUser); err != nil {
		return err
	}
	if err := ValidateNodeName(d.NodeName); err != nil {
		return err
	}
	if err := d.Status.Validate(); err != nil {
		return err
	}
	switch d.Status {
	case StatusPending, StatusFailed:
		if d.HeadscaleNodeID != 0 {
			return failure(CodeHeadscaleNodeIDInvalid, "a pending or failed device has no Headscale node")
		}
	case StatusRegistered:
		if d.HeadscaleNodeID == 0 {
			return failure(CodeHeadscaleNodeIDInvalid, "a registered device needs the observed Headscale node id")
		}
	}
	return nil
}

// Transition moves the device to next. A same-status call is an idempotent
// no-op on every status, including terminal ones. Registration is deliberately
// not reachable through this method: it needs the observed Headscale node id,
// so callers use MarkRegistered.
//
// Re-enrollment (expired → pending) clears HeadscaleNodeID, because pending
// means "no observed node is bound to this record's current attempt". The
// caller keeps any earlier node reference in its own audit record. Because an
// expired device releases its node name, a re-enrollment must re-check the
// name against other devices before it is persisted.
func (d MeshDevice) Transition(next Status) (MeshDevice, error) {
	if err := next.Validate(); err != nil {
		return d, err
	}
	if next == d.Status {
		return d, nil
	}
	if next == StatusRegistered {
		return d, failure(CodeStatusTransitionInvalid, "registration is recorded with MarkRegistered and the observed Headscale node id")
	}
	if !TransitionAllowed(d.Status, next) {
		return d, failure(CodeStatusTransitionInvalid, "the requested device status transition is not allowed")
	}
	if next == StatusPending {
		// Re-enrollment: the record starts a fresh attempt with no observed node.
		d.HeadscaleNodeID = 0
	}
	d.Status = next
	return d, nil
}

// MarkRegistered records a proven enrollment: the Headscale node id must be
// observed and non-zero. Only a pending device registers; a failed device is
// not resurrected (it gets a new record) and revoked never returns. An expired
// device must re-enroll through pending first, so one attempt maps to one
// registration.
func (d MeshDevice) MarkRegistered(headscaleNodeID uint64) (MeshDevice, error) {
	if err := d.Status.Validate(); err != nil {
		return d, err
	}
	if headscaleNodeID == 0 {
		return d, failure(CodeHeadscaleNodeIDInvalid, "registration needs the observed Headscale node id")
	}
	if d.Status != StatusPending {
		return d, failure(CodeStatusTransitionInvalid, "only a pending device can be registered")
	}
	d.HeadscaleNodeID = headscaleNodeID
	d.Status = StatusRegistered
	return d, nil
}

// RevokeIntent is one explicit request to remove a device. DeviceID guards
// against applying the intent to the wrong record, and Reason is a stable
// uppercase code retained by the caller's audit record so a log line needs no
// free-form text.
type RevokeIntent struct {
	DeviceID string
	Reason   string
}

// RevokeOutcome describes what applying a RevokeIntent did. Every outcome is a
// success; a repeated intent never fails and never moves a terminal device.
type RevokeOutcome string

const (
	// RevokeRequested: the device moved to revoking in this call.
	RevokeRequested RevokeOutcome = "revocation_requested"
	// RevokeInProgress: the device was already revoking; the first intent
	// still owns the transition.
	RevokeInProgress RevokeOutcome = "revocation_in_progress"
	// RevokeAlreadyRevoked: the device was already revoked; nothing changed.
	RevokeAlreadyRevoked RevokeOutcome = "already_revoked"
)

// ApplyRevoke applies a revoke intent idempotently. pending, registered,
// expired and failed all move to revoking; repeated calls report the existing
// state without changing it; a revoked device stays revoked. The domain keeps
// only the status effect: the caller persists and audits intent.Reason.
func (d MeshDevice) ApplyRevoke(intent RevokeIntent) (MeshDevice, RevokeOutcome, error) {
	if d.ID == "" || intent.DeviceID != d.ID {
		return d, "", failure(CodeRevokeDeviceMismatch, "the revoke intent must name this device")
	}
	if err := ValidateRevokeReason(intent.Reason); err != nil {
		return d, "", err
	}
	switch d.Status {
	case StatusRevoked:
		return d, RevokeAlreadyRevoked, nil
	case StatusRevoking:
		return d, RevokeInProgress, nil
	case StatusPending, StatusRegistered, StatusExpired, StatusFailed:
		d.Status = StatusRevoking
		return d, RevokeRequested, nil
	default:
		return d, "", failure(CodeStatusInvalid, "the device status is not a defined value")
	}
}

// ValidateRevokeReason accepts one stable uppercase code such as
// USER_DELETE or ENROLLMENT_FAILED.
func ValidateRevokeReason(reason string) error {
	const detail = "the revoke reason must be a stable uppercase code"
	if len(reason) < 3 || len(reason) > 64 || reason[0] < 'A' || reason[0] > 'Z' {
		return failure(CodeRevokeReasonInvalid, detail)
	}
	for i := 1; i < len(reason); i++ {
		c := reason[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return failure(CodeRevokeReasonInvalid, detail)
		}
	}
	return nil
}

// NormalizeNodeName trims and lowercases one MeshMux-assigned node name. The
// name is the Headscale given name MeshMux assigns, not the hostname a Tailscale
// client reports, so it is always a canonical lowercase label.
func NormalizeNodeName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if err := ValidateNodeName(name); err != nil {
		return "", err
	}
	return name, nil
}

// ValidateNodeName requires an already canonical lowercase label of 1-63
// characters that starts and ends alphanumeric.
func ValidateNodeName(name string) error {
	const detail = "need 1-63 lowercase letters, digits or hyphens, starting and ending alphanumeric"
	if len(name) < 1 || len(name) > 63 {
		return failure(CodeNodeNameInvalid, detail)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := isLowerAlphanumeric(c)
		if !alnum && c != '-' {
			return failure(CodeNodeNameInvalid, detail)
		}
		if (i == 0 || i == len(name)-1) && !alnum {
			return failure(CodeNodeNameInvalid, detail)
		}
	}
	return nil
}

// NormalizeHeadscaleUser trims and lowercases the Headscale user snapshot.
func NormalizeHeadscaleUser(raw string) (string, error) {
	user := strings.ToLower(strings.TrimSpace(raw))
	if err := ValidateHeadscaleUser(user); err != nil {
		return "", err
	}
	return user, nil
}

// ValidateHeadscaleUser requires a canonical lowercase Headscale user name of
// 1-63 characters that starts and ends alphanumeric. The snapshot only records
// which user owns the device; this package never creates the user.
func ValidateHeadscaleUser(user string) error {
	const detail = "need 1-63 lowercase letters, digits, dots, underscores or hyphens, starting and ending alphanumeric"
	if len(user) < 1 || len(user) > 63 {
		return failure(CodeHeadscaleUserInvalid, detail)
	}
	for i := 0; i < len(user); i++ {
		c := user[i]
		alnum := isLowerAlphanumeric(c)
		if !alnum && c != '.' && c != '_' && c != '-' {
			return failure(CodeHeadscaleUserInvalid, detail)
		}
		if (i == 0 || i == len(user)-1) && !alnum {
			return failure(CodeHeadscaleUserInvalid, detail)
		}
	}
	return nil
}

func isLowerAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
