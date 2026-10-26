package view

// MeshUserView is one selectable Headscale user. The list is read live; the
// device only stores a name snapshot.
type MeshUserView struct {
	ID   uint64
	Name string
}

// MeshSubscriberView is one selectable subscriber for a proxy_mesh binding.
type MeshSubscriberView struct {
	ID          string
	DisplayName string
	State       string
}

// MeshKeyDisclosure carries one plaintext enrollment key and, for a
// proxy+mesh device, the one-shot client configuration that embeds the
// Headscale pre-auth key. It is filled only for the single POST response that
// issues it; renderMesh never persists or re-renders it.
type MeshKeyDisclosure struct {
	Device  string
	Secret  string
	Expires string
	Config  string
	// JoinCommand is the standard Tailscale join command for devices without
	// a generated sing-box config (mesh-only / subnet-router). It never
	// embeds the secret: the key stays in its own single <pre> so the
	// exactly-once assertion keeps holding. Empty when the control-plane
	// origin is not configured; LoginConfigured tells the two cases apart.
	JoinCommand     string
	LoginConfigured bool
}

// MeshDeviceView is the complete read projection of one device. It carries no
// secret: the key state is a state label, never a value.
type MeshDeviceView struct {
	ID             string
	DisplayName    string
	PurposeLabel   string
	PlatformLabel  string
	HeadscaleUser  string
	NodeName       string
	SubscriberID   string
	SubscriberName string
	NodeID         string
	TailnetIP      string
	Online         string
	OnlineClass    string
	ObservedAt     string
	StatusLabel    string
	StatusClass    string
	KeyLabel       string
	KeyClass       string
	KeyExpires     string
	RevokeReason   string
	CanIssue       bool
	CanConfig      bool
	CanRevoke      bool
	CanRetry       bool
	Routes         []MeshRouteView
	Claims         []MeshClaimView
}

// MeshRouteView is one subnet prefix of one device. The three remote columns
// come from the same read-only `nodes list` snapshot that already annotates the
// page; they are not persisted. Desired, the last observed value and the audit
// operation id come from the Hub record, so the page never presents an
// observation as an approval or an approval as served evidence.
type MeshRouteView struct {
	Prefix        string
	DesiredLabel  string
	DesiredClass  string
	ObservedLabel string
	ObservedAt    string
	Approved      bool
	Available     bool
	Served        bool
	RemoteKnown   bool
	OperationID   string
	CanApprove    bool
	CanWithdraw   bool
}

// MeshClaimView is one Headscale node that carries the same name as a pending
// MeshMux device but is not owned by any device record. It is only a
// suggestion: claiming needs an explicit POST, and recordMeshObservation is the
// same evidence path a reconcile uses.
type MeshClaimView struct {
	NodeID   string
	Name     string
	UserName string
}

// MeshPageView is the whole page model.
type MeshPageView struct {
	Devices     []MeshDeviceView
	Users       []MeshUserView
	Subscribers []MeshSubscriberView
	UsersNotice string
	NodesNotice string
	DefaultUser string
	Disclosure  *MeshKeyDisclosure
	Notice      string
	NoticeClass string
}
