package view

// The subscription wizard view model (Task 4, ADR-0008 §1–§4).
//
// The wizard renders the four selection groups of one subscription and the
// fail-fast result of the last preview or save:
//
//   - "!" marks a reminder: it never blocks a save or a download;
//   - "✖" marks a blocking finding: nothing was saved.
//
// A group with no selectable row is never an empty control. The Out group and
// the mesh group state their 1.0 execution status explicitly ("已记录，执行待
// 1.1"), so an operator can never believe a double hop or a subnet route is
// already running because they selected it.

// WizardLine is one selectable Line row.
type WizardLine struct {
	NodeID       string
	DisplayName  string
	Server       string
	ServerSource string
	Port         int
	SortOrder    int
	Selected     bool
	Credential   string
	Converged    bool
	Code         string
}

// WizardOut is one selectable egress row: a MeshMux Out or an external HTTP
// proxy (Ruling R11). Kind is the node role; an external proxy has no
// heartbeat, so its state label is 外部 instead of online/offline.
type WizardOut struct {
	OutID        string
	DisplayName  string
	Server       string
	ServerSource string
	Port         int
	Online       bool
	Configured   bool
	Selected     bool
	Kind         string
}

// External reports whether the row is an external HTTP proxy.
func (o WizardOut) External() bool { return o.Kind == "http" }

// WizardRule is one selectable rule revision.
type WizardRule struct {
	StableKey string
	Version   int
	Name      string
	Action    string
	Matcher   string
	Preset    bool
	Selected  bool
	// UpgradeHint is set when a newer revision of the same key exists: the
	// subscription stays on its pinned revision until the operator migrates.
	UpgradeHint string
}

// WizardDevice is one selectable mesh device.
type WizardDevice struct {
	DeviceID    string
	DisplayName string
	Purpose     string
	Status      string
	Selected    bool
}

// WizardDiagnostic is one rendered finding.
type WizardDiagnostic struct {
	Blocking bool
	Code     string
	Detail   string
}

// SubscriptionWizardView is the whole wizard page model.
type SubscriptionWizardView struct {
	SubscriberID   string
	SubscriberName string
	State          string
	Lines          []WizardLine
	Outs           []WizardOut
	Rules          []WizardRule
	Devices        []WizardDevice
	Diagnostics    []WizardDiagnostic
	Saved          bool
	GateNote       string
	ContentID      string
	Notice         string
	// Create is true on the create form: the name field is required and no
	// token or convergence evidence exists yet.
	Create bool
}

// DiagnosticBlocking reports whether one rendered finding refuses the save.
func (d WizardDiagnostic) Marker() string {
	if d.Blocking {
		return "✖"
	}
	return "!"
}

// WizardClass maps one finding onto the badge palette.
func (d WizardDiagnostic) Class() string {
	if d.Blocking {
		return "badge failure"
	}
	return "badge"
}

// GateLabel renders the kernel evidence of the last preview or save.
func (v SubscriptionWizardView) GateLabel() string {
	if v.GateNote == "" {
		return "尚未校验"
	}
	return v.GateNote
}
