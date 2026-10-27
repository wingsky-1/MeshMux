package view

import "github.com/wingsky-1/MeshMux/internal/control/store"

// SubscriberView is the management view of one subscription user.
type SubscriberView struct {
	ID          string
	DisplayName string
	State       string
	StateLabel  string
	StateClass  string
	SyncStatus  string
	SyncLabel   string
	SyncClass   string
	SyncCode    string
	Lines       []SubscriberLineView
	Confirmed   int
	Total       int
	Credentials int
}

// SubscriberLineView is one Line as it is shown for one subscriber.
type SubscriberLineView struct {
	NodeID      string
	DisplayName string
	Server      string
	// ServerSource is the origin of Server: reported or manual.
	ServerSource string
	Port         int
	SortOrder    int
	Selected     bool
	Intent       string
	SyncStatus   string
	SyncCode     string
	Confirmed    string
	ConfirmedOK  bool
	ErrorCode    string
}

// SubscriberPageView is the complete page model.
type SubscriberPageView struct {
	Subscribers []SubscriberView
	Lines       []LineView
	EdgeNodes   []store.Node
	Token       string
	TokenOwner  string
	Origin      string
}

// LineView is one configured Line transport. It never carries the REALITY
// private key, the short ID or any credential.
type LineView struct {
	NodeID      string
	DisplayName string
	Server      string
	// ServerSource is the origin of Server: reported or manual.
	ServerSource  string
	Port          int
	SortOrder     int
	ServerName    string
	Handshake     string
	HandshakePort int
	Local         bool
}

// addressSourceLabel renders the origin of one effective Line or Out address.
// An empty source is a legacy manual row or an egress that has no agent
// address (an external HTTP proxy), so it renders nothing.
func addressSourceLabel(source string) string {
	switch source {
	case store.AddressSourceReported:
		return "上报"
	case store.AddressSourceManual:
		return "手填"
	default:
		return ""
	}
}

// addressSourceSuffix appends the origin to an endpoint string only when the
// origin is known.
func addressSourceSuffix(source string) string {
	if label := addressSourceLabel(source); label != "" {
		return " · " + label
	}
	return ""
}
