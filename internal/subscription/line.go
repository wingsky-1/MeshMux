package subscription

import "errors"

// Line is the client-facing transport for one existing node. NodeID is a
// stable reference to the node domain; this package never creates or duplicates
// a node identity. DisplayName is only a label and can change without touching
// NodeID, credentials or REALITY keys.
type Line struct {
	NodeID          string
	DisplayName     string
	Server          string
	Port            int
	SortOrder       int
	ServerName      string
	HandshakeServer string
	HandshakePort   int
	PrivateKey      string
	PublicKey       string
	ShortID         string
	Local           bool
}

// Validate checks the transport for one VLESS/REALITY Line. Local only records
// that the Hub hosts the Line; it never bypasses validation or permits code,
// paths or arbitrary commands.
func (l Line) Validate() error {
	if err := ValidateID(l.NodeID); err != nil {
		return errors.New("LINE_NODE_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateDisplayName(l.DisplayName); err != nil {
		return err
	}
	if !validHost(l.Server) {
		return errors.New("LINE_SERVER_INVALID: need one hostname or IP address without scheme, path, port or credentials")
	}
	if l.Port < 1 || l.Port > 65535 {
		return errors.New("LINE_PORT_INVALID: port must be 1-65535")
	}
	if l.SortOrder < 0 {
		return errors.New("LINE_SORT_ORDER_INVALID: sort_order must be non-negative")
	}
	if !validHost(l.ServerName) {
		return errors.New("LINE_SERVER_NAME_INVALID: need one hostname or IP address without scheme, path, port or credentials")
	}
	if !validHost(l.HandshakeServer) {
		return errors.New("LINE_HANDSHAKE_SERVER_INVALID: need one hostname or IP address without scheme, path, port or credentials")
	}
	if l.HandshakePort < 1 || l.HandshakePort > 65535 {
		return errors.New("LINE_HANDSHAKE_PORT_INVALID: handshake_port must be 1-65535")
	}
	if err := validateRealityKeyPair(l.PrivateKey, l.PublicKey); err != nil {
		return err
	}
	if err := ValidateShortID(l.ShortID); err != nil {
		return err
	}
	return nil
}

// Rename returns a copy with a normalized display name and every identity and
// transport field unchanged.
func (l Line) Rename(displayName string) (Line, error) {
	name, err := NormalizeDisplayName(displayName)
	if err != nil {
		return l, err
	}
	l.DisplayName = name
	return l, nil
}
