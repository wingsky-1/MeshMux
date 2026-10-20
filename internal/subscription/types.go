package subscription

import "errors"

// State is the Subscriber lifecycle state. Deleting is explicit so callers do
// not report a partially failed remote revocation as Deleted.
type State string

const (
	StateActive   State = "active"
	StatePaused   State = "paused"
	StateDeleting State = "deleting"
	StateDeleted  State = "deleted"
)

// Validate accepts only the four defined lifecycle states.
func (s State) Validate() error {
	switch s {
	case StateActive, StatePaused, StateDeleting, StateDeleted:
		return nil
	default:
		return errors.New("SUBSCRIBER_STATE_INVALID: state must be active, paused, deleting or deleted")
	}
}

// Subscriber is a subscription user. DisplayName is a mutable label; ID is
// immutable and is not derived from the name.
type Subscriber struct {
	ID          string
	DisplayName string
	State       State
}

// NewSubscriber normalizes the display name and creates an active Subscriber
// with a new random identity.
func NewSubscriber(displayName string) (Subscriber, error) {
	name, err := NormalizeDisplayName(displayName)
	if err != nil {
		return Subscriber{}, err
	}
	id, err := NewID()
	if err != nil {
		return Subscriber{}, err
	}
	return Subscriber{ID: id, DisplayName: name, State: StateActive}, nil
}

// Validate checks the immutable identity, canonical display name and state.
func (s Subscriber) Validate() error {
	if err := ValidateID(s.ID); err != nil {
		return errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateDisplayName(s.DisplayName); err != nil {
		return err
	}
	return s.State.Validate()
}

// Rename returns a copy with a normalized display name. The subscriber ID and
// lifecycle state are preserved exactly; a failed rename leaves the input
// value untouched.
func (s Subscriber) Rename(displayName string) (Subscriber, error) {
	name, err := NormalizeDisplayName(displayName)
	if err != nil {
		return s, err
	}
	s.DisplayName = name
	return s, nil
}

// Credential is one VLESS identity for one Subscriber on one Line. NodeID
// identifies the existing Line node; UUID is generated independently for
// every credential and never reused for another Line.
type Credential struct {
	ID           string
	SubscriberID string
	NodeID       string
	UUID         string
}

// NewCredential creates a credential with fresh record and VLESS identities.
// The caller must ensure the referenced Subscriber and Line node exist.
func NewCredential(subscriberID, nodeID string) (Credential, error) {
	if err := ValidateID(subscriberID); err != nil {
		return Credential{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateID(nodeID); err != nil {
		return Credential{}, errors.New("NODE_ID_INVALID: need 32 lowercase hex characters")
	}
	id, err := NewID()
	if err != nil {
		return Credential{}, err
	}
	uuid, err := NewUUID()
	if err != nil {
		return Credential{}, err
	}
	return Credential{ID: id, SubscriberID: subscriberID, NodeID: nodeID, UUID: uuid}, nil
}

// Validate checks the record identity and its canonical UUIDv4.
func (c Credential) Validate() error {
	if err := ValidateID(c.ID); err != nil {
		return errors.New("CREDENTIAL_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateID(c.SubscriberID); err != nil {
		return errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateID(c.NodeID); err != nil {
		return errors.New("NODE_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateUUID(c.UUID); err != nil {
		return errors.New("CREDENTIAL_UUID_INVALID: need a canonical lowercase UUIDv4")
	}
	return nil
}
