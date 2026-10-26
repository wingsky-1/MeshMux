package subscription

import (
	"strings"
	"testing"
)

func TestSubscriberRenamePreservesIdentityAndState(t *testing.T) {
	subscriber, err := NewSubscriber("  Alice  ")
	if err != nil {
		t.Fatal(err)
	}
	if subscriber.DisplayName != "Alice" || subscriber.State != StateActive {
		t.Fatalf("unexpected new subscriber: %+v", subscriber)
	}
	subscriber.State = StatePaused

	renamed, err := subscriber.Rename("  Alice Chen  ")
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != subscriber.ID || renamed.State != StatePaused {
		t.Fatalf("rename changed identity or state: %+v", renamed)
	}
	if renamed.DisplayName != "Alice Chen" {
		t.Fatalf("rename did not normalize display name: %q", renamed.DisplayName)
	}
	if err = renamed.Validate(); err != nil {
		t.Fatal(err)
	}
	if subscriber.DisplayName != "Alice" {
		t.Fatal("rename mutated the original value")
	}
}

func TestDisplayNameBoundariesAndControls(t *testing.T) {
	for _, name := range []string{
		"a",
		strings.Repeat("界", 80),
		"line 01",
	} {
		if _, err := NormalizeDisplayName(name); err != nil {
			t.Fatalf("valid display name rejected: %q: %v", name, err)
		}
	}
	for _, name := range []string{
		"",
		"   ",
		strings.Repeat("界", 81),
		"bad\nname",
		"bad\tname",
		"bad\x00name",
		"bad\x7fname",
		"bad\u202ename",
		"bad\u200bname",
	} {
		if _, err := NormalizeDisplayName(name); err == nil {
			t.Fatalf("invalid display name accepted: %q", name)
		}
	}
	if err := ValidateDisplayName(" Alice"); err == nil {
		t.Fatal("untrimmed display name accepted by ValidateDisplayName")
	}
	if _, err := NormalizeDisplayName(" \n Alice \t "); err != nil {
		t.Fatalf("normalization did not trim whitespace: %v", err)
	}
}

func TestSubscriberValidationAndStates(t *testing.T) {
	subscriber, err := NewSubscriber("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []State{StateActive, StatePaused, StateDeleting, StateDeleted} {
		value := subscriber
		value.State = state
		if err = value.Validate(); err != nil {
			t.Fatalf("valid state rejected: %q: %v", state, err)
		}
	}
	for _, state := range []State{"", "ACTIVE", "active ", "removed"} {
		if err := state.Validate(); err == nil {
			t.Fatalf("invalid state accepted: %q", state)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Subscriber)
	}{
		{"bad id", func(s *Subscriber) { s.ID = "short" }},
		{"uppercase id", func(s *Subscriber) { s.ID = strings.ToUpper(s.ID) }},
		{"empty name", func(s *Subscriber) { s.DisplayName = "" }},
		{"untrimmed name", func(s *Subscriber) { s.DisplayName = " alice" }},
		{"bad state", func(s *Subscriber) { s.State = "removed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := subscriber
			tc.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid subscriber accepted")
			}
		})
	}
}

func TestCredentialUUIDIsIndependentPerLine(t *testing.T) {
	subscriber, err := NewSubscriber("alice")
	if err != nil {
		t.Fatal(err)
	}
	lineA := strings.Repeat("a", 32)
	lineB := strings.Repeat("b", 32)
	first, err := NewCredential(subscriber.ID, lineA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCredential(subscriber.ID, lineB)
	if err != nil {
		t.Fatal(err)
	}
	third, err := NewCredential(subscriber.ID, lineA)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.ID == third.ID || second.ID == third.ID {
		t.Fatal("credential record IDs were reused")
	}
	if first.UUID == second.UUID || first.UUID == third.UUID || second.UUID == third.UUID {
		t.Fatal("VLESS UUIDs were reused across credentials or Lines")
	}
	if first.SubscriberID != subscriber.ID || second.NodeID != lineB || third.NodeID != lineA {
		t.Fatal("credential bindings were not preserved")
	}
	for _, credential := range []Credential{first, second, third} {
		if err := credential.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := ValidateUUID(credential.UUID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCredentialValidationRejectsBadBindings(t *testing.T) {
	subscriber, err := NewSubscriber("alice")
	if err != nil {
		t.Fatal(err)
	}
	valid, err := NewCredential(subscriber.ID, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Credential)
	}{
		{"bad id", func(c *Credential) { c.ID = "" }},
		{"bad subscriber", func(c *Credential) { c.SubscriberID = "short" }},
		{"bad node", func(c *Credential) { c.NodeID = strings.ToUpper(c.NodeID) }},
		{"bad uuid", func(c *Credential) { c.UUID = strings.ToUpper(c.UUID) }},
		{"uuid v1", func(c *Credential) { c.UUID = c.UUID[:14] + "1" + c.UUID[15:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			tc.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
	if _, err := NewCredential("short", valid.NodeID); err == nil {
		t.Fatal("NewCredential accepted a malformed subscriber ID")
	}
	if _, err := NewCredential(valid.SubscriberID, "short"); err == nil {
		t.Fatal("NewCredential accepted a malformed node ID")
	}
}
