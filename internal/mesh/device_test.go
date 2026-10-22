package mesh

import (
	"errors"
	"strings"
	"testing"
)

func testDevice(t *testing.T, spec DeviceSpec) MeshDevice {
	t.Helper()
	device, err := NewMeshDevice(spec)
	if err != nil {
		t.Fatalf("NewMeshDevice(%+v): %v", spec, err)
	}
	return device
}

func specFor(purpose Purpose, subscriberID string) DeviceSpec {
	return DeviceSpec{
		DisplayName:  "Living room",
		Purpose:      purpose,
		Platform:     PlatformAndroid,
		NodeName:     "living-room",
		SubscriberID: subscriberID,
	}
}

const testSubscriberID = "0123456789abcdef0123456789abcdef"

func TestNewMeshDeviceDefaultsToSharedHeadscaleUser(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	if device.Status != StatusPending {
		t.Fatalf("new device status = %q, want pending", device.Status)
	}
	if device.HeadscaleUser != DefaultHeadscaleUser {
		t.Fatalf("headscale user = %q, want %q", device.HeadscaleUser, DefaultHeadscaleUser)
	}
	if device.HeadscaleNodeID != 0 {
		t.Fatalf("new device already has a Headscale node id: %d", device.HeadscaleNodeID)
	}
	if err := device.Validate(); err != nil {
		t.Fatalf("new device does not validate: %v", err)
	}
}

func TestNewMeshDeviceNormalizesLabelNameAndUser(t *testing.T) {
	device := testDevice(t, DeviceSpec{
		DisplayName:   "  NAS  ",
		Purpose:       PurposeSubnetRouter,
		Platform:      PlatformNAS,
		NodeName:      "  Home-NAS  ",
		HeadscaleUser: "  MeshMux  ",
	})
	if device.DisplayName != "NAS" {
		t.Fatalf("display name = %q, want trimmed label", device.DisplayName)
	}
	if device.NodeName != "home-nas" {
		t.Fatalf("node name = %q, want canonical lowercase", device.NodeName)
	}
	if device.HeadscaleUser != "meshmux" {
		t.Fatalf("headscale user = %q, want canonical lowercase", device.HeadscaleUser)
	}
	if device.NodeNameKey() != "meshmux/home-nas" {
		t.Fatalf("node name key = %q", device.NodeNameKey())
	}
}

func TestPlatformIsOnlyADisplayHint(t *testing.T) {
	// Purpose, binding and lifecycle must not depend on the platform: the same
	// spec on every platform yields the same status, key and transition results.
	for _, platform := range []Platform{PlatformIOS, PlatformAndroid, PlatformLinux, PlatformNAS, PlatformOther} {
		spec := specFor(PurposeProxyMesh, testSubscriberID)
		spec.Platform = platform
		device := testDevice(t, spec)
		if device.Status != StatusPending {
			t.Fatalf("%s: status = %q, want pending", platform, device.Status)
		}
		registered, err := device.MarkRegistered(41)
		if err != nil {
			t.Fatalf("%s: registration refused: %v", platform, err)
		}
		if registered.Status != StatusRegistered {
			t.Fatalf("%s: registered status = %q", platform, registered.Status)
		}
		if !TransitionAllowed(StatusRegistered, StatusRevoking) {
			t.Fatalf("%s: registration changed the transition table", platform)
		}
	}
	for _, platform := range []Platform{"", "windows", "IOS", "macos", "web"} {
		spec := specFor(PurposeMeshOnly, "")
		spec.Platform = platform
		if _, err := NewMeshDevice(spec); err == nil {
			t.Fatalf("invalid platform accepted: %q", platform)
		}
	}
}

func TestPurposeSubscriberBindingRule(t *testing.T) {
	cases := []struct {
		purpose      Purpose
		subscriberID string
		wantCode     string
	}{
		{PurposeProxyMesh, testSubscriberID, ""},
		{PurposeProxyMesh, "", CodeSubscriberBindingInvalid},
		{PurposeMeshOnly, "", ""},
		{PurposeMeshOnly, testSubscriberID, CodeSubscriberBindingInvalid},
		{PurposeSubnetRouter, "", ""},
		{PurposeSubnetRouter, testSubscriberID, ""},
		{PurposeSubnetRouter, strings.ToUpper(testSubscriberID), CodeSubscriberBindingInvalid},
		{PurposeSubnetRouter, "short", CodeSubscriberBindingInvalid},
		{Purpose(""), testSubscriberID, CodePurposeInvalid},
		{Purpose("proxy"), testSubscriberID, CodePurposeInvalid},
	}
	for _, tc := range cases {
		err := ValidateSubscriberBinding(tc.purpose, tc.subscriberID)
		if tc.wantCode != "" {
			if err == nil {
				t.Fatalf("binding %q/%q accepted, want refusal", tc.purpose, tc.subscriberID)
			}
			assertCode(t, err, tc.wantCode)
			continue
		}
		if err != nil {
			t.Fatalf("binding %q/%q refused: %v", tc.purpose, tc.subscriberID, err)
		}
		// The same rule must hold through the full record constructor.
		if _, err := NewMeshDevice(specFor(tc.purpose, tc.subscriberID)); err != nil {
			t.Fatalf("NewMeshDevice rejected a valid binding: %v", err)
		}
	}
}

func TestMeshOnlyCannotBeBoundToSubscriberAfterCreation(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	device.SubscriberID = testSubscriberID
	if err := device.Validate(); err == nil {
		t.Fatal("mesh_only device with a subscriber accepted")
	} else {
		assertCode(t, err, CodeSubscriberBindingInvalid)
	}
}

func TestStatusTransitionMatrix(t *testing.T) {
	statuses := []Status{
		StatusPending, StatusRegistered, StatusExpired,
		StatusRevoking, StatusRevoked, StatusFailed,
	}
	allowed := map[Status]map[Status]bool{
		StatusPending:    {StatusFailed: true, StatusRevoking: true},
		StatusRegistered: {StatusRevoking: true, StatusExpired: true},
		StatusExpired:    {StatusPending: true, StatusRevoking: true},
		StatusRevoking:   {StatusRevoked: true},
		StatusRevoked:    {},
		StatusFailed:     {StatusRevoking: true},
	}
	for _, from := range statuses {
		for _, to := range statuses {
			want := allowed[from][to]
			if to == from {
				// A repeated status is an idempotent no-op everywhere, including
				// the terminal states.
				want = true
			}
			if got := TransitionAllowed(from, to); got != want {
				t.Fatalf("TransitionAllowed(%q, %q) = %v, want %v", from, to, got, want)
			}
		}
	}
	if TransitionAllowed(Status("unknown"), StatusPending) {
		t.Fatal("an undefined status allowed a transition")
	}
}

func TestTerminalAndFailureStatusesAreNotResurrected(t *testing.T) {
	registered := testDevice(t, specFor(PurposeMeshOnly, ""))
	registered, err := registered.MarkRegistered(7)
	if err != nil {
		t.Fatal(err)
	}

	revoked, _, err := registered.ApplyRevoke(RevokeIntent{DeviceID: registered.ID, Reason: "USER_DELETE"})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err = revoked.Transition(StatusRevoked)
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []Status{StatusPending, StatusRegistered, StatusRevoking, StatusExpired, StatusFailed} {
		if _, err := revoked.Transition(to); err == nil {
			t.Fatalf("revoked device moved to %q", to)
		} else {
			assertCode(t, err, CodeStatusTransitionInvalid)
		}
	}
	// Repeating the terminal status is a no-op, not an error.
	if same, err := revoked.Transition(StatusRevoked); err != nil || same.Status != StatusRevoked {
		t.Fatalf("revoked → revoked = %v, %v", same.Status, err)
	}

	failed, err := registered.Transition(StatusRevoking)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failed.Transition(StatusFailed); err == nil {
		t.Fatal("an unconfirmed revocation was reported as failed")
	}
	if _, err := failed.Transition(StatusPending); err == nil {
		t.Fatal("revoking device returned to pending")
	}
	if _, err := failed.Transition(StatusRegistered); err == nil {
		t.Fatal("revoking device returned to registered")
	}
	if _, err := failed.Transition(StatusExpired); err == nil {
		t.Fatal("revoking device expired")
	}
}

func TestTransitionCannotRegisterWithoutObservedEvidence(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	if _, err := device.Transition(StatusRegistered); err == nil {
		t.Fatal("Transition reached registered without a Headscale node id")
	} else {
		assertCode(t, err, CodeStatusTransitionInvalid)
	}
	if _, err := device.MarkRegistered(0); err == nil {
		t.Fatal("MarkRegistered accepted a zero Headscale node id")
	} else {
		assertCode(t, err, CodeHeadscaleNodeIDInvalid)
	}
	registered, err := device.MarkRegistered(99)
	if err != nil {
		t.Fatal(err)
	}
	if registered.HeadscaleNodeID != 99 {
		t.Fatalf("Headscale node id = %d, want 99", registered.HeadscaleNodeID)
	}
	if _, err := registered.MarkRegistered(100); err == nil {
		t.Fatal("an already registered device was registered again")
	}
}

func TestValidateRejectsNodeIDInconsistentWithStatus(t *testing.T) {
	pending := testDevice(t, specFor(PurposeMeshOnly, ""))
	pending.HeadscaleNodeID = 5
	if err := pending.Validate(); err == nil {
		t.Fatal("pending device with a Headscale node id accepted")
	} else {
		assertCode(t, err, CodeHeadscaleNodeIDInvalid)
	}

	registered := testDevice(t, specFor(PurposeMeshOnly, ""))
	registered.Status = StatusRegistered
	if err := registered.Validate(); err == nil {
		t.Fatal("registered device without a Headscale node id accepted")
	} else {
		assertCode(t, err, CodeHeadscaleNodeIDInvalid)
	}
}

func TestRevokeIntentIsIdempotent(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	intent := RevokeIntent{DeviceID: device.ID, Reason: "USER_DELETE"}

	first, outcome, err := device.ApplyRevoke(intent)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != RevokeRequested || first.Status != StatusRevoking {
		t.Fatalf("first revoke = %q/%q, want revocation_requested/revoking", outcome, first.Status)
	}
	second, outcome, err := first.ApplyRevoke(intent)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != RevokeInProgress || second.Status != StatusRevoking {
		t.Fatalf("second revoke = %q/%q, want revocation_in_progress/revoking", outcome, second.Status)
	}
	// Applying the intent to the same record from the earlier value must not
	// resurrect an older state either.
	if again, _, err := device.ApplyRevoke(intent); err != nil || again.Status != StatusRevoking {
		t.Fatalf("replayed intent = %v, %v", again.Status, err)
	}

	revoked, err := second.Transition(StatusRevoked)
	if err != nil {
		t.Fatal(err)
	}
	third, outcome, err := revoked.ApplyRevoke(intent)
	if err != nil {
		t.Fatalf("revoke after revocation failed: %v", err)
	}
	if outcome != RevokeAlreadyRevoked || third.Status != StatusRevoked {
		t.Fatalf("post-revocation intent = %q/%q", outcome, third.Status)
	}
}

func TestRevokeFromEveryNonTerminalStatus(t *testing.T) {
	base := testDevice(t, specFor(PurposeMeshOnly, ""))
	registered, err := base.MarkRegistered(11)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := base.Transition(StatusFailed)
	if err != nil {
		t.Fatal(err)
	}
	expiredDevice := testDevice(t, specFor(PurposeMeshOnly, ""))
	expiredDevice, err = expiredDevice.MarkRegistered(12)
	if err != nil {
		t.Fatal(err)
	}
	expiredDevice, err = expiredDevice.Transition(StatusExpired)
	if err != nil {
		t.Fatal(err)
	}
	intent := RevokeIntent{Reason: "ENROLLMENT_FAILED"}
	for _, device := range []MeshDevice{base, registered, failed, expiredDevice} {
		intent.DeviceID = device.ID
		next, outcome, err := device.ApplyRevoke(intent)
		if err != nil {
			t.Fatalf("%q: revoke refused: %v", device.Status, err)
		}
		if outcome != RevokeRequested || next.Status != StatusRevoking {
			t.Fatalf("%q: revoke = %q/%q", device.Status, outcome, next.Status)
		}
	}
}

func TestRevokeIntentGuards(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	if _, _, err := device.ApplyRevoke(RevokeIntent{DeviceID: strings.Repeat("a", 32), Reason: "USER_DELETE"}); err == nil {
		t.Fatal("revoke intent for another device accepted")
	} else {
		assertCode(t, err, CodeRevokeDeviceMismatch)
	}
	if _, _, err := device.ApplyRevoke(RevokeIntent{Reason: "USER_DELETE"}); err == nil {
		t.Fatal("revoke intent without a device id accepted")
	}
	for _, reason := range []string{"", "user_delete", "USER DELETE", "USER-DELETE", "USER_DELETE\n", "A"} {
		if _, _, err := device.ApplyRevoke(RevokeIntent{DeviceID: device.ID, Reason: reason}); err == nil {
			t.Fatalf("invalid revoke reason accepted: %q", reason)
		}
	}
	if device.Status != StatusPending {
		t.Fatalf("a refused intent changed the status to %q", device.Status)
	}
}

func TestNodeNameUniquenessWhileOccupied(t *testing.T) {
	first := testDevice(t, specFor(PurposeMeshOnly, ""))
	second := testDevice(t, specFor(PurposeMeshOnly, ""))
	if first.ID == second.ID {
		t.Fatal("two devices share an id")
	}
	duplicate := second
	duplicate.NodeName = first.NodeName
	if err := ValidateNodeNameUniqueness([]MeshDevice{first, duplicate}); err == nil {
		t.Fatal("duplicate node name accepted while both are pending")
	} else {
		assertCode(t, err, CodeNodeNameDuplicate)
	}

	// A different Headscale user is a different namespace.
	otherUser := duplicate
	otherUser.HeadscaleUser = "second"
	if err := ValidateNodeNameUniqueness([]MeshDevice{first, otherUser}); err != nil {
		t.Fatalf("same name in another user refused: %v", err)
	}

	// Once the name is released the same name may be reused.
	registered, err := first.MarkRegistered(3)
	if err != nil {
		t.Fatal(err)
	}
	revoking, _, err := registered.ApplyRevoke(RevokeIntent{DeviceID: registered.ID, Reason: "USER_DELETE"})
	if err != nil {
		t.Fatal(err)
	}
	if !revoking.Status.OccupiesNodeName() {
		t.Fatal("revoking must keep the name reserved until revocation is confirmed")
	}
	if err := ValidateNodeNameUniqueness([]MeshDevice{revoking, duplicate}); err == nil {
		t.Fatal("duplicate name accepted while revocation is pending")
	}
	revoked, err := revoking.Transition(StatusRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateNodeNameUniqueness([]MeshDevice{revoked, duplicate}); err != nil {
		t.Fatalf("released name still refused: %v", err)
	}

	// expired and failed release the name as well.
	expired := testDevice(t, specFor(PurposeMeshOnly, ""))
	expired, err = expired.MarkRegistered(24)
	if err != nil {
		t.Fatal(err)
	}
	expired, err = expired.Transition(StatusExpired)
	if err != nil {
		t.Fatal(err)
	}
	failed := testDevice(t, specFor(PurposeMeshOnly, ""))
	failed, err = failed.Transition(StatusFailed)
	if err != nil {
		t.Fatal(err)
	}
	for _, released := range []MeshDevice{expired, failed} {
		candidate := testDevice(t, specFor(PurposeMeshOnly, ""))
		candidate.NodeName = released.NodeName
		if err := ValidateNodeNameUniqueness([]MeshDevice{released, candidate}); err != nil {
			t.Fatalf("%q did not release the node name: %v", released.Status, err)
		}
	}
}

func TestNodeNameUniquenessRejectsDuplicateIDs(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	if err := ValidateNodeNameUniqueness([]MeshDevice{device, device}); err == nil {
		t.Fatal("duplicate device ids accepted")
	} else {
		assertCode(t, err, CodeDeviceDuplicateID)
	}
}

func TestNodeNameCanonicalShape(t *testing.T) {
	for _, name := range []string{"a", "nas-01", "a" + strings.Repeat("b", 62), "0abc"} {
		if err := ValidateNodeName(name); err != nil {
			t.Fatalf("valid node name rejected: %q: %v", name, err)
		}
	}
	for _, name := range []string{
		"",
		strings.Repeat("a", 64),
		"MeshMux",
		"nas_01",
		"nas.01",
		"-nas",
		"nas-",
		"nas 01",
		"nas/01",
		"NAS",
	} {
		if err := ValidateNodeName(name); err == nil {
			t.Fatalf("invalid node name accepted: %q", name)
		} else {
			assertCode(t, err, CodeNodeNameInvalid)
		}
	}
	if _, err := NormalizeNodeName("  Node-01  "); err != nil {
		t.Fatalf("normalization refused a trimmable name: %v", err)
	}
}

func TestHeadscaleUserSnapshotShape(t *testing.T) {
	for _, user := range []string{DefaultHeadscaleUser, "team.a", "a_b-c", "a"} {
		if err := ValidateHeadscaleUser(user); err != nil {
			t.Fatalf("valid user rejected: %q: %v", user, err)
		}
	}
	for _, user := range []string{"", "MeshMux", "_team", "team.", "team/a", "team a", strings.Repeat("a", 64)} {
		if err := ValidateHeadscaleUser(user); err == nil {
			t.Fatalf("invalid user accepted: %q", user)
		} else {
			assertCode(t, err, CodeHeadscaleUserInvalid)
		}
	}
}

func TestInvalidDeviceStatusAndIdentity(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	device.Status = Status("active")
	if err := device.Validate(); err == nil {
		t.Fatal("undefined status accepted")
	} else {
		assertCode(t, err, CodeStatusInvalid)
	}
	device = testDevice(t, specFor(PurposeMeshOnly, ""))
	device.ID = strings.ToUpper(device.ID)
	if err := device.Validate(); err == nil {
		t.Fatal("non-canonical device id accepted")
	} else {
		assertCode(t, err, CodeDeviceIDInvalid)
	}
	device = testDevice(t, specFor(PurposeMeshOnly, ""))
	device.Purpose = Purpose("gateway")
	if err := device.Validate(); err == nil {
		t.Fatal("undefined purpose accepted")
	} else {
		assertCode(t, err, CodePurposeInvalid)
	}
}

func TestDisplayNameFailureUsesMeshCode(t *testing.T) {
	spec := specFor(PurposeMeshOnly, "")
	spec.DisplayName = "bad\nname"
	if _, err := NewMeshDevice(spec); err == nil {
		t.Fatal("control character in display name accepted")
	} else {
		assertCode(t, err, CodeDisplayNameInvalid)
	}
}

func TestReenrollmentFromExpired(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	registered, err := device.MarkRegistered(21)
	if err != nil {
		t.Fatal(err)
	}
	lost, err := registered.Transition(StatusExpired)
	if err != nil {
		t.Fatal(err)
	}
	// A registered device that disappears keeps its last observed id while
	// expired, so the operator can see which node vanished.
	if lost.HeadscaleNodeID != 21 {
		t.Fatalf("expired device dropped its last observed node id: %d", lost.HeadscaleNodeID)
	}
	if err := lost.Validate(); err != nil {
		t.Fatalf("expired device with a last observed id does not validate: %v", err)
	}

	// Registration is not reachable from expired: one attempt maps to one
	// registration, so re-enrollment goes through pending first.
	if _, err := lost.MarkRegistered(22); err == nil {
		t.Fatal("an expired device registered without re-enrolling")
	}
	if _, err := lost.Transition(StatusRegistered); err == nil {
		t.Fatal("Transition reached registered from expired")
	}

	// Re-enrollment starts a fresh pending attempt with no bound node.
	pending, err := lost.Transition(StatusPending)
	if err != nil {
		t.Fatalf("re-enrollment refused: %v", err)
	}
	if pending.HeadscaleNodeID != 0 {
		t.Fatalf("re-enrollment kept the old node id: %d", pending.HeadscaleNodeID)
	}
	if err := pending.Validate(); err != nil {
		t.Fatalf("re-enrolled device does not validate: %v", err)
	}
	again, err := pending.MarkRegistered(23)
	if err != nil {
		t.Fatalf("re-enrolled device could not register: %v", err)
	}
	if again.HeadscaleNodeID != 23 {
		t.Fatalf("re-enrolled node id = %d, want 23", again.HeadscaleNodeID)
	}
}

func TestPendingFailureIsSettled(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	failed, err := device.Transition(StatusFailed)
	if err != nil {
		t.Fatalf("pending → failed refused: %v", err)
	}
	if _, err := failed.Transition(StatusPending); err == nil {
		t.Fatal("failed device returned to pending")
	}
	revoking, err := failed.Transition(StatusRevoking)
	if err != nil {
		t.Fatalf("failed → revoking refused: %v", err)
	}
	if revoking.Status != StatusRevoking {
		t.Fatalf("status = %q, want revoking", revoking.Status)
	}
}

func TestFailedDeviceCannotRegister(t *testing.T) {
	device := testDevice(t, specFor(PurposeMeshOnly, ""))
	failed, err := device.Transition(StatusFailed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failed.MarkRegistered(5); err == nil {
		t.Fatal("a failed device was registered")
	} else {
		assertCode(t, err, CodeStatusTransitionInvalid)
	}
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	var domainErr *DomainError
	if !errors.As(err, &domainErr) {
		t.Fatalf("error %v is not a *DomainError", err)
	}
	if domainErr.Code != code {
		t.Fatalf("error code = %q, want %q", domainErr.Code, code)
	}
	if strings.TrimSpace(domainErr.Error()) == "" {
		t.Fatal("empty domain error message")
	}
}
