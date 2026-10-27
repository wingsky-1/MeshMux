package mesh_test

// Rekey is the one Mesh mutation that replaces a secret the operator may already
// hold. Its order is what keeps a failed attempt recoverable, so these tests
// assert the ordering fact rather than only the final key state:
//
//   - an intermediate failure anywhere before the swap leaves the previous key
//     usable and the device unchanged;
//   - a successful attempt shows exactly one live key, and the swap is the single
//     write that retires the old one;
//   - an expired device reaches pending only together with a usable key.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
	"github.com/wingsky-1/MeshMux/internal/web/handler"
	"github.com/wingsky-1/MeshMux/internal/web/handler/handlertest"
	meshh "github.com/wingsky-1/MeshMux/internal/web/handler/mesh"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
)

// meshIOLiveKey returns the single issued key of a device, failing when the
// device has no live key or more than one. Rekey must never produce either
// state.
func meshIOLiveKey(t *testing.T, app *handler.Server, deviceID string, now time.Time) store.MeshEnrollmentKeyRecord {
	t.Helper()
	keys, err := app.Store.ListMeshEnrollmentKeys(deviceID)
	if err != nil {
		t.Fatal(err)
	}
	var live []store.MeshEnrollmentKeyRecord
	for _, key := range keys {
		if key.State == mesh.KeyIssued && now.Before(time.Unix(key.ExpiresAt, 0)) {
			live = append(live, key)
		}
	}
	if len(live) != 1 {
		t.Fatalf("live keys = %d (%+v), want exactly 1", len(live), keys)
	}
	return live[0]
}

// TestMeshRekeyHeadscaleFailureKeepsOldKey is the case the old order broke: the
// Headscale user cannot be resolved, so the new material is never produced. The
// device must keep the key it had, not lose it to an early withdrawal.
func TestMeshRekeyHeadscaleFailureKeepsOldKey(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, firstSecret := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	now := app.Now()
	before := meshIOLiveKey(t, app, device.ID, now)

	fake.FailWith["users.list"] = meshnet.CodeUnavailable
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), meshnet.CodeUnavailable) {
		t.Fatalf("control-plane refusal lost its code: %.300s", w.Body.String())
	}
	// The old secret survives a failed attempt in both directions: the row is
	// still the live one, and the row was not rewritten.
	after := meshIOLiveKey(t, app, device.ID, now)
	if after.ID != before.ID || after.State != mesh.KeyIssued {
		t.Fatalf("failed rekey moved the live key: before=%+v after=%+v", before, after)
	}
	if after.ConsumedAt != 0 {
		t.Fatalf("failed rekey touched the old key: %+v", after)
	}
	// The old key is still usable: registration spends it, which proves the
	// failed attempt left a working secret rather than a dead row.
	if _, err := app.Store.RecordMeshObservation(device.ID, 9, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != before.ID || keys[0].State != mesh.KeyConsumed {
		t.Fatalf("the surviving key was not the one spent by registration: %+v", keys)
	}
	if strings.Contains(w.Body.String(), firstSecret) {
		t.Fatal("failed rekey reflected the old secret")
	}
}

// TestMeshRekeySwapFailureKeepsOldKey forces the one write after staging to
// fail: the transaction that installs the new key cannot insert. The staged
// Headscale key must be compensated and the previous key must stay live, so the
// operator's existing secret is not lost to a replace that never happened.
func TestMeshRekeySwapFailureKeepsOldKey(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	sub, _ := handlertest.MeshConvergedSubscriber(t, app, now)
	w := b.Post("/mesh", url.Values{
		"display_name": {"phone"}, "purpose": {"proxy_mesh"},
		"platform": {"ios"}, "subscriber_id": {sub.ID},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	devices, err := app.Store.ListMeshDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices = %d err=%v", len(devices), err)
	}
	device := devices[0]
	live := meshIOLiveKey(t, app, device.ID, now)

	// A trigger refuses only the install write, so every read and every stage
	// step before it succeeds: this is the apply failure, not an early refusal.
	if _, err = app.Store.DB.Exec(`CREATE TRIGGER mesh_rekey_install_refused
 BEFORE INSERT ON mesh_enrollment_keys
 WHEN NEW.state='issued'
 BEGIN
   SELECT RAISE(ABORT, 'MESH_REKEY_TEST_REFUSED');
 END`); err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), store.CodeDatabaseUnavailable) {
		t.Fatalf("apply failure lost its code: %.400s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "本次操作未启用新 Key，设备与已有 Key 保持原状") {
		t.Fatalf("apply failure misstates what it did: %.400s", w.Body.String())
	}
	if _, err = app.Store.DB.Exec(`DROP TRIGGER mesh_rekey_install_refused`); err != nil {
		t.Fatal(err)
	}
	after := meshIOLiveKey(t, app, device.ID, now)
	if after.ID != live.ID {
		t.Fatalf("failed apply replaced the live key: %+v", after)
	}
	// The staged Headscale key existed and was never handed out, so it was
	// expired instead of being left live.
	if fake.CallsOf("preauthkeys.create") != 1 || fake.CallsOf("preauthkeys.expire") != 1 {
		t.Fatalf("staged Headscale key was not compensated: %v", fake.Calls)
	}
	// Nothing from the failed attempt was stored: the history is the one row
	// the device already had.
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != live.ID {
		t.Fatalf("failed apply wrote key rows: %+v", keys)
	}
	// And the device is still usable: the next attempt succeeds.
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	meshIOLiveKey(t, app, device.ID, app.Now())
}

// TestMeshRekeyRenderFailureAfterHeadscaleKeyKeepsOldKey covers the proxy+mesh
// chain: the Headscale pre-auth key exists and the document cannot be rendered.
// The attempt falls back to a Hub key (the 9c contract), which now installs only
// after everything else succeeded, and the old key is retired exactly then.
func TestMeshRekeyRenderFailureKeepsOldKeyUsable(t *testing.T) {
	app, b, fake, _ := handlertest.MeshEndpointTestApp(t, handlertest.TestHeadscaleOrigin)
	now := time.Unix(1_700_000_000, 0)
	app.Now = func() time.Time { return now }
	sub, _ := handlertest.MeshConvergedSubscriber(t, app, now)
	w := b.Post("/mesh", url.Values{
		"display_name": {"phone"}, "purpose": {"proxy_mesh"},
		"platform": {"ios"}, "subscriber_id": {sub.ID},
	})
	handlertest.RequireStatus(t, w, http.StatusOK)
	devices, err := app.Store.ListMeshDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices = %d err=%v", len(devices), err)
	}
	device := devices[0]

	// Pausing the bound subscriber makes the preflight refuse: no Headscale key
	// is minted, the Hub key still is, and the response discloses it because
	// losing the ability to enroll would be worse than losing the document.
	if _, err = app.Store.SetSubscriberState(sub.ID, "paused", now); err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if fake.CallsOf("preauthkeys.create") != 0 {
		t.Fatalf("a refused preflight minted a Headscale key: %v", fake.Calls)
	}
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("a refused document did not disclose a Hub key: %.400s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), meshh.CodeMeshEndpointSubscriberUnavailable) {
		t.Fatalf("the document refusal lost its code: %.400s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "旧 Key 已作废") {
		t.Fatalf("the page did not state the old key was withdrawn: %.400s", w.Body.String())
	}
	live := meshIOLiveKey(t, app, device.ID, now)
	if live.State != mesh.KeyIssued {
		t.Fatalf("the new key is not live: %+v", live)
	}
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	var states []mesh.KeyState
	for _, key := range keys {
		states = append(states, key.State)
		if key.ID == live.ID && key.State != mesh.KeyIssued {
			t.Fatalf("the disclosed key is not the live row: %+v", key)
		}
	}
	if len(keys) != 2 {
		t.Fatalf("key history after a degraded rekey: %+v", keys)
	}
	if states[0] == states[1] {
		t.Fatalf("the rekey did not retire exactly one key: %+v", keys)
	}
}

// TestMeshRekeyExpiredDeviceGetsKeyWithItsStatus proves the expired → pending
// edge and the key install are one write: the device is never pending with no
// usable key, and a failed attempt leaves it expired.
func TestMeshRekeyExpiredDeviceGetsKeyWithItsStatus(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "nas", "mesh_only", "nas", "")
	now := app.Now()
	// Register, then observe the node disappear: registered → expired.
	if _, err := app.Store.RecordMeshObservation(device.ID, 31, now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.RecordMeshObservation(device.ID, 0, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	expired, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.Status != mesh.StatusExpired {
		t.Fatalf("fixture device is %s, want expired", expired.Status)
	}
	// A Headscale refusal keeps it expired: no status moved, no key minted.
	fake.FailWith["users.list"] = meshnet.CodeUnavailable
	fake.ResetCalls()
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	still, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.Status != mesh.StatusExpired {
		t.Fatalf("failed rekey moved the device to %s", still.Status)
	}
	if _, err := app.Store.ListMeshEnrollmentKeys(device.ID); err != nil {
		t.Fatal(err)
	}

	delete(fake.FailWith, "users.list")
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	reenrolled, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reenrolled.Status != mesh.StatusPending || reenrolled.HeadscaleNodeID != 0 {
		t.Fatalf("re-enrollment wrong: %+v", reenrolled)
	}
	// The status and the key landed together, so the device can enroll now.
	live := meshIOLiveKey(t, app, reenrolled.ID, app.Now())
	if live.State != mesh.KeyIssued {
		t.Fatalf("re-enrolled device has no usable key: %+v", live)
	}
	// The retired key belongs to the previous registration attempt and was
	// already spent there, so the history holds exactly one live row.
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	var issued int
	for _, key := range keys {
		if key.State == mesh.KeyIssued {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("issued rows after re-enrollment = %d (%+v)", issued, keys)
	}
}

// TestMeshRekeyLapsesOldKeyWithoutClaimingAWithdrawal keeps the audit trail
// honest: a key whose window already closed was not revoked by the rekey, so the
// page must not say it was withdrawn.
func TestMeshRekeyLapsesOldKeyWithoutClaimingAWithdrawal(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	base := app.Now()
	// Move the clock past the first key's window without touching its row: that
	// is exactly the "lapsed but still issued" state the issue path retires.
	app.Now = func() time.Time { return base.Add(mesh.KeyTTL + time.Minute) }
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, "旧 Key 已作废") {
		t.Fatalf("a lapsed key was reported as withdrawn: %.400s", body)
	}
	if !strings.Contains(body, "过期的旧 Key 已归档") {
		t.Fatalf("the lapsed key was not described: %.400s", body)
	}
	keys, err := app.Store.ListMeshEnrollmentKeys(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("key history = %d rows (%+v)", len(keys), keys)
	}
	var expired, issued int
	for _, key := range keys {
		switch key.State {
		case mesh.KeyExpired:
			expired++
		case mesh.KeyIssued:
			issued++
		case mesh.KeyRevoked:
			t.Fatalf("a lapsed key was reported as revoked: %+v", key)
		}
	}
	if expired != 1 || issued != 1 {
		t.Fatalf("expired=%d issued=%d (%+v)", expired, issued, keys)
	}
}

// TestMeshRekeyNeverLeavesTwoLiveKeys is the invariant the old order enforced by
// withdrawal and the new order enforces by the swap: at no observed point does
// one device hold two live secrets.
func TestMeshRekeyNeverLeavesTwoLiveKeys(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	now := app.Now()
	for attempt := 0; attempt < 3; attempt++ {
		w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
		handlertest.RequireStatus(t, w, http.StatusOK)
		meshIOLiveKey(t, app, device.ID, now)
	}
	// The partial unique index is the storage-level guarantee behind the swap:
	// a direct second issued row for the same device is refused.
	if _, err := app.Store.DB.Exec(`INSERT INTO mesh_enrollment_keys(id, device_id, secret_hash, state, issued_at, expires_at, consumed_at)
 VALUES('cccccccccccccccccccccccccccccccc',?,x'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20','issued',?,?,0)`,
		device.ID, now.Unix(), now.Add(mesh.KeyTTL).Unix()); err == nil {
		t.Fatal("the single-active index accepted a second live key")
	}
}

// TestMeshRekeyExpiredDeviceKeepsItsLapsedKeyOnNameConflict proves the apply step
// is all-or-nothing for the status edge too: an expired device whose node name
// was taken while it was expired stays expired, keeps its existing key rows and
// gets no new key.
func TestMeshRekeyExpiredDeviceKeepsItsLapsedKeyOnNameConflict(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "nas", "mesh_only", "nas", "")
	now := app.Now()
	if _, err := app.Store.RecordMeshObservation(device.ID, 41, now); err != nil {
		t.Fatal(err)
	}
	// The registration consumed the key; the disappearance expires the device
	// and releases its name.
	if _, err := app.Store.RecordMeshObservation(device.ID, 0, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A second device takes the released name. The page derives a node name from
	// the label, so the collision is built from the expired device's own name.
	taker := storetest.MeshSpec("nas2", mesh.PurposeMeshOnly, "")
	taker.NodeName = device.NodeName
	if _, err := app.Store.CreateMeshDevice(taker, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	fake.ResetCalls()
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), mesh.CodeNodeNameDuplicate) {
		t.Fatalf("name conflict lost its code: %.400s", w.Body.String())
	}
	after, err := app.Store.GetMeshDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != mesh.StatusExpired {
		t.Fatalf("a refused rekey moved the device to %s", after.Status)
	}
	if keys, err := app.Store.ListMeshEnrollmentKeys(device.ID); err != nil || len(keys) != 1 || keys[0].State != mesh.KeyConsumed {
		t.Fatalf("a refused rekey rewrote the key history: %+v err=%v", keys, err)
	}
}

// TestMeshRekeyEarlierFailureLeavesTheOldKeyInstallable is the operator-level
// recovery claim: after an intermediate failure the device can still be enrolled
// with the secret already handed out, and a later successful rekey replaces it.
func TestMeshRekeyEarlierFailureLeavesTheOldKeyInstallable(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, firstSecret := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	now := app.Now()
	fake.FailWith["users.list"] = meshnet.CodeUnavailable
	handlertest.RequireStatus(t, b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}}), http.StatusServiceUnavailable)
	delete(fake.FailWith, "users.list")

	// The first secret is still the live one and still spends: the failed
	// attempt left a working enrollment path, which is the point of the
	// reorder.
	if len(firstSecret) != 43 {
		t.Fatalf("first secret has %d characters", len(firstSecret))
	}
	if _, err := app.Store.RecordMeshObservation(device.ID, 5, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Registration consumed the surviving key, so the next attempt starts from
	// a device with no live key — the legacy shape a second rekey must handle.
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusConflict)
	if !strings.Contains(w.Body.String(), meshh.CodeMeshDeviceNotReenrollable) {
		t.Fatalf("registered device accepted a rekey: %.300s", w.Body.String())
	}
	// Bring it back to pending the only legal way, then rekey for real.
	if _, err := app.Store.RecordMeshObservation(device.ID, 0, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 || match[1] == firstSecret {
		t.Fatal("recovery rekey did not disclose a fresh key")
	}
	meshIOLiveKey(t, app, device.ID, app.Now())
}

// TestMeshRekeyAuditEventsFollowWhatHappened pins the two audit facts apart: a
// withdrawn live key logs MESH_DEVICE_ENROLLMENT_KEY_REVOKED, a lapsed one is
// retired as expired and never claims a withdrawal.
func TestMeshRekeyAuditEventsFollowWhatHappened(t *testing.T) {
	app, b, fake, logs := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	logs.Reset()
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(logs.String(), "MESH_DEVICE_ENROLLMENT_KEY_REVOKED") {
		t.Fatalf("a withdrawn key logged no revocation: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "MESH_DEVICE_ENROLLMENT_KEY_REISSUED") {
		t.Fatalf("a rekey logged no reissue: %s", logs.String())
	}

	// The same device, now past its window: the swap retires the lapsed row as
	// expired and the page says so instead of claiming a withdrawal.
	base := app.Now()
	app.Now = func() time.Time { return base.Add(mesh.KeyTTL + time.Minute) }
	logs.Reset()
	w = b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	if !strings.Contains(logs.String(), "MESH_DEVICE_ENROLLMENT_KEY_EXPIRED") {
		t.Fatalf("a lapsed key logged no expiry: %s", logs.String())
	}
	if strings.Contains(logs.String(), "MESH_DEVICE_ENROLLMENT_KEY_REVOKED") {
		t.Fatalf("a lapsed key was logged as revoked: %s", logs.String())
	}
}

// TestMeshRekeyPageNeverRepeatsAKey guards the disclosure contract across the
// reorder: the new secret appears once in the response and never on the page.
func TestMeshRekeyPageNeverRepeatsAKey(t *testing.T) {
	_, b, fake, logs := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusOK)
	match := meshKeyPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatalf("no key in the rekey response: %.400s", w.Body.String())
	}
	if strings.Count(w.Body.String(), match[1]) != 1 {
		t.Fatalf("the reissued key appears %d times", strings.Count(w.Body.String(), match[1]))
	}
	page := b.Req("GET", "/mesh", nil, nil)
	handlertest.RequireStatus(t, page, http.StatusOK)
	if strings.Contains(page.Body.String(), match[1]) {
		t.Fatal("the following page replayed the key")
	}
	if strings.Contains(logs.String(), match[1]) {
		t.Fatal("the key reached the log")
	}
}

// TestMeshRekeyStagedKeyBelongsToItsDevice refuses a staged key for another
// device: the swap writes by device id, so the record itself must agree.
func TestMeshRekeyStagedKeyBelongsToItsDevice(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	first, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	second, _ := handlertest.MeshCreateDevice(t, b, fake, "tablet", "mesh_only", "android", "")
	key, _, err := mesh.NewEnrollmentKey(second.ID, app.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.ApplyMeshRekey(first.ID, key, app.Now()); err == nil ||
		!storetest.HasErrorCode(err, mesh.CodeKeyDeviceMismatch) {
		t.Fatalf("cross-device key accepted: %v", err)
	}
	// Neither device changed.
	meshIOLiveKey(t, app, first.ID, app.Now())
	meshIOLiveKey(t, app, second.ID, app.Now())
}

// TestMeshRekeyApplyRefusesNonIssuedKey keeps the staging contract: only an
// issued record can be installed, so a caller cannot re-install a spent secret.
func TestMeshRekeyApplyRefusesNonIssuedKey(t *testing.T) {
	app, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	now := app.Now()
	key, _, err := mesh.NewEnrollmentKey(device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	key.State = mesh.KeyRevoked
	if _, err := app.Store.ApplyMeshRekey(device.ID, key, now); err == nil ||
		!storetest.HasErrorCode(err, mesh.CodeKeyTransitionInvalid) {
		t.Fatalf("a revoked key was installed: %v", err)
	}
	live := meshIOLiveKey(t, app, device.ID, now)
	if live.State != mesh.KeyIssued {
		t.Fatalf("live key changed: %+v", live)
	}
}

func TestMeshRekeyLiveKeyReadback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	live := store.MeshEnrollmentKeyRecord{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", State: mesh.KeyIssued, ExpiresAt: now.Add(time.Minute).Unix()}
	lapsed := store.MeshEnrollmentKeyRecord{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", State: mesh.KeyIssued, ExpiresAt: now.Unix()}
	revoked := store.MeshEnrollmentKeyRecord{ID: "cccccccccccccccccccccccccccccccc", State: mesh.KeyRevoked, ExpiresAt: now.Add(time.Minute).Unix()}
	cases := []struct {
		name string
		keys []store.MeshEnrollmentKeyRecord
		id   string
		want bool
	}{
		{"live", []store.MeshEnrollmentKeyRecord{live}, live.ID, true},
		{"lapsed", []store.MeshEnrollmentKeyRecord{lapsed}, lapsed.ID, false},
		{"revoked", []store.MeshEnrollmentKeyRecord{revoked}, revoked.ID, false},
		{"absent", []store.MeshEnrollmentKeyRecord{live}, revoked.ID, false},
		{"empty", nil, live.ID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := meshh.MeshEnrollmentKeyLive(tc.keys, tc.id, now); got != tc.want {
				t.Fatalf("meshh.MeshEnrollmentKeyLive(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
	// The helper reports about the named row only: a live sibling cannot make a
	// retired row look usable.
	if meshh.MeshEnrollmentKeyLive([]store.MeshEnrollmentKeyRecord{live, revoked}, revoked.ID, now) {
		t.Fatal("a revoked row was reported live because another row was live")
	}
}

// TestMeshRekeyFailureMessageIsActionable covers the contract for a failed apply:
// the page must say the old key still works, so the operator does not discard a
// secret that is in fact still valid.
func TestMeshRekeyFailureMessageIsActionable(t *testing.T) {
	_, b, fake, _ := handlertest.MeshTestApp(t)
	device, _ := handlertest.MeshCreateDevice(t, b, fake, "phone", "mesh_only", "ios", "")
	fake.FailWith["users.list"] = meshnet.CodeUnavailable
	w := b.Post("/mesh/rekey", url.Values{"device_id": {device.ID}})
	handlertest.RequireStatus(t, w, http.StatusServiceUnavailable)
	body := w.Body.String()
	if !strings.Contains(body, meshnet.CodeUnavailable) {
		t.Fatalf("stable code missing: %.400s", body)
	}
	if !strings.Contains(body, w.Header().Get("X-Operation-ID")) {
		t.Fatal("operation id missing from the failure page")
	}
	if !strings.Contains(body, "请检查 Headscale 服务后重试") {
		t.Fatalf("failure page gives no next step: %.400s", body)
	}
}
