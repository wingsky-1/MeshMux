package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"net/http"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
	"github.com/wingsky-1/MeshMux/internal/core/meshnet"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// TestMeshErrorCodeOnlyReturnsRegisteredCodes pins the closed set: a value that
// is not a registered constant never becomes a mesh code, however code-shaped it
// looks in the message.
func TestMeshErrorCodeOnlyReturnsRegisteredCodes(t *testing.T) {
	accepted := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New(store.CodeDatabaseUnavailable), store.CodeDatabaseUnavailable},
		{errors.New(store.CodeMeshDeviceNotFound + ": unknown mesh device"), store.CodeMeshDeviceNotFound},
		{store.MeshError(store.CodeMeshRouteConflict, "the prefix is already declared"), store.CodeMeshRouteConflict},
		{&mesh.DomainError{Code: mesh.CodeNodeNameDuplicate, Detail: "taken"}, mesh.CodeNodeNameDuplicate},
		{&meshnet.Error{Code: meshnet.CodeUnavailable}, meshnet.CodeUnavailable},
		{fmt.Errorf("%s: %w", codeMeshEndpointRenderFailed, errors.New("boom")), codeMeshEndpointRenderFailed},
	}
	for _, tc := range accepted {
		if got := meshErrorCode(tc.err); got != tc.want {
			t.Errorf("meshErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}

	// Anything the registry does not know - a path, a digest, a driver message,
	// a wrapped free-form error - becomes the fixed internal code.
	rejected := []error{
		errors.New("SOMETHING_NOT_REGISTERED"),
		errors.New(`open /run/headscale/headscale.sock: connect: no such file or directory`),
		errors.New("91a5d3e3d7d4b0d3: digest mismatch"),
		errors.New("HEADSCALE_SOMETHING_NEW: the adapter grew a code"),
		errors.New("MESH_X: an unregistered mesh code"),
		fmt.Errorf("wrapped: %w", errors.New("postgres is down")),
	}
	for _, err := range rejected {
		if got := meshErrorCode(err); got != codeMeshInternalError {
			t.Errorf("meshErrorCode(%v) = %q, want %q", err, got, codeMeshInternalError)
		}
	}
}

// TestMeshStatusIsChosenFromCodesOnly proves the HTTP class never depends on a
// prefix scan over free-form text.
func TestMeshStatusIsChosenFromCodesOnly(t *testing.T) {
	cases := []struct {
		code   string
		status int
	}{
		{store.CodeDatabaseUnavailable, http.StatusServiceUnavailable},
		{meshnet.CodeUnavailable, http.StatusServiceUnavailable},
		{meshnet.CodeTimeout, http.StatusServiceUnavailable},
		{store.CodeMeshDeviceNotFound, http.StatusNotFound},
		{store.CodeMeshEnrollmentKeyNotFound, http.StatusNotFound},
		{store.CodeMeshRouteNotFound, http.StatusNotFound},
		{codeMeshClaimNodeNotFound, http.StatusNotFound},
		{store.CodeMeshDeviceCorrupt, http.StatusInternalServerError},
		{store.CodeMeshRouteCorrupt, http.StatusInternalServerError},
		{codeMeshInternalError, http.StatusInternalServerError},
		{mesh.CodeDeviceIDInvalid, http.StatusBadRequest},
		{mesh.CodeRoutePrefixInvalid, http.StatusBadRequest},
		{mesh.CodeKeySecretInvalid, http.StatusBadRequest},
		{mesh.CodeNodeNameDuplicate, http.StatusConflict},
		{mesh.CodeKeyAlreadyActive, http.StatusConflict},
		{codeMeshEndpointRenderFailed, http.StatusConflict},
		{subscription.CodeMeshLineInTailnet, http.StatusConflict},
		{subscription.CodeMeshPurposeUnsupported, http.StatusConflict},
		{codeMeshRouteApprovalUnconfirmed, http.StatusConflict},
		{codeMeshRouteApprovalPartial, http.StatusInternalServerError},
		{codeMeshRouteWithdrawPartial, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		if got := meshStatus(tc.code); got != tc.status {
			t.Errorf("meshStatus(%q) = %d, want %d", tc.code, got, tc.status)
		}
	}
	// A code that only resembles an export or adapter code is not promoted into
	// its status class.
	if got := meshStatus("EXPORT_MESH_SOMETHING_NEW"); got != http.StatusConflict {
		t.Errorf("unknown export-like code = %d", got)
	}
}

// TestMeshControlPlaneFailRefusesForeignCodes proves a Headscale error that is
// not a registered adapter code is not forwarded verbatim as a 503: an adapter
// that grows a code is a Hub-side contract defect, so the page reports the
// fixed internal code and a 500, never the new value.
func TestMeshControlPlaneFailRefusesForeignCodes(t *testing.T) {
	_, b, fake, _ := meshTestApp(t)
	fake.failWith["nodes.list"] = "HEADSCALE_SOMETHING_NEW"
	w := b.post("/mesh/reconcile", nil)
	requireStatus(t, w, http.StatusInternalServerError)
	if strings.Contains(w.Body.String(), "HEADSCALE_SOMETHING_NEW") {
		t.Fatalf("unregistered adapter code reached the page: %.300s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), codeMeshInternalError) {
		t.Fatalf("refusal lost its sanitized code: %.300s", w.Body.String())
	}
}

// TestMeshPageNoticeNeverRendersFreeFormText proves a corrupt stored row is
// reported by its registered code only: the store detail and the stored value
// stay out of the page, and the log carries the code rather than the message.
func TestMeshPageNoticeNeverRendersFreeFormText(t *testing.T) {
	app, b, _, logs := meshTestApp(t)
	device, err := app.Store.CreateMeshDevice(meshSpec("phone", mesh.PurposeMeshOnly, ""), app.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A hand-edited node name that no longer satisfies the domain rules is a
	// corrupt row: the store reports MESH_DEVICE_CORRUPT without quoting it.
	if _, err = app.Store.DB.Exec(`UPDATE mesh_devices SET node_name='Not A Name' WHERE id=?`, device.ID); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	w := b.post("/mesh/reconcile", nil)
	// A corrupt row is a server-side defect: it must never render as a healthy
	// page, and it must never quote the row.
	requireStatus(t, w, http.StatusInternalServerError)
	body := w.Body.String()
	if !strings.Contains(body, store.CodeMeshDeviceCorrupt) {
		t.Fatalf("page lost %s: %.400s", store.CodeMeshDeviceCorrupt, body)
	}
	for _, leak := range []string{"the stored mesh device record is invalid", "Not A Name"} {
		if strings.Contains(body, leak) {
			t.Fatalf("page quoted %q: %.400s", leak, body)
		}
	}
	var event struct {
		ErrorCode string `json:"error_code"`
	}
	found := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if !strings.Contains(line, "web_event") {
			continue
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		if event.ErrorCode == store.CodeMeshDeviceCorrupt {
			found = true
		}
	}
	if !found {
		t.Fatalf("reconcile did not log %s: %s", store.CodeMeshDeviceCorrupt, logs.String())
	}
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "Not A Name") || strings.Contains(line, "the stored mesh device record is invalid") {
			t.Fatalf("log line quoted the row: %s", line)
		}
	}
}

// TestMeshCodesCoverEveryRenderedConstant keeps the registry in step with the
// codes the Mesh pages can name. A fallback that is not registered would surface
// as MESH_INTERNAL_ERROR instead of its own code.
func TestMeshCodesCoverEveryRenderedConstant(t *testing.T) {
	for _, code := range []string{
		codeMeshDeviceCreateFailed,
		codeMeshDeviceKeyIssue,
		codeMeshDeviceRekeyFailed,
		codeMeshDeviceRevokeFailed,
		codeMeshDeviceNotReenrollable,
		codeMeshReconcileFailed,
		codeMeshRouteApproval,
		codeMeshRouteWithdraw,
		codeMeshRouteApprovalPartial,
		codeMeshRouteWithdrawPartial,
		codeMeshRouteApprovalUnconfirmed,
		codeMeshRouteNodeUnobserved,
		codeMeshHeadscaleUserUnknown,
		codeMeshClaimNodeNotFound,
		codeMeshClaimNodeMismatch,
		codeMeshClaimNodeOccupied,
		codeMeshClaimFailed,
		codeMeshEndpointControlURLUnavailable,
		codeMeshEndpointPurposeUnsupported,
		codeMeshEndpointSubscriberUnavailable,
		codeMeshEndpointKeyIssueFailed,
		codeMeshEndpointRenderFailed,
	} {
		if !isMeshCode(code) {
			t.Errorf("%q is rendered by a Mesh handler but not registered", code)
		}
	}
	if isMeshCode("SOMETHING_NOT_REGISTERED") {
		t.Error("foreign code accepted by the registry")
	}
}

// TestSubscriptionStoreErrorComparesCodes pins the download gate: a database
// failure is recognised by its code, and a detail that merely starts with the
// same text is not.
func TestSubscriptionStoreErrorComparesCodes(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{nil, nil},
		{store.ErrSubscriptionStoreUnavailable, store.ErrSubscriptionStoreUnavailable},
		{errors.New(store.CodeDatabaseUnavailable), store.ErrSubscriptionStoreUnavailable},
		{fmt.Errorf("%s: %w", store.CodeDatabaseUnavailable, errors.New("disk gone")), store.ErrSubscriptionStoreUnavailable},
		{store.ErrSubscriptionRejected, store.ErrSubscriptionRejected},
		// A rejection whose detail happens to quote the database code is still a
		// rejection: only the code segment decides.
		{errors.New(store.CodeDatabaseUnavailable + "_LOOKALIKE: no"), store.ErrSubscriptionRejected},
		{errors.New("SUBSCRIPTION_DOWNLOAD_REJECTED: " + store.CodeDatabaseUnavailable), store.ErrSubscriptionRejected},
		{errors.New("/var/lib/meshmux/web.db: unreachable"), store.ErrSubscriptionRejected},
	}
	for _, tc := range cases {
		got := store.SubscriptionStoreError(tc.err)
		if !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
			t.Errorf("subscriptionStoreError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestErrorCodeOfIsPrefixSafe proves the shared helper splits on the first colon
// and never trims a detail into the code.
func TestErrorCodeOfIsPrefixSafe(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("CODE_A: detail"), "CODE_A"},
		{errors.New("CODE_A"), "CODE_A"},
		{errors.New("CODE_A:detail:more"), "CODE_A"},
		{errors.New(": leading colon"), ": leading colon"},
		{errors.New("path/with:colon CODE"), "path/with"},
	}
	for _, tc := range cases {
		if got := store.ErrorCodeOf(tc.err); got != tc.want {
			t.Errorf("errorCodeOf(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	// A code is only ever compared against a constant, never against a prefix.
	if strings.HasPrefix(store.CodeDatabaseUnavailable, "DATABASE") == false {
		t.Fatal("test assumption broken")
	}
}
