package handler

// The subscription wizard (Task 4, ADR-0008 §1–§4).
//
// The wizard is the only place a subscription selection is written. It has four
// groups — Lines, Out, rules, mesh devices — and two explicit actions:
//
//	preview : compose + gate, writes nothing, renders "!" reminders and "✖"
//	          blocking findings
//	save    : the same pipeline, and only an approved artifact is persisted
//
// The four fail-fast layers of ADR-0008 §7 map onto this file:
//
//	layer 1 (input)   : reminders, rendered with "!" and never blocking
//	layer 2 (save)    : strict identity validation in the store
//	layer 3 (compose) : conflicts and the Out slot, from the pure composer
//	layer 4 (gate)    : sing-box always, mihomo only when installed
//
// A save never falls back to a partial selection: the store writes nothing when
// any layer blocks, so the page can always say "not saved" honestly.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/wingsky-1/MeshMux/internal/policy"
	"github.com/wingsky-1/MeshMux/internal/subscription"
	"github.com/wingsky-1/MeshMux/internal/web/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// subscriptionWizardLine is one Line row of the wizard's first group.
type subscriptionWizardLine struct {
	NodeID      string
	DisplayName string
	Server      string
	Port        int
	SortOrder   int
	Selected    bool
	// Credential is the UUID already issued to this subscriber on this Line.
	// Empty on the create form, where no credential exists yet.
	Credential string
	// Converged is the per-Line gate evidence, so the wizard never claims a
	// Line can serve the selection when it cannot.
	Converged bool
	Code      string
}

// subscriptionWizardView is the whole wizard page model.
type subscriptionWizardView struct {
	SubscriberID   string
	SubscriberName string
	State          string
	Lines          []subscriptionWizardLine
	Outs           []store.OutPoolEntry
	OutID          string
	Rules          []policy.Rule
	RuleSelections []store.RuleRevision
	Devices        []store.MeshDeviceRecord
	DeviceIDs      []string
	// Diagnostics is the last preview or save result. A reminder renders "!";
	// a blocking finding renders "✖" and means nothing was saved.
	Diagnostics []subscription.Diagnostic
	// Saved is true when the last save approved and persisted the selection.
	Saved bool
	// GateNote names the kernels that ran, or the skipped mihomo gate.
	GateNote string
	// ContentID is the approved artifact digest after a successful save.
	ContentID string
	// Notice is one-shot feedback of a save.
	Notice string
	// Submitted is the selection of the request being rendered. It overrides
	// the saved selection, so a blocked save or a preview never loses the
	// operator's checkboxes.
	Submitted *store.SelectionSpec
}

// toView converts the handler model into the render model.
func (m subscriptionWizardView) toView() view.SubscriptionWizardView {
	out := view.SubscriptionWizardView{
		SubscriberID: m.SubscriberID, SubscriberName: m.SubscriberName, State: m.State,
		GateNote: m.GateNote, ContentID: m.ContentID, Notice: m.Notice, Saved: m.Saved,
		Create: m.SubscriberID == "",
		Lines:  []view.WizardLine{}, Outs: []view.WizardOut{}, Rules: []view.WizardRule{}, Devices: []view.WizardDevice{},
		Diagnostics: []view.WizardDiagnostic{},
	}
	for _, line := range m.Lines {
		out.Lines = append(out.Lines, view.WizardLine{
			NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server,
			Port: line.Port, SortOrder: line.SortOrder, Selected: line.Selected,
			Credential: line.Credential, Converged: line.Converged, Code: line.Code,
		})
	}
	for _, outEntry := range m.Outs {
		out.Outs = append(out.Outs, view.WizardOut{
			OutID: outEntry.OutID, DisplayName: outEntry.DisplayName,
			Server: outEntry.Server, Port: outEntry.Port,
			Online: outEntry.Online, Configured: outEntry.TransportConfigured,
			Selected: outEntry.OutID == m.OutID, Kind: outEntry.Role,
		})
	}
	selectedRules := make(map[string]bool, len(m.RuleSelections))
	for _, revision := range m.RuleSelections {
		selectedRules[revision.StableKey+"@"+strconv.Itoa(revision.Version)] = true
	}
	latest := make(map[string]int, len(m.Rules))
	for _, rule := range m.Rules {
		if rule.Version > latest[rule.StableKey] {
			latest[rule.StableKey] = rule.Version
		}
	}
	for _, rule := range m.Rules {
		hint := ""
		if latest[rule.StableKey] > rule.Version {
			hint = "可升级到 v" + strconv.Itoa(latest[rule.StableKey]) + "（不自动迁移）"
		}
		out.Rules = append(out.Rules, view.WizardRule{
			StableKey: rule.StableKey, Version: rule.Version, Name: rule.Name,
			Action:      view.RuleLibraryActionLabel(rule.Action),
			Matcher:     view.RuleLibraryMatcherLabel(rule.Kind, rule.Values),
			Preset:      rule.Origin == policy.OriginPreset,
			Selected:    selectedRules[rule.StableKey+"@"+strconv.Itoa(rule.Version)],
			UpgradeHint: hint,
		})
	}
	selectedDevices := make(map[string]bool, len(m.DeviceIDs))
	for _, deviceID := range m.DeviceIDs {
		selectedDevices[deviceID] = true
	}
	for _, device := range m.Devices {
		out.Devices = append(out.Devices, view.WizardDevice{
			DeviceID: device.ID, DisplayName: device.DisplayName,
			Purpose: string(device.Purpose), Status: string(device.Status),
			Selected: selectedDevices[device.ID],
		})
	}
	for _, diagnostic := range m.Diagnostics {
		out.Diagnostics = append(out.Diagnostics, view.WizardDiagnostic{
			Blocking: diagnostic.Level == subscription.DiagnosticBlocking,
			Code:     diagnostic.Code,
			Detail:   diagnostic.Detail,
		})
	}
	return out
}

// registerSubscriptionWizardRoutes registers the wizard's two POST endpoints.
// Both go through the standard mutation boundary (session, Origin, CSRF,
// duplicate-field and size checks), so the wizard inherits the same request
// contract as every other management action.
func (app *Server) registerSubscriptionWizardRoutes(r chi.Router) {
	r.Post("/subscribers/wizard/preview", app.mutation(app.subscriptionWizardPreview, true))
	r.Post("/subscribers/wizard/save", app.mutation(app.subscriptionWizardSave, true))
}

// subscriptionWizardPage renders the wizard for one subscriber (or the create
// form when subscriber_id is empty).
func (app *Server) subscriptionWizardPage(w http.ResponseWriter, r *http.Request, sess session, model subscriptionWizardView) {
	app.render(w, r, http.StatusOK, view.SubscriptionWizardPage(
		view.PageData{Title: "订阅向导", Path: "/subscribers", CSRF: sess.CSRF, Dev: app.cfg.DevHTTP},
		model.toView(),
	))
}

// subscribersWizard is the GET entry point. The subscriber is optional: without
// one the page is the create form, with one it restores the saved selection.
func (app *Server) subscribersWizard(w http.ResponseWriter, r *http.Request, sess session) {
	subscriberID := strings.TrimSpace(r.URL.Query().Get("subscriber_id"))
	// The query string is not a mutation input, but it still must be a
	// canonical identity before it reaches a store read.
	if subscriberID != "" && subscription.ValidateID(subscriberID) != nil {
		app.fail(w, r, http.StatusBadRequest, "SUBSCRIBER_ID_INVALID", "订阅用户标识不正确。", "请从订阅用户页打开向导。")
		return
	}
	model, err := app.subscriptionWizardModel(subscriberID)
	if err != nil {
		app.subscriptionWizardFail(w, r, err)
		return
	}
	app.subscriptionWizardPage(w, r, sess, model)
}

// subscriptionWizardModel builds the wizard's selection datasources.
func (app *Server) subscriptionWizardModel(subscriberID string) (subscriptionWizardView, error) {
	return app.subscriptionWizardModelWith(subscriberID, nil)
}

// subscriptionWizardModelWith builds the page with an optional submitted
// selection that overrides the saved checkboxes.
func (app *Server) subscriptionWizardModelWith(subscriberID string, submitted *store.SelectionSpec) (subscriptionWizardView, error) {
	model := subscriptionWizardView{SubscriberID: subscriberID, Outs: []store.OutPoolEntry{}, Rules: []policy.Rule{}, Devices: []store.MeshDeviceRecord{}, Submitted: submitted}
	now := app.now()
	lines, err := app.store.ListLines()
	if err != nil {
		return model, err
	}
	outs, err := app.store.OutPool(now)
	if err != nil {
		return model, err
	}
	model.Outs = outs
	rules, err := app.rulesLib().LatestRules()
	if err != nil {
		return model, err
	}
	model.Rules = rules
	devices, err := app.store.ListMeshDevices()
	if err != nil {
		return model, err
	}
	for _, device := range devices {
		switch string(device.Status) {
		case "revoked", "revoking", "expired", "failed":
			continue
		}
		model.Devices = append(model.Devices, device)
	}
	selection := subscription.Selection{}
	if model.Submitted != nil {
		// The request being rendered is the source of truth for the checked
		// state; the saved snapshot only fills in what the request omitted.
		for position, nodeID := range model.Submitted.LineIDs {
			selection.Lines = append(selection.Lines, subscription.SelectionLine{NodeID: nodeID, Position: position})
		}
		if model.Submitted.OutID != "" {
			selection.Out = &subscription.SelectionOut{OutID: model.Submitted.OutID}
		}
		for position, revision := range model.Submitted.Rules {
			selection.Rules = append(selection.Rules, subscription.SelectionRule{StableKey: revision.StableKey, Version: revision.Version, Position: position})
		}
		for position, deviceID := range model.Submitted.NetworkIDs {
			selection.Networks = append(selection.Networks, subscription.SelectionNetwork{DeviceID: deviceID, Position: position})
		}
		// A submitted selection always has Lines, so the saved-read branch below
		// is skipped; the create/preview path still needs the Line list.
		if subscriberID == "" {
			for _, line := range lines {
				model.Lines = append(model.Lines, subscriptionWizardLine{
					NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server,
					Port: line.Port, SortOrder: line.SortOrder,
				})
			}
			applySubmittedSelection(&model, selection)
			return model, nil
		}
	}
	if subscriberID != "" {
		sub, err := app.store.GetSubscriber(subscriberID)
		if err != nil {
			return model, err
		}
		model.SubscriberName, model.State = sub.DisplayName, string(sub.State)
		selection, _, err = app.store.SubscriptionSelection(subscriberID)
		if err != nil {
			return model, err
		}
		evidence, err := app.store.SubscriberSyncView(subscriberID, now)
		if err != nil {
			return model, err
		}
		lineEvidence := make(map[string]store.SubscriberLineSyncSnapshot, len(evidence.Lines))
		for _, line := range evidence.Lines {
			lineEvidence[line.NodeID] = line
		}
		credentials, err := app.store.ListSubscriberCredentials(subscriberID)
		if err != nil {
			return model, err
		}
		activeCredential := make(map[string]string, len(credentials))
		for _, credential := range credentials {
			if _, exists := activeCredential[credential.NodeID]; !exists {
				activeCredential[credential.NodeID] = credential.UUID
			}
		}
		selected := make(map[string]bool, len(selection.Lines))
		for _, line := range selection.Lines {
			selected[line.NodeID] = true
		}
		for _, line := range lines {
			row := subscriptionWizardLine{
				NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server,
				Port: line.Port, SortOrder: line.SortOrder, Selected: selected[line.NodeID],
				Credential: activeCredential[line.NodeID],
			}
			if evidence, ok := lineEvidence[line.NodeID]; ok {
				row.Converged = evidence.Status == store.SubscriberSyncHealthy
				row.Code = evidence.Code
			}
			model.Lines = append(model.Lines, row)
		}
		if selection.Out != nil {
			model.OutID = selection.Out.OutID
		}
		for _, revision := range selection.RuleRevisions() {
			model.RuleSelections = append(model.RuleSelections, store.RuleRevision{StableKey: revision.StableKey, Version: revision.Version})
		}
		for _, device := range selection.Networks {
			model.DeviceIDs = append(model.DeviceIDs, device.DeviceID)
		}
		return model, nil
	}
	for _, line := range lines {
		model.Lines = append(model.Lines, subscriptionWizardLine{
			NodeID: line.NodeID, DisplayName: line.DisplayName, Server: line.Server,
			Port: line.Port, SortOrder: line.SortOrder,
		})
	}
	return model, nil
}

// applySubmittedSelection marks the rows of one selection as checked. It runs
// after the saved snapshot was applied, so a preview or a blocked save shows the
// request rather than the last confirmed choice.
func applySubmittedSelection(model *subscriptionWizardView, selection subscription.Selection) {
	selectedLines := make(map[string]bool, len(selection.Lines))
	for _, line := range selection.Lines {
		selectedLines[line.NodeID] = true
	}
	for index := range model.Lines {
		model.Lines[index].Selected = selectedLines[model.Lines[index].NodeID]
	}
	if selection.Out != nil {
		model.OutID = selection.Out.OutID
	}
	model.RuleSelections = nil
	for _, rule := range selection.Rules {
		model.RuleSelections = append(model.RuleSelections, store.RuleRevision{StableKey: rule.StableKey, Version: rule.Version})
	}
	model.DeviceIDs = nil
	for _, device := range selection.Networks {
		model.DeviceIDs = append(model.DeviceIDs, device.DeviceID)
	}
}

// readWizardSelection parses the four groups of one submitted selection.
func readWizardSelection(r *http.Request) (store.SelectionSpec, string, error) {
	spec := store.SelectionSpec{}
	spec.OutID = strings.TrimSpace(r.PostForm.Get("out_id"))
	if spec.OutID != "" {
		if err := subscription.ValidateID(spec.OutID); err != nil {
			return spec, "", errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
		}
	}
	// r.PostForm is a map, so a direct range would make the dense positions —
	// and therefore the snapshot identity and the rendered rule order — depend
	// on Go's randomized map iteration. Sorting the field names first makes one
	// checkbox set always produce exactly one selection: positions follow the
	// sorted `line_*` / `device_*` / `rule_*` names, so a repeated submission of
	// the same set is byte-identical.
	keys := make([]string, 0, len(r.PostForm))
	for key := range r.PostForm {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := r.PostForm[key]
		if len(values) != 1 || values[0] != "1" {
			continue
		}
		if nodeID, ok := strings.CutPrefix(key, "line_"); ok {
			if err := subscription.ValidateID(nodeID); err != nil {
				return spec, "", errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
			}
			spec.LineIDs = append(spec.LineIDs, nodeID)
			continue
		}
		if deviceID, ok := strings.CutPrefix(key, "device_"); ok {
			if err := subscription.ValidateID(deviceID); err != nil {
				return spec, "", errors.New("MESH_DEVICE_ID_INVALID: need 32 lowercase hex characters")
			}
			spec.NetworkIDs = append(spec.NetworkIDs, deviceID)
		}
	}
	for _, key := range keys {
		values := r.PostForm[key]
		if len(values) != 1 || values[0] != "1" {
			continue
		}
		raw, ok := strings.CutPrefix(key, "rule_")
		if !ok {
			continue
		}
		stableKey, versionRaw, found := strings.Cut(raw, "@")
		if !found {
			return spec, "", errors.New("RULE_REVISION_INVALID: a rule selection needs key@version")
		}
		version, err := strconv.Atoi(versionRaw)
		if err != nil || version < 1 {
			return spec, "", errors.New("RULE_REVISION_INVALID: a rule selection needs key@version")
		}
		spec.Rules = append(spec.Rules, store.RuleRevision{StableKey: stableKey, Version: version})
	}
	// The mutation boundary rejects repeated fields, so the four groups use
	// distinct prefixes. The order is the sorted field-name order decided above,
	// never map order; the store assigns dense positions from that same order.
	return spec, strings.TrimSpace(r.PostForm.Get("display_name")), nil
}

// subscriptionWizardPreview composes and gates one selection without writing.
func (app *Server) subscriptionWizardPreview(w http.ResponseWriter, r *http.Request, sess session) {
	subscriberID := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	spec, _, err := readWizardSelection(r)
	if err != nil {
		app.fail(w, r, http.StatusBadRequest, "SUBSCRIPTION_SELECTION_INVALID", "所选内容不正确。", "请重新勾选线路、Out、规则与组网设备后重试。")
		return
	}
	verifier, err := app.publishVerifier()
	if err != nil {
		app.subscriptionWizardFail(w, r, err)
		return
	}
	draft, err := app.store.DraftSubscriptionSelection(subscriberID, strings.TrimSpace(r.PostForm.Get("display_name")), spec)
	if err != nil {
		app.subscriptionWizardFail(w, r, err)
		return
	}
	preview := app.store.PreviewDraftSelection(draft, verifier)
	app.event(r, "SUBSCRIPTION_PREVIEWED")
	model, err := app.subscriptionWizardModelWith(subscriberID, &spec)
	if err != nil {
		app.fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "预览已生成但页面数据读取失败。", "请刷新页面后重试。")
		return
	}
	model.Diagnostics = preview.Diagnostics
	model.Submitted = &spec
	model.GateNote = strings.Join(preview.Gates, " + ")
	if preview.MihomoSkipped {
		model.GateNote = strings.TrimSpace(model.GateNote + "（Mihomo 未安装，未校验）")
	}
	model.Notice = "预览完成：未保存任何内容。"
	app.subscriptionWizardPage(w, r, sess, model)
}

// subscriptionWizardSave approves and persists one selection. A blocked
// preview saves nothing and says so.
func (app *Server) subscriptionWizardSave(w http.ResponseWriter, r *http.Request, sess session) {
	subscriberID := strings.TrimSpace(r.PostForm.Get("subscriber_id"))
	spec, displayName, err := readWizardSelection(r)
	if err != nil {
		app.fail(w, r, http.StatusBadRequest, "SUBSCRIPTION_SELECTION_INVALID", "所选内容不正确。", "请重新勾选线路、Out、规则与组网设备后重试。")
		return
	}
	now := app.now()
	verifier, err := app.publishVerifier()
	if err != nil {
		app.subscriptionWizardFail(w, r, err)
		return
	}
	result, err := app.store.ApproveSubscriptionSelection(context.Background(), subscriberID, displayName, spec, verifier, now)
	if err != nil {
		app.subscriptionWizardFail(w, r, err)
		return
	}
	preview := result.Preview
	// A blocked save wrote nothing, so a create still has no persisted
	// subscriber: the page is rebuilt from the request alone.
	pageSubscriberID := subscriberID
	if !preview.Blocking() {
		pageSubscriberID = result.SubscriberID
		subscriberID = result.SubscriberID
	}
	if preview.Blocking() {
		app.event(r, preview.Code())
		model, modelErr := app.subscriptionWizardModelWith(pageSubscriberID, &spec)
		if modelErr != nil {
			app.fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "保存被拒绝但页面数据读取失败。", "请刷新页面后重试。")
			return
		}
		model.Diagnostics = preview.Diagnostics
		model.Submitted = &spec
		model.Notice = "保存被拒绝：产物未通过门禁，未写入任何选择。"
		app.subscriptionWizardPage(w, r, sess, model)
		return
	}

	app.event(r, "SUBSCRIPTION_SAVED")
	// The selection is durable and approved; the Line publication follows
	// immediately. A failed publication leaves the page pending instead of
	// claiming a convergence that did not happen.
	if err := app.store.PrepareSubscriberSync(subscriberID, now); err != nil {
		app.event(r, store.SanitizeSubscriberSyncCode(err.Error()))
	}
	model, err := app.subscriptionWizardModel(subscriberID)
	if err != nil {
		app.fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "选择已保存但页面数据读取失败。", "请刷新页面后重试。")
		return
	}
	model.Diagnostics = preview.Diagnostics
	model.Saved = true
	model.ContentID = preview.ContentID
	model.GateNote = strings.Join(preview.Gates, " + ")
	if preview.MihomoSkipped {
		model.GateNote = strings.TrimSpace(model.GateNote + "（Mihomo 未安装，未校验）")
	}
	model.Notice = "选择已保存并通过门禁。"
	if result.Bearer != "" {
		model.Notice = "订阅用户已创建，选择已保存并通过门禁。"
	}
	if result.Bearer != "" {
		app.renderSubscribers(w, r, sess, &tokenDisclosure{Subscriber: model.SubscriberName, Token: result.Bearer})
		return
	}
	app.subscriptionWizardPage(w, r, sess, model)
}

// subscriptionWizardFail maps a wizard store error onto the stable HTTP
// contract. Every composer refusal keeps its own code, so the page can explain
// the real reason instead of a generic failure.
func (app *Server) subscriptionWizardFail(w http.ResponseWriter, r *http.Request, err error) {
	code, _, _ := strings.Cut(err.Error(), ": ")
	status := http.StatusConflict
	switch code {
	case store.CodeDatabaseUnavailable:
		status = http.StatusServiceUnavailable
	case "SUBSCRIBER_NOT_FOUND", "OUT_NOT_FOUND", "LINE_NOT_FOUND", "RULE_NOT_FOUND", "MESH_DEVICE_NOT_FOUND":
		status = http.StatusNotFound
	case "SUBSCRIBER_ID_INVALID", "LINE_ID_INVALID", "LINES_REQUIRED", "LINES_TOO_MANY",
		"OUT_BINDING_INVALID", "MESH_DEVICE_ID_INVALID", "SUBSCRIPTION_SELECTION_INVALID":
		status = http.StatusBadRequest
	case store.CodeComposeGateUnavailable:
		status = http.StatusServiceUnavailable
	}
	detail := err.Error()
	if _, after, found := strings.Cut(detail, ": "); found {
		detail = after
	}
	app.event(r, code)
	// The detail names the offending subscription or Line, which the operator
	// needs to resolve a reference conflict. It carries no credential, token or
	// document byte: every store refusal is built from identities and names.
	app.fail(w, r, status, code, "订阅向导操作未完成："+detail, "请按页面提示修正选择或检查服务日志后重试。")
}
