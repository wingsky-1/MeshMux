package policy

import (
	"errors"
	"github.com/wingsky-1/MeshMux/internal/web/handler/infra"
	"net/http"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// The rule-library page (Task 3, ADR-0008 §5): preset rows are read-only,
// custom rows grow by revision, and a referenced delete is refused with the
// subscriber names. Writes re-render the list with a one-shot notice, like
// the nodes-page Out actions; failures use the shared fail envelope so the
// stable code (RULE_PRESET_IMMUTABLE and friends) always reaches the log and
// the page.

func (app *Server) rulesLib() *policy.Store { return policy.New(app.Store.DB, store.RuleUsageSource()) }

// rulesLibraryModel builds the page from the latest revision of every key,
// each with the subscribers pinning exactly that revision. History comes from
// one ListRules pass, not one query per row.
func (app *Server) rulesLibraryModel(notice string, pending view.PendingRuleDelete, hasPending bool) (view.RulesLibraryView, error) {
	lib := app.rulesLib()
	latest, err := lib.LatestRules()
	if err != nil {
		return view.RulesLibraryView{}, err
	}
	all, err := lib.ListRules("")
	if err != nil {
		return view.RulesLibraryView{}, err
	}
	history := map[string][]int{}
	for _, r := range all {
		history[r.StableKey] = append(history[r.StableKey], r.Version)
	}
	model := view.RulesLibraryView{Notice: notice, Pending: pending, HasPending: hasPending}
	for _, r := range latest {
		used, err := lib.RuleUsedBy(r.StableKey, r.Version)
		if err != nil {
			return view.RulesLibraryView{}, err
		}
		names := make([]string, 0, len(used))
		for _, u := range used {
			names = append(names, u.DisplayName())
		}
		row := view.RuleLibraryRow{
			StableKey: r.StableKey, Version: r.Version, Name: r.Name,
			Action: view.RuleLibraryActionLabel(r.Action), Matcher: view.RuleLibraryMatcherLabel(r.Kind, r.Values),
			Values: append([]string(nil), r.Values...), ValuesText: strings.Join(r.Values, "\n"),
			ActionValue: string(r.Action), KindValue: string(r.Kind),
			Origin: view.RuleLibraryOriginLabel(r.Origin == policy.OriginPreset),
			Preset: r.Origin == policy.OriginPreset, UsedBy: names, History: history[r.StableKey],
		}
		if row.Preset {
			model.Presets = append(model.Presets, row)
		} else {
			model.Customs = append(model.Customs, row)
		}
	}
	return model, nil
}

func (app *Server) renderRulesLibrary(w http.ResponseWriter, r *http.Request, sess infra.Session, model view.RulesLibraryView) {
	app.Render(w, r, http.StatusOK, view.RulesLibraryPage(view.PageData{Title: "规则库", Path: "/rules", CSRF: sess.CSRF, Dev: app.Cfg.DevHTTP, DirectProxy: app.Cfg.DirectProxy}, model))
}

// rulesLibraryPage renders the read-only list. A store failure is a 503; it
// never renders a half-built list as the library.
func (app *Server) rulesLibraryPage(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	model, err := app.rulesLibraryModel("", view.PendingRuleDelete{}, false)
	if err != nil {
		app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "规则库读取失败。", "请检查数据库与服务日志后重试。")
		return
	}
	app.renderRulesLibrary(w, r, sess, model)
}

// readLibraryForm parses one rule write. Values arrive one per line (commas
// are accepted too); blank lines are dropped before validation so a trailing
// newline never becomes a blank matcher.
func readLibraryForm(r *http.Request) (key, name string, action policy.Action, kind policy.MatcherKind, values []string) {
	key = strings.TrimSpace(r.PostForm.Get("stable_key"))
	name = strings.TrimSpace(r.PostForm.Get("name"))
	action = policy.Action(strings.TrimSpace(r.PostForm.Get("action")))
	kind = policy.MatcherKind(strings.TrimSpace(r.PostForm.Get("matcher_kind")))
	for _, line := range strings.Split(strings.ReplaceAll(r.PostForm.Get("values"), ",", "\n"), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			values = append(values, value)
		}
	}
	return key, name, action, kind, values
}

// rulesLibraryCreate inserts version 1 of a custom rule and re-renders the
// list with the receipt. Preset keys are refused, never squatted.
func (app *Server) rulesLibraryCreate(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	key, name, action, kind, values := readLibraryForm(r)
	created, err := app.rulesLib().CreateCustomRule(key, name, action, kind, values, app.Now())
	if err != nil {
		app.failRulesLibrary(w, r, err)
		return
	}
	app.Event(r, "RULE_CREATED")
	model, err := app.rulesLibraryModel("自定义规则已创建："+created.StableKey+" v1。预置规则不受影响。", view.PendingRuleDelete{}, false)
	if err != nil {
		app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "规则已写入但列表读取失败。", "请刷新页面后确认。")
		return
	}
	app.renderRulesLibrary(w, r, sess, model)
}

// rulesLibraryRevise inserts a new revision under the same key. Old rows stay
// byte-identical so pinned subscriptions are unaffected until Task 4 migrates
// them explicitly; the notice says so.
func (app *Server) rulesLibraryRevise(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	key, name, action, kind, values := readLibraryForm(r)
	revised, err := app.rulesLib().ReviseCustomRule(key, name, action, kind, values, app.Now())
	if err != nil {
		app.failRulesLibrary(w, r, err)
		return
	}
	app.Event(r, "RULE_REVISED")
	model, err := app.rulesLibraryModel("已生成新版本 v"+strconv.Itoa(revised.Version)+"（"+revised.StableKey+"），旧版本订阅不受影响。", view.PendingRuleDelete{}, false)
	if err != nil {
		app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "规则已写入但列表读取失败。", "请刷新页面后确认。")
		return
	}
	app.renderRulesLibrary(w, r, sess, model)
}

// rulesLibraryDelete is the two-step delete with protection. The first POST
// names the revision and re-renders the impacted subscriptions; only a second
// POST with confirm=1 deletes, and a referenced revision is refused there with
// the same subscriber names the page just showed.
func (app *Server) rulesLibraryDelete(w http.ResponseWriter, r *http.Request, sess infra.Session) {
	key := strings.TrimSpace(r.PostForm.Get("stable_key"))
	version, _ := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("version")))
	if version < 1 {
		app.Fail(w, r, http.StatusNotFound, "RULE_NOT_FOUND", "规则版本不存在。", "请从规则库列表中选择一个版本后重试。")
		return
	}
	if r.PostForm.Get("confirm") != "1" {
		rule, err := app.rulesLib().GetRule(key, version)
		if err != nil {
			app.failRulesLibrary(w, r, err)
			return
		}
		// M1: presets are refused on the first step too, with the same code
		// as the confirmed step — the page never offers a delete confirm
		// for a row that can never be deleted.
		if rule.Origin == policy.OriginPreset {
			app.failRulesLibrary(w, r, errors.New(policy.CodePresetImmutable+": preset rule "+rule.StableKey+" cannot be deleted; it is replaced by versioned migration only"))
			return
		}
		used, err := app.rulesLib().RuleUsedBy(key, version)
		if err != nil {
			app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "引用关系读取失败。", "请检查数据库后重试；未删除任何规则。")
			return
		}
		names := make([]string, 0, len(used))
		for _, u := range used {
			names = append(names, u.DisplayName())
		}
		app.Event(r, "RULE_DELETE_PENDING")
		model, err := app.rulesLibraryModel("", view.PendingRuleDelete{StableKey: rule.StableKey, Version: rule.Version, Name: rule.Name, UsedBy: names}, true)
		if err != nil {
			app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "规则库读取失败。", "请检查数据库后重试；未删除任何规则。")
			return
		}
		app.renderRulesLibrary(w, r, sess, model)
		return
	}
	if err := app.rulesLib().DeleteRule(key, version); err != nil {
		app.failRulesLibrary(w, r, err)
		return
	}
	app.Event(r, "RULE_DELETED")
	model, err := app.rulesLibraryModel("规则已删除："+key+" v"+strconv.Itoa(version)+"。", view.PendingRuleDelete{}, false)
	if err != nil {
		app.Fail(w, r, http.StatusServiceUnavailable, store.CodeDatabaseUnavailable, "规则已删除但列表读取失败。", "请刷新页面后确认。")
		return
	}
	app.renderRulesLibrary(w, r, sess, model)
}

// rulesLibraryFailure maps one library refusal onto the HTTP contract. The
// used-by refusal keeps its subscriber names in the detail: the operator
// needs the list to migrate those subscriptions first.
func rulesLibraryFailure(err error) (status int, code string) {
	code = err.Error()
	if before, _, found := strings.Cut(code, ": "); found {
		code = before
	}
	switch code {
	case policy.CodePresetImmutable:
		return http.StatusForbidden, code
	case policy.CodeReferenced:
		return http.StatusConflict, code
	case policy.CodeNotFound:
		return http.StatusNotFound, code
	case policy.CodeInvalid:
		return http.StatusBadRequest, code
	case policy.CodeConflict:
		return http.StatusConflict, code
	case store.CodeDatabaseUnavailable, "RULE_CORRUPT", "RULE_SEED_FAILED":
		return http.StatusServiceUnavailable, code
	default:
		return http.StatusInternalServerError, code
	}
}

func (app *Server) failRulesLibrary(w http.ResponseWriter, r *http.Request, err error) {
	status, code := rulesLibraryFailure(err)
	detail := err.Error()
	if _, after, found := strings.Cut(detail, ": "); found {
		detail = after
	}
	app.Fail(w, r, status, code, "规则库写操作未完成："+detail, "请修正后重试；预置规则不可写，被订阅引用的规则请先迁移订阅。")
}
