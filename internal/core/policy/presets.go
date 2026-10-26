package policy

import "github.com/wingsky-1/MeshMux/internal/core/subscription/ir"

// The versioned preset seed bundle. Version 1 stocks one preset per matcher
// kind so every library path (render, validate, compose) has a real row to
// exercise. A future bundle ships as new rows under the same stable_keys with
// a higher version: old rows are never edited in place, so subscriptions
// pinned to an old revision keep their bytes and surface as "可升级".
const PresetBundleVersion = 1

// Preset is one seed entry. Only this file may introduce stable_keys in the
// preset- namespace; custom writes there are refused.
type Preset struct {
	StableKey string
	Name      string
	Action    Action
	Kind      MatcherKind
	Values    []string
}

// Presets is the whole bundle at PresetBundleVersion. Example domains use
// example.invalid and documentation ranges only.
var Presets = []Preset{
	{
		StableKey: "preset-direct-private",
		Name:      "直连 · 内网与 Tailnet 网段",
		Action:    ActionDirect,
		Kind:      MatcherIPCIDR,
		// The first entry is the tailnet range the mesh domain and the device
		// exporter also read: one source, so a preset can never disagree with
		// the routes the Hub itself allocates.
		Values: []string{ir.TailnetIPv4Prefix, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	},
	{
		StableKey: "preset-direct-cn",
		Name:      "直连 · 中国大陆域名",
		Action:    ActionDirect,
		Kind:      MatcherGeoSite,
		Values:    []string{"cn"},
	},
	{
		StableKey: "preset-direct-cn-ip",
		Name:      "直连 · 中国大陆 IP",
		Action:    ActionDirect,
		Kind:      MatcherGeoIP,
		Values:    []string{"cn"},
	},
	{
		StableKey: "preset-proxy-ai",
		Name:      "代理 · AI 服务规则集",
		Action:    ActionProxy,
		Kind:      MatcherRuleSet,
		Values:    []string{"ai"},
	},
	{
		StableKey: "preset-reject-ads",
		Name:      "拒绝 · 广告与跟踪后缀",
		Action:    ActionReject,
		Kind:      MatcherDomainSuffix,
		Values:    []string{"ads.example.invalid", "tracker.example.invalid"},
	},
	{
		StableKey: "preset-direct-mirror",
		Name:      "直连 · 镜像站例外",
		Action:    ActionDirect,
		Kind:      MatcherDomain,
		Values:    []string{"dl.example.invalid"},
	},
}
