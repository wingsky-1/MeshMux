package store

// Composition inputs for one subscription artifact.
//
// One builder serves every path that composes a subscription:
//
//	draft + preview  (credentials minted by the draft, nothing persisted)
//	save             (the same draft inputs, written unchanged)
//	download         (credentials read from proxy_credentials, never minted)
//
// Having a single builder is what makes the approved digest meaningful: the
// bytes the wizard gated are produced by exactly the same function that the
// download re-runs, from exactly the same rows.
//
// Everything here is read-only and returns stable codes. A record that exists
// but cannot be used (a Line whose stored transport is invalid, a device row
// that vanished) is reported as a blocking diagnostic where a diagnostic is the
// answer, and as a stable error where the caller cannot proceed at all.

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/policy"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// selectionInputs is the pure composer's input set for one selection.
type selectionInputs struct {
	Lines   []subscription.ComposeLine
	Out     []subscription.ComposeOut
	Rules   []subscription.ComposeRule
	Network []subscription.ComposeNetwork
}

// selectionAssembly is the read result of one selection: the composer inputs
// plus any non-fatal finding (layer-3 diagnostics) the read already knows.
type selectionAssembly struct {
	inputs      selectionInputs
	diagnostics []subscription.Diagnostic
}

// assembleSelectionTx resolves one canonical selection into composer inputs.
//
// Input: ordered Line ids, already-minted credentials (one per Line), the
// optional Out id, pinned rule revisions and device ids.
// Validation: every Line record must still be readable and public-safe; the Out
// must still have a dial body; the rules must still resolve to pinned artifacts.
// A missing Line transport, Out body or device row becomes a blocking
// diagnostic instead of an error, because the wizard still has to render the
// rest of the selection the operator submitted.
// Side effects: none. Return: the composer inputs plus those diagnostics.
func assembleSelectionTx(tx *sql.Tx, lineIDs []string, credentials []subscription.Credential, outID string, ruleRevisions []RuleRevision, deviceIDs []string) (selectionAssembly, error) {
	assembly := selectionAssembly{}
	for index, nodeID := range lineIDs {
		line, err := downloadLineTx(tx, nodeID)
		if err != nil {
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(subscription.CodeComposeLineInvalid, "所选 Line 已不可用"))
			continue
		}
		if index >= len(credentials) {
			return selectionAssembly{}, errors.New(CodeSelectionInvalid + ": a selected line has no credential")
		}
		assembly.inputs.Lines = append(assembly.inputs.Lines, subscription.ComposeLine{Line: publicLine(line), Credential: credentials[index]})
	}
	if outID != "" {
		out, err := selectionOutTx(tx, outID)
		if err != nil {
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(subscription.CodeComposeOutInvalid, "所选 Out 已不可用或未配置出口地址"))
		} else {
			assembly.inputs.Out = []subscription.ComposeOut{out}
		}
	}
	rules, err := selectionRulesTx(tx, ruleRevisions)
	if err != nil {
		return selectionAssembly{}, err
	}
	assembly.inputs.Rules = rules
	for _, deviceID := range deviceIDs {
		var name string
		err := tx.QueryRow(`SELECT display_name FROM mesh_devices WHERE id=?`, deviceID).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(subscription.CodeComposeLineInvalid, "所选组网设备不存在"))
			continue
		}
		if err != nil {
			return selectionAssembly{}, errors.New(CodeDatabaseUnavailable)
		}
		assembly.inputs.Network = append(assembly.inputs.Network, subscription.ComposeNetwork{DeviceID: deviceID, DisplayName: name})
	}
	return assembly, nil
}

// selectionOutTx resolves one selected egress into its operator-visible dial
// parameters. The link credential and the HTTP proxy credentials stay in the
// private tables: a subscription never carries them. An HTTP proxy egress is
// reported with ComposeOutHTTP so the composer, the UI and the selection
// identity can tell the two shapes apart.
func selectionOutTx(tx *sql.Tx, outID string) (subscription.ComposeOut, error) {
	var role, displayName, server, proxyURL string
	var port int
	err := tx.QueryRow(`SELECT n.role, n.display_name,
	  COALESCE(s.server,''), COALESCE(s.port,0), COALESCE(h.url,'')
	  FROM nodes n
	  LEFT JOIN out_settings s ON s.node_id=n.id
	  LEFT JOIN node_http_proxy h ON h.node_id=n.id
	  WHERE n.id=?`, outID).
		Scan(&role, &displayName, &server, &port, &proxyURL)
	if errors.Is(err, sql.ErrNoRows) {
		return subscription.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the egress does not exist")
	}
	if err != nil {
		return subscription.ComposeOut{}, errors.New(CodeDatabaseUnavailable)
	}
	switch role {
	case "out":
		if server == "" || port == 0 {
			return subscription.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the out has no transport")
		}
		return subscription.ComposeOut{OutID: outID, DisplayName: displayName, Server: server, Port: port}, nil
	case "http":
		if proxyURL == "" {
			return subscription.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the http proxy has no URL")
		}
		egress, err := node.ParseHTTPProxyURL(proxyURL)
		if err != nil {
			return subscription.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the http proxy URL is invalid")
		}
		return subscription.ComposeOut{
			OutID: outID, DisplayName: displayName,
			Server: egress.Server, Port: egress.Port, Kind: subscription.ComposeOutHTTP,
		}, nil
	default:
		return subscription.ComposeOut{}, errors.New("OUT_ROLE_INVALID: only out and http nodes can be selected")
	}
}

// selectionRulesTx resolves the pinned rule revisions into composer rules with
// their pinned artifacts.
//
// The pin source comes from the active server policy revision, which is the
// deployment's single artifact lock. A rule that needs an artifact the active
// revision does not pin is refused by the composer with
// COMPOSE_RULESET_UNPINNED, so a subscription can never fetch an unpinned file.
func selectionRulesTx(tx *sql.Tx, revisions []RuleRevision) ([]subscription.ComposeRule, error) {
	if len(revisions) == 0 {
		return []subscription.ComposeRule{}, nil
	}
	pins, err := activePolicyPinsTx(tx)
	if err != nil {
		return nil, err
	}
	out := make([]subscription.ComposeRule, 0, len(revisions))
	for _, revision := range revisions {
		var name, action, kind, raw string
		err := tx.QueryRow(`SELECT name, action, matcher_kind, matcher_value FROM policy_rules WHERE stable_key=? AND version=?`,
			revision.StableKey, revision.Version).Scan(&name, &action, &kind, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("RULE_NOT_FOUND: a selected rule revision no longer exists")
		}
		if err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, errors.New("RULE_INVALID: a stored rule is not readable")
		}
		out = append(out, subscription.ComposeRule{
			StableKey: revision.StableKey,
			Version:   revision.Version,
			Action:    subscription.Action(action),
			Kind:      subscription.MatcherKind(kind),
			Values:    values,
			Pins:      pinsForRule(subscription.MatcherKind(kind), values, pins),
		})
	}
	return out, nil
}

// activePolicyPinsTx reads the pinned artifacts of the active server policy
// revision. No active revision means no pins, so a geo/ruleset rule is refused
// instead of rendering an unversioned reference.
func activePolicyPinsTx(tx *sql.Tx) (policy.RuleSetPins, error) {
	record, _, err := activePolicyIntentTx(tx, PolicyLayerServer)
	if err != nil {
		if isPolicyNotFound(err) {
			return policy.RuleSetPins{}, nil
		}
		return policy.RuleSetPins{}, err
	}
	return decodePolicyPins(record.Pins)
}

// pinsForRule maps the artifact pins of the active revision onto one composer
// rule, keyed by the geo code or the remote tag the rule names.
func pinsForRule(kind subscription.MatcherKind, values []string, pins policy.RuleSetPins) map[string]subscription.RuleSetPin {
	out := make(map[string]subscription.RuleSetPin, len(values))
	for _, value := range values {
		var pin policy.RulesetPin
		var ok bool
		switch kind {
		case subscription.MatcherGeoSite:
			pin, ok = pins.GeoSite[value]
		case subscription.MatcherGeoIP:
			pin, ok = pins.GeoIP[value]
		case subscription.MatcherRuleSet:
			pin, ok = pins.Remote[value]
		default:
			continue
		}
		if !ok {
			continue
		}
		out[value] = subscription.RuleSetPin{Source: pin.Source, Version: pin.Version, SHA256: pin.SHA256}
	}
	return out
}
