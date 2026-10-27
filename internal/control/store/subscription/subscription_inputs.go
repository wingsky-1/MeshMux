package subscription

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

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// selectionInputs is the pure composer's input set for one selection.
type selectionInputs struct {
	Lines   []coredomain.ComposeLine
	Out     []coredomain.ComposeOut
	Rules   []coredomain.ComposeRule
	Network []coredomain.ComposeNetwork
}

// selectionAssembly is the read result of one selection: the composer inputs
// plus any non-fatal finding (layer-3 diagnostics) the read already knows.
type selectionAssembly struct {
	inputs      selectionInputs
	diagnostics []coredomain.Diagnostic
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
func assembleSelectionTx(tx *sql.Tx, lineIDs []string, credentials []coredomain.Credential, outID string, ruleRevisions []RuleRevision, deviceIDs []string) (selectionAssembly, error) {
	assembly := selectionAssembly{}
	for index, nodeID := range lineIDs {
		line, err := downloadLineTx(tx, nodeID)
		if err != nil {
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(coredomain.CodeComposeLineInvalid, "所选 Line 已不可用"))
			continue
		}
		if index >= len(credentials) {
			return selectionAssembly{}, errors.New(CodeSelectionInvalid + ": a selected line has no credential")
		}
		assembly.inputs.Lines = append(assembly.inputs.Lines, coredomain.ComposeLine{Line: publicLine(line), Credential: credentials[index]})
	}
	if outID != "" {
		out, err := selectionOutTx(tx, outID)
		if err != nil {
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(coredomain.CodeComposeOutInvalid, "所选 Out 已不可用或未配置出口地址"))
		} else {
			assembly.inputs.Out = []coredomain.ComposeOut{out}
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
			assembly.diagnostics = append(assembly.diagnostics, blockingDiagnostic(coredomain.CodeComposeLineInvalid, "所选组网设备不存在"))
			continue
		}
		if err != nil {
			return selectionAssembly{}, errors.New(common.CodeDatabaseUnavailable)
		}
		assembly.inputs.Network = append(assembly.inputs.Network, coredomain.ComposeNetwork{DeviceID: deviceID, DisplayName: name})
	}
	return assembly, nil
}

// selectionOutTx resolves one selected egress into the material the client
// documents carry.
//
// Under client-chain egress the subscriber's client dials the egress itself, so
// the artifact needs the dial body plus the bearer credential: the SS link key
// of a managed Out, or the Basic pair of an external HTTP proxy. Both are
// secrets of the same class as the per-Line VLESS UUID — protected by the
// subscription bearer URL and never logged. An HTTP proxy is reported with
// ComposeOutHTTP so the composer, the UI and the selection identity can tell the
// two shapes apart.
func selectionOutTx(tx *sql.Tx, outID string) (coredomain.ComposeOut, error) {
	var role, displayName, server, linkKey, proxyURL string
	var username, password sql.NullString
	var port int
	err := tx.QueryRow(`SELECT n.role, n.display_name,
	  COALESCE(s.server,''), COALESCE(s.port,0), COALESCE(s.link_key,''), COALESCE(h.url,''),
	  h.username, h.password
	  FROM nodes n
	  LEFT JOIN out_settings s ON s.node_id=n.id
	  LEFT JOIN node_http_proxy h ON h.node_id=n.id
	  WHERE n.id=?`, outID).
		Scan(&role, &displayName, &server, &port, &linkKey, &proxyURL, &username, &password)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the egress does not exist")
	}
	if err != nil {
		return coredomain.ComposeOut{}, errors.New(common.CodeDatabaseUnavailable)
	}
	switch role {
	case "out":
		if server == "" || port == 0 {
			return coredomain.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the out has no transport")
		}
		if linkKey == "" {
			return coredomain.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the out has no link key")
		}
		return coredomain.ComposeOut{OutID: outID, DisplayName: displayName, Server: server, Port: port, LinkKey: linkKey}, nil
	case "http":
		if proxyURL == "" {
			return coredomain.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the http proxy has no URL")
		}
		egress, err := nodedomain.ParseHTTPProxyURL(proxyURL)
		if err != nil {
			return coredomain.ComposeOut{}, errors.New("OUT_NOT_CONFIGURED: the http proxy URL is invalid")
		}
		return coredomain.ComposeOut{
			OutID: outID, DisplayName: displayName,
			Server: egress.Server, Port: egress.Port, Kind: coredomain.ComposeOutHTTP,
			Username: username.String, Password: password.String,
		}, nil
	default:
		return coredomain.ComposeOut{}, errors.New("OUT_ROLE_INVALID: only out and http nodes can be selected")
	}
}

// selectionRulesTx resolves the selected rule revisions into composer rules.
//
// A rule is assembled exactly as configured: the Hub performs no artifact check
// here. The pinned-artifact model is gone, so a selected geo/ruleset rule is
// rendered from its stored values and the client kernel resolves the artifact;
// the rule library's own write path already validated the matcher shape.
func selectionRulesTx(tx *sql.Tx, revisions []RuleRevision) ([]coredomain.ComposeRule, error) {
	if len(revisions) == 0 {
		return []coredomain.ComposeRule{}, nil
	}
	out := make([]coredomain.ComposeRule, 0, len(revisions))
	for _, revision := range revisions {
		var name, action, kind, raw string
		err := tx.QueryRow(`SELECT name, action, matcher_kind, matcher_value FROM policy_rules WHERE stable_key=? AND version=?`,
			revision.StableKey, revision.Version).Scan(&name, &action, &kind, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("RULE_NOT_FOUND: a selected rule revision no longer exists")
		}
		if err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, errors.New("RULE_INVALID: a stored rule is not readable")
		}
		out = append(out, coredomain.ComposeRule{
			StableKey: revision.StableKey,
			Version:   revision.Version,
			Action:    coredomain.Action(action),
			Kind:      coredomain.MatcherKind(kind),
			Values:    values,
		})
	}
	return out, nil
}
