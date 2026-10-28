// Package hub installs the Hub role: Caddy, Headscale, the MeshMux Web unit,
// the Fail2ban SSH jail and the root-dispatch path unit of the self-upgrade.
//
// It owns the Hub-only preflight policy (Debian 13, port ownership, managed
// listener reuse) and the rendered Caddyfile, Headscale config and unit files.
// The shared engine (ledger, artifacts, lock, journal, file apply primitives)
// comes from install/core; this package never imports the Node channel.
//
// InstallHub is the only host-mutation entry the CLI calls. It runs
// preflight -> stage -> apply -> verify, writes the terminal ledger and returns
// one InstallResult carrying the stage, the stable error code and the recovery
// action.
package hub
