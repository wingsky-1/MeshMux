package install

// The installer's own path vocabulary (Caddyfile, Headscale config, Fail2ban
// jail and filter directories, the journald drop-in, the Hub dispatch units and
// the upgrade-claim record) is owned by install/core's paths.go.
//
// It is deliberately not re-exported here: every one of those paths is read or
// written by the installer engine only, and no caller outside this tree may
// name a MeshMux-owned host path. The few paths another package legitimately
// needs (the installer root, the runtime binary, the Web unit) come from
// internal/cli/versions, which remains the single shared source.
