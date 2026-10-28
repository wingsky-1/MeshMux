package core

// The journald drop-in is the only logging configuration MeshMux writes. Before
// it existed, journal rotation depended entirely on the host default, so a
// long-lived Hub or Line could grow the journal until it filled a small VPS.
//
// The drop-in deliberately contains quota keys only. Journal storage location,
// forwarding, rate limits and per-unit settings stay with the distribution's
// /etc/systemd/journald.conf and its own drop-ins; that file is never
// rewritten, so the host's logging policy is never taken over. The three values
// are one source of truth for both roles and render byte-identically for a Hub
// and a standalone Line.
//
// journald reads its configuration at start only (systemd-journald has no
// reload action), so the quota takes effect when journald next starts. The
// installer writes the file as a managed, ledgered, atomically replaced and
// rollback-covered target and never restarts the host's logging daemon
// mid-operation.
//
// Sizing: SystemMaxUse=1G keeps a single-admin host's persistent journal well
// under the 10%-of-filesystem default that a small disk would otherwise hand
// out, while still holding roughly a month of structured MeshMux logs;
// RuntimeMaxUse=512M keeps the volatile journal far below the 10%-of-/run
// default; MaxFileSec=30day rotates one file per month so a single journal file
// stays small enough to grep instead of growing for the whole retention window.
const JournaldDropIn = `# MeshMux-owned journald quota. It caps the host journal so MeshMux services
# cannot fill the filesystem; storage, forwarding, rate limits and per-unit
# settings stay with the distribution and the operator. Takes effect when
# systemd-journald next starts.
[Journal]
SystemMaxUse=1G
RuntimeMaxUse=512M
MaxFileSec=30day
`
