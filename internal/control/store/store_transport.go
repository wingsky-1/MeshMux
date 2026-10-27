package store

// Fixed values of the store's own transport and lifetime contract.
//
// Each appears exactly once and is referenced by name:
//   - session lifetime, idle lifetime and the authentication budget are the
//     security contract of the single administrator session;
//   - the SQLite DSN pragmas are the durability boundary (WAL, FULL sync,
//     foreign keys, busy timeout);
//   - the offline window is shared by every projection that reports whether a
//     node is currently contacting the Hub.
//
// A port, timeout or pragma number must never be re-typed at a call site: a
// change here has to move every reader at once, or the store silently runs two
// durability policies.

import (
	"strconv"
	"time"
)

const (
	// sessionLifetime is the absolute lifetime of one authenticated session.
	sessionLifetime = 8 * time.Hour
	// idleLifetime is the inactivity window after which a session is expired.
	idleLifetime = 30 * time.Minute
	// authWindow is the rolling window of the durable global authentication
	// budget. It opens at the first attempt and is measured from that instant,
	// so spending a slot never extends the lockout and restarting the service
	// does not clear it.
	authWindow = 10 * time.Minute
	// authBudget is the number of attempts one authWindow permits.
	authBudget = 10

	// SessionLifetime is the exported session lifetime the Web layer renders.
	SessionLifetime = sessionLifetime

	// OfflineAfter is the window after which a node that stopped contacting the
	// Hub is reported offline. Every node, Out and subscriber projection reads
	// this value.
	OfflineAfter = 2 * time.Minute
)

// SQLite DSN pragmas. They are the store's durability contract: one writer, WAL
// journal, FULL synchronous commit, enforced foreign keys and a bounded busy
// wait. They are assembled in one place so no caller can open the database with
// a weaker policy, and the timeout appears once.
const (
	sqliteBusyTimeoutMS = 5000
)

// sqliteDSNPragmas is the exact query string appended to the database path.
func sqliteDSNPragmas() string {
	return "?_pragma=busy_timeout(" + strconv.Itoa(sqliteBusyTimeoutMS) + ")" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)"
}
