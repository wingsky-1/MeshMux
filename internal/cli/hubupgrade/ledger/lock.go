package ledger

// The one in-process producer mutex of the Web process (#11d Task 3r, spec
// §5.2).
//
// `Busy() → nextBackupGeneration() → WriteOp(backing_up)` is a check-then-act:
// two concurrent `POST /tasks/hub-upgrade/backup` requests could both read "not
// busy", both take the same max+1 generation, and single-flight would be
// bypassed with two operations at one generation. The Web is concurrent
// (net/http runs one goroutine per request), so this process-wide mutex must
// cover exactly that read-read-write triple.
//
// Its scope is deliberately narrow. VACUUM, the binary stage, the per-operation
// record commit and the pointer refresh all write only the operation's own
// directory, so they run outside it. Readers never take it: per-operation
// records are only ever replaced by rename, which the Node store already proved
// safe to read without a lock, and there is no flat slot to reconcile. It is
// also not re-entrant — a holder must not call CreateBackup.
//
// Cross-process exclusion is not this mutex's job: the store's data-directory
// flock already guarantees that one meshmux Web process owns a data directory.

import "sync"

var backupProduceMu sync.Mutex

// LockBackupProduce acquires the process-wide producer mutex and returns its
// unlock function. It covers only the producer's Busy read, generation read and
// backing_up write; approve, /tasks reads, confirm and the dispatcher must not
// take it.
func LockBackupProduce() func() {
	backupProduceMu.Lock()
	return backupProduceMu.Unlock
}
