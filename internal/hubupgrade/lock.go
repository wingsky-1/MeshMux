package hubupgrade

// The one in-process flat-slot lock of the Web process (#11d Task 3, Task-1
// carry 2).
//
// internal/backup's flat reader is not read-only: every entry runs
// recoverFlatSlot, which renames payload.trash-* back over payload/ when the
// record still names the retired copy. If a Web read interleaves with a
// publish, the reader can displace the payload the publisher just renamed into
// place and then a record can name bytes that are no longer there — a permanent
// record/payload mismatch that only manual repair resolves. "Read" and "write"
// are therefore one critical section.
//
// The lock lives in this package because it is the shared leaf the Web process
// already imports for the Hub upgrade surface: the producer (CreateBackup) takes
// it here, and internal/web takes the same mutex around its approval read/write
// and, in Task 7, its /tasks read of the flat backup record. Putting a copy in
// each caller would recreate the race the moment one of them forgot.
//
// The lock is process-local by design. Cross-process exclusion is already
// guaranteed by the store's data-directory flock: only one meshmux Web process
// can own a data directory. It is not re-entrant: CreateBackup takes it once,
// and a caller that holds it must not call CreateBackup.

import "sync"

var flatSlotMu sync.Mutex

// LockFlatSlot acquires the process-wide flat backup-slot lock and returns its
// unlock function. Every access to <data-dir>/database-backup — producer,
// approval, restore gate and page read — must hold it for the whole read or
// write, including the record layer's recovery step.
func LockFlatSlot() func() {
	flatSlotMu.Lock()
	return flatSlotMu.Unlock
}
