package upgrade

// Read-only Hub self-upgrade projection for the /tasks page (#11d, spec
// §5.4/§5.5/§5.11).
//
// The journal is the authority (D3): no mirror table is queried, and no
// directory under database-backup/ is scanned to guess the current record. The
// filesystem and process-owner reads happen here, in the handler, and are
// mapped into view.HubUpgradeView; the view package owns only the struct and
// the operator-facing wording.

import (
	"os"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/control/store"
	"github.com/wingsky-1/MeshMux/internal/web/view"
)

// hubUpgradeView reads the Hub upgrade facts for one page render.
func (app *Server) hubUpgradeView(now time.Time) view.HubUpgradeView {
	block := view.HubUpgradeView{Identity: app.hubIdentity(now)}
	owner := os.Geteuid()
	ops, err := hubupgrade.ListOps(app.Store.Dir, owner)
	if err != nil {
		block.Err = store.ErrorCodeOf(err)
		return block
	}
	if op, ok := newestUpdateOp(ops); ok {
		block.Op, block.HasOp = op, true
		if op.State == hubupgrade.StateBackingUp || op.State == hubupgrade.StateBackedUp {
			block.ExpiresAt = op.UpdatedAt.Add(hubupgrade.OrphanTimeout)
		}
		result, ok, err := hubupgrade.ReadResult(app.hubResultsDirValue(), op.OperationID)
		switch {
		case err != nil:
			block.ResultErr = store.ErrorCodeOf(err)
		case ok:
			block.Result, block.HasResult = result, true
		}
	}
	if _, record, ok, err := hubupgrade.LatestBackup(app.Store.Dir, owner); err == nil && ok {
		block.Record, block.HasRecord = record, true
	} else if err != nil && block.Err == "" {
		block.Err = store.ErrorCodeOf(err)
	}
	if marker, ok, err := hubupgrade.ReadRestoredMarker(app.Store.Dir); err == nil && ok {
		block.Restored, block.HasRestored = marker, true
	} else if err != nil && block.Err == "" {
		block.Err = store.ErrorCodeOf(err)
	}
	return block
}

// newestUpdateOp is the journal's current update operation: the highest backup
// generation, then the newest update time. It is journal-backed, so an
// operation directory no journal names can never become "current".
func newestUpdateOp(ops []hubupgrade.Op) (hubupgrade.Op, bool) {
	var newest hubupgrade.Op
	found := false
	for _, op := range ops {
		if op.Kind != hubupgrade.KindUpdate {
			continue
		}
		switch {
		case !found,
			op.BackupGeneration > newest.BackupGeneration,
			op.BackupGeneration == newest.BackupGeneration && op.UpdatedAt.After(newest.UpdatedAt):
			newest, found = op, true
		}
	}
	return newest, found
}
