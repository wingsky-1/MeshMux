package common

// The subscriber-level synchronization vocabulary and its code sanitizer.
//
// Three projections report a subscriber state (the subscriber page, the Line
// readback and the Out readback), so the three state names and the sanitizer
// live in the leaf rather than in any one of them.

import (
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// The subscriber-level synchronization summary.
const (
	SubscriberSyncHealthy = "healthy"
	SubscriberSyncPending = "pending"
	SubscriberSyncPartial = "partial"
)

// SyncErrorCodePattern bounds a sanitized status code. Anything else is
// replaced by a generic code, so an internal message can never reach the UI.
//
// The expression is the cross-layer stable-code grammar of internal/versions
// (the Web launcher, the root restore parser and the Node handoff read the same
// one); exposing it under this name keeps the sync projection's contract
// explicit without compiling a second copy.
var SyncErrorCodePattern = versions.StableCodePattern

// SanitizeSyncCode keeps only the stable code part of an error.
func SanitizeSyncCode(raw string) string {
	code := strings.TrimSpace(raw)
	if index := strings.Index(code, ":"); index > 0 {
		code = strings.TrimSpace(code[:index])
	}
	if !SyncErrorCodePattern.MatchString(code) {
		return "SYNC_FAILED"
	}
	return code
}
