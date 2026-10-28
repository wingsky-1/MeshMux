package hub

import "github.com/wingsky-1/MeshMux/internal/cli/install/core"

// The journald drop-in bytes are shared with the Node channel, so the constant
// is owned by install/core and forwarded here next to the Hub renderers that
// write it. The rationale for the three quota keys is documented on the core
// constant; nothing about them is Hub-specific.
const JournaldDropIn = core.JournaldDropIn
