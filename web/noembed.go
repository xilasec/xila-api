//go:build !embedfrontend

package web

import "io/fs"

// Assets returns no embedded assets in the default build: the UI is served
// separately (e.g. `pnpm dev`). Build with -tags embedfrontend to bundle it.
func Assets() (fs.FS, bool) { return nil, false }
