//go:build embedfrontend

// Package web optionally embeds the built SvelteKit SPA so the API binary can
// serve the UI and the API from one artifact. Build with -tags embedfrontend
// after `pnpm build` has produced web/build (see `make bundle`).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:build
var buildFS embed.FS

// Assets returns the embedded SPA file system.
func Assets() (fs.FS, bool) {
	sub, err := fs.Sub(buildFS, "build")
	if err != nil {
		return nil, false
	}
	return sub, true
}
