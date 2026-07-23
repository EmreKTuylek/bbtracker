package server

import "embed"

// staticFS embeds the vanilla-JS frontend (no build step). Files live in
// ./static and are served as-is by http.FileServerFS.
//
//go:embed all:static
var staticFS embed.FS
