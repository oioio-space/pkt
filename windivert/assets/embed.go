//go:build windows

// Package assets embeds the WinDivert kernel driver binary.
package assets

import _ "embed"

// Sys64 contains the WinDivert64.sys driver binary (v2.2.2, x64).
//
//go:embed WinDivert64.sys
var Sys64 []byte
