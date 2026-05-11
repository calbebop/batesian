// Package batesian provides the embedded built-in attack rules.
// The go:embed directive lives here (at the repo root) so that the rules/
// directory remains at the top level of the repository for easy contributor
// discovery and editing, while still being compiled into the binary.
package batesian

import (
	"embed"
	"io/fs"
)

//go:embed all:rules
var rulesEmbedded embed.FS

// RulesFS returns the embedded built-in rules as an fs.FS rooted at "rules/".
// Pass this to rules.LoadFS to load all built-in attack rules.
func RulesFS() fs.FS {
	sub, err := fs.Sub(rulesEmbedded, "rules")
	if err != nil {
		// Only fails if the embed directive is wrong — this is a compile-time invariant.
		panic("batesian: embedded rules directory not found: " + err.Error())
	}
	return sub
}
