package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The secret canary evidence window must preserve UTF-8 boundaries.
func TestSnippetAround_NeverSplitsRune(t *testing.T) {
	const needle = "CANARY"
	for _, tc := range []struct {
		name string
		body string
	}{
		{"multibyte both sides", strings.Repeat("é", 30) + needle + strings.Repeat("é", 30)},
		// Even-length prefix + 2-byte chars put the start edge on a continuation
		// byte; 3-byte suffix chars put the end edge on one too, so both window
		// edges land mid-rune.
		{"both edges mid-rune", "aa" + strings.Repeat("é", 25) + needle + strings.Repeat("世", 25)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := snippetAround(tc.body, needle)
			if got == "" {
				t.Fatal("snippetAround returned empty for a present needle")
			}
			if !utf8.ValidString(got) {
				t.Errorf("snippetAround produced invalid UTF-8: %x", got)
			}
		})
	}
}
