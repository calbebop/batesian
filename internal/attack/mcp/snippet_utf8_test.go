package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// oneLine and snippetAround build Finding.Evidence from the scanned target's raw
// response, which is marshalled to JSON and SARIF. A byte-offset cut that splits
// a multibyte rune becomes U+FFFD there, corrupting the evidence. These pin the
// rune-safety that the #90 truncation fix established and that the two helpers
// had re-introduced by slicing on a raw byte index.

func TestOneLine_NeverSplitsRune(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    string
	}{
		{"ascii under limit", strings.Repeat("a", 50)},
		{"ascii over limit", strings.Repeat("a", 250)},
		// "a" + 100 "é" (2 bytes each) is 201 bytes, so the cut at 200 lands on a
		// continuation byte unless it is backed to a rune boundary.
		{"multibyte cut mid-rune", "a" + strings.Repeat("é", 100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := oneLine(tc.s)
			if !utf8.ValidString(got) {
				t.Errorf("oneLine produced invalid UTF-8: %x", got)
			}
			if len(tc.s) > 200 && !strings.HasSuffix(got, "...") {
				t.Errorf("oneLine dropped the truncation marker on a long input: %q", got)
			}
		})
	}
}

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
