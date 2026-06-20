package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTruncateRunes_MultibyteStaysValid is the regression guard: byte-index
// truncation can cut a multibyte rune mid-sequence and emit invalid UTF-8. The
// output must always be valid UTF-8 and within the byte budget.
func TestTruncateRunes_MultibyteStaysValid(t *testing.T) {
	s := strings.Repeat("世", 60) // 180 bytes; each rune is 3 bytes
	for _, max := range []int{4, 10, 11, 12, 13, 80, 179} {
		out := truncateRunes(s, max)
		if !utf8.ValidString(out) {
			t.Errorf("truncateRunes(max=%d) produced invalid UTF-8: %q", max, out)
		}
		if len(out) > max {
			t.Errorf("truncateRunes(max=%d) len=%d exceeds budget", max, len(out))
		}
	}
}

func TestTruncateRunes_ShortStringUnchanged(t *testing.T) {
	if got := truncateRunes("héllo", 80); got != "héllo" {
		t.Errorf("short string changed: %q", got)
	}
}

func TestTruncateRunes_ASCIIEllipsis(t *testing.T) {
	got := truncateRunes(strings.Repeat("a", 100), 10)
	if want := strings.Repeat("a", 7) + "..."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if len(got) != 10 {
		t.Errorf("len=%d, want 10", len(got))
	}
}

func TestTruncate_CollapsesNewlines(t *testing.T) {
	if got := truncate("a\nb\nc", 80); got != "a b c" {
		t.Errorf("newlines not collapsed: %q", got)
	}
}
