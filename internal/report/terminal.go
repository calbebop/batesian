package report

import (
	"fmt"
	"strings"
	"unicode"
)

// EscapeTerminal makes untrusted text safe for human-readable output.
func EscapeTerminal(s string) string {
	var out strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			if r <= 0xFFFF {
				fmt.Fprintf(&out, "\\u%04X", r)
			} else {
				fmt.Fprintf(&out, "\\U%08X", r)
			}
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}
