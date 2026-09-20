// Package severity defines valid finding severities, ordering, and output scores.
package severity

import "strings"

// ordered lists legal severities from worst to least severe.
var ordered = []string{"critical", "high", "medium", "low", "info"}

// sarifScore maps severities to GitHub security-severity values.
var sarifScore = map[string]string{
	"critical": "9.5",
	"high":     "7.5",
	"medium":   "5.0",
	"low":      "3.0",
	"info":     "1.0",
}

// Ordered returns the legal severities, worst first.
func Ordered() []string {
	out := make([]string, len(ordered))
	copy(out, ordered)
	return out
}

// Canonical returns the normalized severity, or "" for an unknown value.
func Canonical(s string) string {
	folded := strings.ToLower(strings.TrimSpace(s))
	for _, k := range ordered {
		if folded == k {
			return k
		}
	}
	return ""
}

// Valid reports whether s names a severity, ignoring case and surrounding space.
func Valid(s string) bool { return Canonical(s) != "" }

// CanonicalOrRaw preserves unknown severity values for output.
func CanonicalOrRaw(s string) string {
	if c := Canonical(s); c != "" {
		return c
	}
	return s
}

// Rank orders severities with higher values being worse. Unknown values rank 0.
func Rank(s string) int {
	c := Canonical(s)
	if c == "" {
		return 0
	}
	for i, k := range ordered {
		if k == c {
			return len(ordered) - i
		}
	}
	return 0
}

// SARIFScore returns the security-severity value for s, defaulting to 1.0.
func SARIFScore(s string) string {
	if v, ok := sarifScore[Canonical(s)]; ok {
		return v
	}
	return "1.0"
}

// List renders the legal severities for an error message.
func List() string { return strings.Join(ordered, ", ") }
