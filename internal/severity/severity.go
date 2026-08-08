// Package severity is the single source of truth for finding severities: which
// values are legal, how they order, and how they map onto the numbers other
// formats want.
//
// It exists because three places encoded that knowledge independently and had
// already drifted. internal/engine ranked severities for coalescing and
// lowercased its input; internal/report scored them for SARIF and did not; the
// table printer carried its own inline ordering. So "Critical" ranked as the worst
// severity when two findings were merged, scored 1.0 (the value meaning "least
// severe") in SARIF, and was omitted from the table entirely while still being
// counted in its header.
package severity

import "strings"

// ordered lists every legal severity, worst first. This order is the report's
// grouping order and the basis of Rank.
var ordered = []string{"critical", "high", "medium", "low", "info"}

// sarifScore maps a severity onto GitHub's security-severity tag, a CVSS-like
// number it uses to bucket findings.
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

// Canonical folds a severity to its legal spelling, or returns "" when the value
// is not a severity at all. Callers that must not lose data check for "".
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

// Rank orders severities for comparison, higher being worse. An unrecognized
// value ranks below every legal one rather than tying with "info", so a typo can
// never win a coalescing contest against a real severity.
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

// SARIFScore returns the security-severity value for s. An unrecognized severity
// gets the lowest score, because inventing a high one for a value we do not
// understand would overstate it.
func SARIFScore(s string) string {
	if v, ok := sarifScore[Canonical(s)]; ok {
		return v
	}
	return "1.0"
}

// List renders the legal severities for an error message.
func List() string { return strings.Join(ordered, ", ") }
