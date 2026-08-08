package severity_test

import (
	"testing"

	"github.com/calbebop/batesian/internal/severity"
)

// The three copies this package replaced disagreed on case: one lowercased its
// input, the others compared raw. So "Critical" ranked as the worst severity when
// coalescing and simultaneously scored as the least severe in SARIF.
func TestCanonical_FoldsCaseAndSpace(t *testing.T) {
	for _, in := range []string{"critical", "Critical", "CRITICAL", "  critical  "} {
		if got := severity.Canonical(in); got != "critical" {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, "critical")
		}
	}
	for _, in := range []string{"", "sev1", "urgent", "criticalish"} {
		if got := severity.Canonical(in); got != "" {
			t.Errorf("Canonical(%q) = %q, want \"\" for a non-severity", in, got)
		}
	}
}

// Rank is only ever compared, so the absolute numbers do not matter, but the
// ordering and the treatment of an unknown value do.
func TestRank_OrdersWorstFirstAndSinksUnknown(t *testing.T) {
	ordered := severity.Ordered()
	for i := 1; i < len(ordered); i++ {
		if severity.Rank(ordered[i-1]) <= severity.Rank(ordered[i]) {
			t.Errorf("%q should rank above %q", ordered[i-1], ordered[i])
		}
	}
	// A typo must not beat a real severity when coalescing picks a winner.
	if severity.Rank("sev1") >= severity.Rank("info") {
		t.Error("an unrecognized severity must rank below every real one, including info")
	}
	// Case must not change the rank.
	if severity.Rank("Critical") != severity.Rank("critical") {
		t.Error("Rank must not depend on case")
	}
}

func TestSARIFScore_MatchesCanonicalAndCase(t *testing.T) {
	if severity.SARIFScore("Critical") != severity.SARIFScore("critical") {
		t.Error("SARIFScore must not depend on case; this was the drift against the engine's rank")
	}
	if severity.SARIFScore("critical") == severity.SARIFScore("info") {
		t.Error("critical and info must not score the same")
	}
	if severity.SARIFScore("sev1") != severity.SARIFScore("info") {
		t.Error("an unrecognized severity should score lowest rather than inventing a high one")
	}
}

func TestOrdered_IsACopy(t *testing.T) {
	a := severity.Ordered()
	a[0] = "tampered"
	if severity.Ordered()[0] != "critical" {
		t.Error("Ordered must return a copy so a caller cannot reorder the canonical list")
	}
}
