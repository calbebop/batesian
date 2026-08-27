package cli

import (
	"encoding/json"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/severity"
)

// TestCanonicalOrRaw pins the fallback: known severities fold to canonical
// spelling; anything else comes back verbatim rather than as an empty string
// (an output site collapsing "Critical" to "" would erase the severity).
func TestCanonicalOrRaw(t *testing.T) {
	cases := []struct{ in, want string }{
		{"critical", "critical"},
		{"Critical", "critical"},
		{"  HIGH  ", "high"},
		{"sev1", "sev1"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := severity.CanonicalOrRaw(tc.in); got != tc.want {
			t.Errorf("CanonicalOrRaw(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func findingWithSeverity(sev string) attack.Finding {
	return attack.Finding{
		RuleID:   "test-rule-001",
		Severity: sev,
		Title:    "t",
	}
}

// TestBuildSummary_SumsToTotalWithUnknown pins the property the unknown
// bucket exists for: executors set severity as a plain string, so a value
// nothing validates used to be counted in total while vanishing from every
// bucket. The buckets must always sum to total.
func TestBuildSummary_SumsToTotalWithUnknown(t *testing.T) {
	results := []engine.RunResult{
		{Findings: []attack.Finding{
			findingWithSeverity("critical"),
			findingWithSeverity("high"),
			findingWithSeverity("High"), // folds with the one above
			findingWithSeverity("info"),
			findingWithSeverity("sev1"), // unknown
		}},
		{Findings: []attack.Finding{
			findingWithSeverity("low"),
		}},
	}

	summary := buildSummary(results)
	if summary["total"] != 6 {
		t.Fatalf("total = %d, want 6", summary["total"])
	}
	if summary["critical"] != 1 || summary["high"] != 2 || summary["info"] != 1 || summary["low"] != 1 {
		t.Fatalf("canonical buckets wrong: %+v", summary)
	}
	if summary["unknown"] != 1 {
		t.Fatalf("unknown bucket = %d, want 1 (the sev1 finding)", summary["unknown"])
	}

	sum := 0
	for _, k := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		sum += summary[k]
	}
	if sum != summary["total"] {
		t.Fatalf("buckets sum to %d, want total %d: %+v", sum, summary["total"], summary)
	}
}

// TestBuildSummary_AllKnownOmitsUnknown: the unknown key is absent when every
// finding has a known severity, so consumers never see a zero-count noise
// bucket.
func TestBuildSummary_AllKnownOmitsUnknown(t *testing.T) {
	results := []engine.RunResult{
		{Findings: []attack.Finding{findingWithSeverity("high")}},
	}
	summary := buildSummary(results)
	if _, present := summary["unknown"]; present {
		t.Fatalf("unknown bucket must be omitted when empty: %+v", summary)
	}
}

// TestBuildSummaryMarshal_JSONStable: the summary must serialize without
// map-order surprises, since scripts diff scan outputs.
func TestBuildSummaryMarshal_JSONStable(t *testing.T) {
	summary := buildSummary([]engine.RunResult{
		{Findings: []attack.Finding{findingWithSeverity("high")}},
	})
	b, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys []string
	if err := json.Unmarshal(b, &keys); err == nil {
		t.Fatalf("expected object, got array: %s", b)
	}
	var doc map[string]int
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["high"] != 1 || doc["total"] != 1 {
		t.Fatalf("round-trip mismatch: %s", b)
	}
}
