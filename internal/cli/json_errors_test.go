package cli

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// TestBuildScanJSON_ErroredRulesAppear: a rule whose RunResult carries an error
// must appear in the JSON output's "errors" array, not vanish. Before this fix,
// errored rules produced no finding and no skip entry, so they were entirely
// absent from the machine-readable output.
func TestBuildScanJSON_ErroredRulesAppear(t *testing.T) {
	doc := buildScanJSON("https://target.example.com", []engine.RunResult{
		{Rule: &rules.Rule{ID: "mcp-x"}, Err: errors.New("executor panicked: nil pointer dereference")},
	})
	errs, ok := doc["errors"].([]map[string]string)
	if !ok {
		t.Fatalf("expected an errors array, got %T: %v", doc["errors"], doc["errors"])
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 errored rule, got %d", len(errs))
	}
	if errs[0]["rule_id"] != "mcp-x" {
		t.Errorf("expected rule_id mcp-x, got %q", errs[0]["rule_id"])
	}
	if errs[0]["error"] == "" {
		t.Error("error message should not be empty")
	}
}

func TestBuildScanJSON_ConfirmedWithoutEvidenceIsIndicator(t *testing.T) {
	doc := buildScanJSON("https://target.example.com", []engine.RunResult{{
		Rule: &rules.Rule{ID: "a2a-test"},
		Findings: []attack.Finding{
			{RuleID: "a2a-test", Confidence: attack.ConfirmedExploit, Title: "Unproven finding"},
			{RuleID: "a2a-test", Evidence: "Observed suspicious response", Title: "Unset confidence"},
		},
	}})
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	var report struct {
		Findings []struct {
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
	for i, finding := range report.Findings {
		if finding.Confidence != "indicator" {
			t.Errorf("finding %d confidence = %q, want indicator", i, finding.Confidence)
		}
	}
}
