package engine

import (
	"context"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/rules"
)

type confidenceExecutor struct{ findings []attack.Finding }

func (e confidenceExecutor) Execute(context.Context, string, attack.Options) ([]attack.Finding, error) {
	return e.findings, nil
}

func TestRunOne_RequiresEvidenceForConfirmed(t *testing.T) {
	rule := &rules.Rule{ID: "test-rule"}
	findings := []attack.Finding{
		{Confidence: attack.ConfirmedExploit, Evidence: "Observed unauthorized task read"},
		{Confidence: attack.ConfirmedExploit, Evidence: " \n"},
		{Evidence: "Observed suspicious response"},
	}
	result := New(attack.Options{}).runOne(t.Context(), "https://target.example.com",
		planEntry{rule: rule, executor: confidenceExecutor{findings}}, attack.NewBlackboard())
	if result.Err != nil || len(result.Findings) != len(findings) {
		t.Fatalf("runOne returned %+v", result)
	}
	want := []attack.Confidence{attack.ConfirmedExploit, attack.RiskIndicator, attack.RiskIndicator}
	for i, f := range result.Findings {
		if f.Confidence != want[i] {
			t.Errorf("finding %d confidence = %q, want %q", i, f.Confidence, want[i])
		}
	}
}

func TestCoalesce_EmptyEvidenceCannotWinConfirmed(t *testing.T) {
	results := []RunResult{
		{Rule: &rules.Rule{ID: "mcp-token-replay-001"}, Findings: []attack.Finding{{
			RuleID: "mcp-token-replay-001", TargetURL: "https://target.example.com/mcp",
			Severity: "critical", Confidence: attack.ConfirmedExploit,
		}}},
		{Rule: &rules.Rule{ID: "mcp-oauth-audience-002"}, Findings: []attack.Finding{{
			RuleID: "mcp-oauth-audience-002", TargetURL: "https://target.example.com/mcp",
			Severity: "high", Confidence: attack.ConfirmedExploit, Evidence: "Observed invalid audience accepted",
		}}},
	}
	out := Coalesce(results)
	if TotalFindings(out) != 1 || len(out[1].Findings) != 1 || out[1].Findings[0].Confidence != attack.ConfirmedExploit {
		t.Fatalf("evidence-backed finding did not win: %+v", out)
	}
	if results[0].Findings[0].Confidence != attack.ConfirmedExploit {
		t.Error("Coalesce modified its input")
	}
}
