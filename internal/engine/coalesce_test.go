package engine

import (
	"strings"
	"testing"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/rules"
)

func mkResult(ruleID string, f attackpkg.Finding) RunResult {
	f.RuleID = ruleID
	return RunResult{Rule: &rules.Rule{ID: ruleID}, Findings: []attackpkg.Finding{f}}
}

// TestCoalesce_SameClassSameTarget: token-replay (indicator) + oauth-audience
// (confirmed) on the same target collapse to the confirmed one, with a note.
func TestCoalesce_SameClassSameTarget(t *testing.T) {
	results := []RunResult{
		mkResult("mcp-token-replay-001", attackpkg.Finding{Severity: "high", Confidence: attackpkg.RiskIndicator, Title: "replay", TargetURL: "https://srv/mcp", Evidence: "ev1"}),
		mkResult("mcp-oauth-audience-002", attackpkg.Finding{Severity: "high", Confidence: attackpkg.ConfirmedExploit, Title: "aud", TargetURL: "https://srv/mcp", Evidence: "ev2"}),
	}
	out := Coalesce(results)

	if got := TotalFindings(out); got != 1 {
		t.Fatalf("expected 1 finding after coalesce, got %d", got)
	}
	// The survivor must be the confirmed oauth-audience finding.
	var survivor attackpkg.Finding
	for _, r := range out {
		for _, f := range r.Findings {
			survivor = f
		}
	}
	if survivor.RuleID != "mcp-oauth-audience-002" {
		t.Errorf("expected oauth-audience to survive, got %q", survivor.RuleID)
	}
	if !strings.Contains(survivor.Evidence, "Coalesced") || !strings.Contains(survivor.Evidence, "mcp-token-replay-001") {
		t.Errorf("expected subsumed note in evidence, got %q", survivor.Evidence)
	}
}

// TestCoalesce_DifferentTarget: same class but different targets => both kept.
func TestCoalesce_DifferentTarget(t *testing.T) {
	results := []RunResult{
		mkResult("mcp-token-replay-001", attackpkg.Finding{Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://a/mcp"}),
		mkResult("mcp-oauth-audience-002", attackpkg.Finding{Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://b/mcp"}),
	}
	if got := TotalFindings(Coalesce(results)); got != 2 {
		t.Errorf("expected 2 findings across different targets, got %d", got)
	}
}

// TestCoalesce_UnrelatedRules: rules with no class are never merged.
func TestCoalesce_UnrelatedRules(t *testing.T) {
	results := []RunResult{
		mkResult("a2a-task-idor-001", attackpkg.Finding{Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://srv/"}),
		mkResult("a2a-push-ssrf-001", attackpkg.Finding{Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://srv/"}),
	}
	if got := TotalFindings(Coalesce(results)); got != 2 {
		t.Errorf("expected 2 findings for unclassified rules, got %d", got)
	}
}

// TestCoalesce_SingleRuleMultipleFindings: one classified rule firing twice is
// not cross-rule overlap and must not be collapsed.
func TestCoalesce_SingleRuleMultipleFindings(t *testing.T) {
	results := []RunResult{
		{Rule: &rules.Rule{ID: "mcp-token-replay-001"}, Findings: []attackpkg.Finding{
			{RuleID: "mcp-token-replay-001", Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://srv/mcp", Title: "a"},
			{RuleID: "mcp-token-replay-001", Severity: "high", Confidence: attackpkg.ConfirmedExploit, TargetURL: "https://srv/mcp", Title: "b"},
		}},
	}
	if got := TotalFindings(Coalesce(results)); got != 2 {
		t.Errorf("expected both single-rule findings kept, got %d", got)
	}
}
