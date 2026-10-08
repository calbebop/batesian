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

func TestCoalesceRetainsRelatedFindings(t *testing.T) {
	chain := []attackpkg.ChainStep{{Hop: 1, Principal: "caller", Action: "send token", Outcome: "accepted"}}
	results := []RunResult{
		mkResult("mcp-token-replay-001", attackpkg.Finding{
			Severity: "high", Confidence: attackpkg.RiskIndicator, Title: "signature bypass",
			TargetURL: "https://srv/mcp", Evidence: "unsigned token accepted",
			Remediation: "Verify token signatures.", Chain: chain,
		}),
		mkResult("mcp-oauth-audience-002", attackpkg.Finding{
			Severity: "high", Confidence: attackpkg.ConfirmedExploit, Title: "audience bypass",
			TargetURL: "https://srv/mcp", Evidence: "wrong audience accepted",
			Remediation: "Validate token audience.",
		}),
		mkResult("mcp-token-replay-001", attackpkg.Finding{
			Severity: "medium", Confidence: attackpkg.RiskIndicator, Title: "another token bypass",
			TargetURL: "https://srv/mcp", Evidence: "second token accepted",
			Remediation: "Reject invalid tokens.",
		}),
	}
	out := Coalesce(results)
	if TotalFindings(out) != 1 || len(out[1].Findings) != 1 {
		t.Fatalf("unexpected coalesced results: %+v", out)
	}
	winner := out[1].Findings[0]
	if len(winner.Related) != 2 {
		t.Fatalf("related findings = %+v, want two", winner.Related)
	}
	related := winner.Related[0]
	if related.RuleID != "mcp-token-replay-001" || related.Evidence != "unsigned token accepted" ||
		related.Remediation != "Verify token signatures." || len(related.Chain) != 1 || related.Chain[0] != chain[0] {
		t.Errorf("subsumed details lost: %+v", related)
	}
	if winner.Related[1].Evidence != "second token accepted" || winner.Related[1].Remediation != "Reject invalid tokens." {
		t.Errorf("second subsumed finding lost: %+v", winner.Related[1])
	}
	if winner.Remediation != "Validate token audience." || winner.Evidence == "" {
		t.Errorf("winner details changed: %+v", winner)
	}
	if len(results[1].Findings[0].Related) != 0 || results[1].Findings[0].Evidence != "wrong audience accepted" {
		t.Error("coalescing modified input findings")
	}
	if again := Coalesce(out); len(again[1].Findings[0].Related) != 2 {
		t.Errorf("repeated coalescing duplicated related findings: %+v", again)
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

// TestFindingsBySeverity_FoldsToCanonical: a capitalized severity must fold into
// its canonical (lowercase) bucket. The JSON summary keys FindingsBySeverity by
// lowercase, so without folding a "High" finding lands in its own bucket and the
// summary count disagrees with the findings list.
func TestFindingsBySeverity_FoldsToCanonical(t *testing.T) {
	results := []RunResult{
		mkResult("r1", attackpkg.Finding{RuleID: "a", Severity: "High"}),
		mkResult("r2", attackpkg.Finding{RuleID: "b", Severity: "high"}),
		mkResult("r3", attackpkg.Finding{RuleID: "c", Severity: "CRITICAL"}),
	}
	got := FindingsBySeverity(results)
	if len(got["high"]) != 2 {
		t.Errorf("\"High\" and \"high\" must fold into one canonical \"high\" bucket; got %d", len(got["high"]))
	}
	if len(got["critical"]) != 1 {
		t.Errorf("\"CRITICAL\" must fold into \"critical\"; got %d", len(got["critical"]))
	}
	if _, ok := got["High"]; ok {
		t.Error("a capitalized severity key must not survive canonicalization")
	}
}
