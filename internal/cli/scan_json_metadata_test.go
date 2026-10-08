package cli

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

func TestScanJSONMetadataAndOutcomes(t *testing.T) {
	oldVersion, oldCommit, oldDate, oldRootVersion := attack.Version, buildCommit, buildDate, rootCmd.Version
	t.Cleanup(func() {
		attack.Version, buildCommit, buildDate, rootCmd.Version = oldVersion, oldCommit, oldDate, oldRootVersion
	})
	SetVersion("1.8.0", "abc123", "2026-10-08")

	loaded := []*rules.Rule{
		{ID: "mcp-token-replay-001", Info: rules.RuleInfo{Severity: "high"}},
		{ID: "mcp-oauth-audience-002", Info: rules.RuleInfo{Severity: "high"}},
		{ID: "mcp-skipped-001"},
		{ID: "mcp-error-001"},
		{ID: "mcp-clean-001"},
		{ID: "mcp-unselected-001"},
	}
	executed := []engine.RunResult{
		{Rule: loaded[0], Findings: []attack.Finding{{
			RuleID: loaded[0].ID, Severity: "high", Confidence: attack.RiskIndicator,
			TargetURL: "https://target.example/mcp", Evidence: "unsigned token accepted",
		}}},
		{Rule: loaded[1], Findings: []attack.Finding{{
			RuleID: loaded[1].ID, Severity: "high", Confidence: attack.ConfirmedExploit,
			TargetURL: "https://target.example/mcp", Evidence: "wrong audience accepted",
		}}},
		{Rule: loaded[2], Skipped: true, SkipMsg: "missing prerequisite"},
		{Rule: loaded[3], Err: errors.New("probe failed")},
		{Rule: loaded[4]},
	}
	doc, err := buildScanJSON(scanJSONInput{
		Target: "https://target.example/mcp", Reported: engine.Coalesce(executed),
		Outcomes: buildRuleOutcomes(executed), Loaded: loaded, Supplemental: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc["schema_version"] != scanJSONSchemaVersion {
		t.Errorf("schema version = %v", doc["schema_version"])
	}
	scanner := doc["scanner"].(scanJSONScanner)
	if scanner.Name != "batesian" || scanner.Version != "1.8.0" || scanner.Commit != "abc123" || scanner.BuildDate != "2026-10-08" {
		t.Errorf("scanner = %+v", scanner)
	}
	ruleset := doc["ruleset"].(scanJSONRuleset)
	if ruleset.Source != "builtin+supplemental" || ruleset.Loaded != 6 || ruleset.Selected != 5 || len(ruleset.SHA256) != 64 {
		t.Errorf("ruleset = %+v", ruleset)
	}
	outcomes := doc["rule_outcomes"].([]scanJSONRuleOutcome)
	if len(outcomes) != 5 {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	for i, want := range []scanJSONRuleOutcome{
		{RuleID: loaded[0].ID, Status: "findings", FindingCount: 1},
		{RuleID: loaded[1].ID, Status: "findings", FindingCount: 1},
		{RuleID: loaded[2].ID, Status: "skipped", Reason: "missing prerequisite"},
		{RuleID: loaded[3].ID, Status: "error", Error: "probe failed"},
		{RuleID: loaded[4].ID, Status: "no_findings"},
	} {
		if outcomes[i] != want {
			t.Errorf("outcome %d = %+v, want %+v", i, outcomes[i], want)
		}
	}
	if doc["summary"].(map[string]int)["total"] != 1 {
		t.Errorf("coalesced summary = %v", doc["summary"])
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		SchemaVersion int                   `json:"schema_version"`
		Scanner       scanJSONScanner       `json:"scanner"`
		Ruleset       scanJSONRuleset       `json:"ruleset"`
		RuleOutcomes  []scanJSONRuleOutcome `json:"rule_outcomes"`
		Findings      []json.RawMessage     `json:"findings"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.SchemaVersion != 1 || wire.Scanner.Version != "1.8.0" || wire.Ruleset.Selected != 5 ||
		len(wire.RuleOutcomes) != 5 || len(wire.Findings) != 1 {
		t.Errorf("unexpected JSON fields: %s", body)
	}
}

func TestRuleCatalogSHA256StableAcrossOrder(t *testing.T) {
	a := &rules.Rule{ID: "a", Info: rules.RuleInfo{Severity: "high"}}
	b := &rules.Rule{ID: "b", Info: rules.RuleInfo{Severity: "low"}}
	duplicateID := &rules.Rule{ID: "a", Info: rules.RuleInfo{Severity: "medium"}}
	first, err := ruleCatalogSHA256([]*rules.Rule{a, b, duplicateID})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := ruleCatalogSHA256([]*rules.Rule{duplicateID, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if first != reordered {
		t.Errorf("catalog hash changed with rule order: %s != %s", first, reordered)
	}
	b.Info.Severity = "medium"
	changed, err := ruleCatalogSHA256([]*rules.Rule{a, b, duplicateID})
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Errorf("catalog hash did not reflect rule content: %s vs %s", first, changed)
	}
}
