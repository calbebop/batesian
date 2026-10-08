package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func sarifFixture() []engine.RunResult {
	r := &rules.Rule{}
	r.ID = "mcp-test-001"
	r.Info.Name = "Test Rule"
	r.Info.Severity = "high"
	return []engine.RunResult{{
		Rule: r,
		Findings: []attack.Finding{{
			RuleID:      "mcp-test-001",
			RuleName:    "Test Rule",
			Severity:    "high",
			Confidence:  attack.ConfirmedExploit,
			Title:       "Test finding",
			Description: "Test description",
			Evidence:    "Observed unauthorized task read",
			TargetURL:   "https://agent.example.com/mcp",
		}},
	}}
}

func TestWriteSARIF_ConfirmedWithoutEvidenceIsIndicator(t *testing.T) {
	results := sarifFixture()
	results[0].Findings[0].Evidence = ""
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if got := doc.Runs[0].Results[0].Properties["confidence"]; got != "indicator" {
		t.Errorf("evidence-free finding confidence = %q, want indicator", got)
	}
}

type sarifDoc struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful *bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				AssociatedRule *struct {
					ID string `json:"id"`
				} `json:"associatedRule"`
			} `json:"toolExecutionNotifications"`
			Properties struct {
				Selected  int `json:"rulesSelected"`
				Completed int `json:"rulesCompleted"`
				Skipped   int `json:"rulesSkipped"`
				Errored   int `json:"rulesErrored"`
			} `json:"properties"`
		} `json:"invocations"`
		Results []struct {
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation map[string]any `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func TestWriteSARIF_AbsoluteURIHasNoUriBaseId(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, sarifFixture(), "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// Guard against the literal markers slipping back into the output.
	if strings.Contains(buf.String(), "uriBaseId") || strings.Contains(buf.String(), "SRCROOT") {
		t.Fatalf("SARIF must not contain uriBaseId/SRCROOT for an absolute target URI:\n%s", buf.String())
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 || len(doc.Runs[0].Results[0].Locations) != 1 {
		t.Fatalf("expected one run with one located result, got: %+v", doc)
	}

	al := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if al["uri"] != "https://agent.example.com/mcp" {
		t.Errorf("artifactLocation.uri = %v, want the absolute target URL", al["uri"])
	}
	if _, present := al["uriBaseId"]; present {
		t.Errorf("artifactLocation must not contain uriBaseId for an absolute URI, got: %v", al)
	}
	invocation := doc.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful == nil || !*invocation.ExecutionSuccessful {
		t.Fatalf("complete scan must report a successful invocation: %+v", invocation)
	}
}

func TestWriteSARIF_CleanScanEmptiesResultsArray(t *testing.T) {
	r := &rules.Rule{}
	r.ID = "mcp-test-001"
	r.Info.Name = "Test Rule"
	r.Info.Severity = "high"
	clean := []engine.RunResult{{Rule: r}} // ran, found nothing

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, clean, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	if strings.Contains(buf.String(), "\"results\": null") {
		t.Fatalf("clean scan must emit an empty results array, not null:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "\"results\": []") {
		t.Fatalf("clean scan must emit \"results\": []:\n%s", buf.String())
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].Results == nil || len(doc.Runs[0].Results) != 0 {
		t.Fatalf("expected one run with a non-nil empty results array; runs=%d results=%v",
			len(doc.Runs), doc.Runs[0].Results)
	}
	invocation := doc.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful == nil || !*invocation.ExecutionSuccessful {
		t.Fatalf("clean scan must report success: %+v", invocation)
	}
	if invocation.Properties.Selected != 1 || invocation.Properties.Completed != 1 {
		t.Fatalf("unexpected coverage counts: %+v", invocation.Properties)
	}
	if len(invocation.Notifications) != 0 {
		t.Fatalf("complete scan emitted notifications: %+v", invocation.Notifications)
	}
}

func TestSARIF_HelpURIFromReferences(t *testing.T) {
	r := &rules.Rule{}
	r.ID = "mcp-helpuri-001"
	r.Info.Name = "Help URI Rule"
	r.Info.Severity = "high"
	r.Info.References = []string{
		"some-non-url-citation",
		"https://modelcontextprotocol.io/specification",
		"https://second.example/ignored",
	}
	results := []engine.RunResult{{Rule: r}}

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected one driver rule, got: %+v", doc)
	}
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	if rule.HelpURI != "https://modelcontextprotocol.io/specification" {
		t.Fatalf("helpUri = %q, want the first http(s) reference", rule.HelpURI)
	}
}

func TestSARIF_FingerprintDistinguishesFindingsAndIgnoresQuery(t *testing.T) {
	fp := func(ruleID, title, description, target string) string {
		results := []engine.RunResult{{
			Rule: &rules.Rule{ID: ruleID},
			Findings: []attack.Finding{{
				RuleID:      ruleID,
				Severity:    "high",
				Title:       title,
				Description: description,
				TargetURL:   target,
			}},
		}}
		var buf bytes.Buffer
		if err := report.WriteSARIF(&buf, results, "test"); err != nil {
			t.Fatalf("WriteSARIF: %v", err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					PartialFingerprints map[string]string `json:"partialFingerprints"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		fingerprints := doc.Runs[0].Results[0].PartialFingerprints
		if _, ok := fingerprints["primaryLocationLineHash"]; ok {
			t.Fatal("network result must not claim to have a source line hash")
		}
		return fingerprints["findingIdentity/v1"]
	}

	a := fp("mcp-x-001", "Same vulnerability", "A", "https://host.example/mcp?nonce=one")
	b := fp("mcp-x-001", "Same vulnerability", "A", "https://HOST.example/mcp?nonce=two#fragment")
	if a == "" || a != b {
		t.Fatalf("query and host case must not change identity: %q vs %q", a, b)
	}
	if c := fp("mcp-x-001", "Same vulnerability", "Reworded", "https://host.example/mcp"); c != a {
		t.Fatalf("description edits must not change identity: %q vs %q", a, c)
	}
	for _, tc := range []struct {
		name, ruleID, title, description, target string
	}{
		{"rule", "mcp-x-002", "Same vulnerability", "A", "https://host.example/mcp"},
		{"title", "mcp-x-001", "Different finding", "A", "https://host.example/mcp"},
		{"host", "mcp-x-001", "Same vulnerability", "A", "https://other.example/mcp"},
		{"path", "mcp-x-001", "Same vulnerability", "A", "https://host.example/other"},
		{"port", "mcp-x-001", "Same vulnerability", "A", "https://host.example:8443/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fp(tc.ruleID, tc.title, tc.description, tc.target); got == a {
				t.Fatalf("distinct findings shared fingerprint %q", got)
			}
		})
	}
}

func TestWriteSARIF_PreservesEvidenceAndChain(t *testing.T) {
	results := sarifFixture()
	finding := &results[0].Findings[0]
	finding.Evidence = strings.Repeat("é", 600)
	finding.Remediation = "Require authorization."
	finding.Chain = []attack.ChainStep{{Hop: 1, Principal: "tenant-a", Action: "request", Outcome: "accepted"}}

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Properties struct {
					Evidence string `json:"evidence"`
					Chain    []struct {
						Hop       int    `json:"hop"`
						Principal string `json:"principal"`
						Action    string `json:"action"`
						Outcome   string `json:"outcome"`
					} `json:"chain"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	result := doc.Runs[0].Results[0]
	if result.Properties.Evidence != finding.Evidence {
		t.Fatal("full evidence was not preserved")
	}
	if !strings.Contains(result.Message.Text, "Test finding") ||
		!strings.Contains(result.Message.Text, "Evidence: ") ||
		!strings.Contains(result.Message.Text, "Remediation: Require authorization.") {
		t.Fatalf("alert message lacks triage details: %q", result.Message.Text)
	}
	if len(result.Properties.Chain) != 1 || result.Properties.Chain[0].Principal != "tenant-a" ||
		result.Properties.Chain[0].Action != "request" {
		t.Fatalf("chain missing from SARIF: %+v", result.Properties.Chain)
	}
}

func TestWriteSARIF_SeverityMatchesReferencedRule(t *testing.T) {
	results := sarifFixture()
	results[0].Findings = append(results[0].Findings,
		attack.Finding{RuleID: "mcp-test-001", Severity: "medium", Title: "Medium finding", TargetURL: "https://agent.example.com/mcp"},
		attack.Finding{RuleID: "mcp-test-001", Severity: "info", Title: "Info finding", TargetURL: "https://agent.example.com/mcp"},
		attack.Finding{RuleID: "mcp-test-001", Severity: "sev1", Title: "Unknown finding", TargetURL: "https://agent.example.com/mcp"},
	)
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID            string `json:"id"`
						DefaultConfig struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties struct {
							Score string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string `json:"ruleId"`
				Level      string `json:"level"`
				Properties struct {
					Severity     string `json:"severity"`
					SourceRuleID string `json:"sourceRuleId"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	rulesByID := make(map[string]struct{ score, level string })
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		rulesByID[rule.ID] = struct{ score, level string }{rule.Properties.Score, rule.DefaultConfig.Level}
	}
	if got := len(doc.Runs[0].Results); got != 4 {
		t.Fatalf("results = %d, want 4", got)
	}
	for i, result := range doc.Runs[0].Results {
		wantID := []string{"mcp-test-001", "mcp-test-001/medium", "mcp-test-001/info", "mcp-test-001/unknown"}[i]
		wantScore := []string{"7.5", "5.0", "1.0", ""}[i]
		wantSeverity := []string{"high", "medium", "info", "sev1"}[i]
		if result.RuleID != wantID || result.Properties.SourceRuleID != "mcp-test-001" || result.Properties.Severity != wantSeverity {
			t.Errorf("result %d rule identity: %+v", i, result)
		}
		rule, ok := rulesByID[result.RuleID]
		if !ok || rule.score != wantScore || rule.level != result.Level {
			t.Errorf("result %d severity differs from rule: rule=%+v result=%+v", i, rule, result)
		}
	}
}

func TestWriteSARIF_ReportsIncompleteCoverage(t *testing.T) {
	results := sarifFixture()
	results = append(results,
		engine.RunResult{
			Rule:    &rules.Rule{ID: "mcp-skipped-001"},
			Skipped: true,
			SkipMsg: "not tested: missing second principal",
		},
		engine.RunResult{
			Rule: &rules.Rule{ID: "mcp-error-001"},
			Err:  errors.New("request failed"),
		},
	)

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("coverage notifications must not become alerts: %+v", doc.Runs[0].Results)
	}
	invocation := doc.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful == nil || *invocation.ExecutionSuccessful {
		t.Fatalf("incomplete scan must report an unsuccessful invocation: %+v", invocation)
	}
	if got := invocation.Properties; got.Selected != 3 || got.Completed != 1 || got.Skipped != 1 || got.Errored != 1 {
		t.Fatalf("unexpected coverage counts: %+v", got)
	}
	if len(invocation.Notifications) != 2 {
		t.Fatalf("expected skip and error notifications, got %+v", invocation.Notifications)
	}
	skip := invocation.Notifications[0]
	if skip.Level != "warning" || skip.Message.Text != "not tested: missing second principal" ||
		skip.AssociatedRule == nil || skip.AssociatedRule.ID != "mcp-skipped-001" {
		t.Fatalf("unexpected skip notification: %+v", skip)
	}
	failure := invocation.Notifications[1]
	if failure.Level != "error" || failure.Message.Text != "request failed" ||
		failure.AssociatedRule == nil || failure.AssociatedRule.ID != "mcp-error-001" {
		t.Fatalf("unexpected error notification: %+v", failure)
	}
}

func TestWriteSARIF_PreservesFindingWithRuleError(t *testing.T) {
	results := sarifFixture()
	results[0].Err = errors.New("follow-up failed")

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, results, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Runs[0].Results) != 1 || len(doc.Runs[0].Invocations[0].Notifications) != 1 {
		t.Fatalf("finding or error notification was lost: %+v", doc.Runs[0])
	}
}

func TestWriteSARIF_NotificationWithoutRule(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, []engine.RunResult{{Skipped: true}}, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	n := doc.Runs[0].Invocations[0].Notifications[0]
	if n.AssociatedRule != nil || n.Message.Text != "rule did not complete" {
		t.Fatalf("unexpected fallback notification: %+v", n)
	}
}
