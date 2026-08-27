package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

// sarifFixture builds a one-finding result set with an absolute network target,
// which is the only shape Batesian ever produces (scan targets are URLs).
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
			TargetURL:   "https://agent.example.com/mcp",
		}},
	}}
}

// sarifDoc is a minimal view of the parts of a SARIF document this test inspects.
type sarifDoc struct {
	Runs []struct {
		Results []struct {
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation map[string]any `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// TestWriteSARIF_AbsoluteURIHasNoUriBaseId verifies the artifactLocation for a
// network target carries the absolute target URL and NO uriBaseId. Per SARIF
// 2.1.0: "if the uri property contains an absolute URI, the uriBaseId property
// SHALL be absent." The previous output paired the absolute URI with a
// %SRCROOT% uriBaseId, violating the spec.
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
}

// TestWriteSARIF_CleanScanEmptiesResultsArray verifies a zero-finding scan
// writes "results": [] rather than "results": null. SARIF 2.1.0 types
// runs[].results as an array - null is not a legal value - so a nil Go slice
// here produced a document that schema-validating consumers (GitHub
// code-scanning upload, VS Code SARIF viewer) reject, precisely when the
// target was clean. A clean scan is the most common scan outcome.
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
}

// TestSARIF_HelpURIFromReferences pins that a rule's first http(s) reference
// becomes the driver rule's helpUri - the field GitHub code-scanning renders
// as the alert's help link. HelpURI existed as a struct field but was never
// assigned, so every alert shipped with no help link despite every rule
// citing specs and advisories.
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

// TestSARIF_PartialFingerprintStableAcrossTargetDrift pins the alert-
// correlation property: two findings with identical rule ID and title but
// different target URLs must produce the SAME fingerprint, since the whole
// point is that one logical vulnerability keeps one alert when its endpoint
// string moves. It also pins the negative - different titles hash differently.
func TestSARIF_PartialFingerprintStableAcrossTargetDrift(t *testing.T) {
	fp := func(ruleID, title, target string) string {
		results := []engine.RunResult{{
			Rule: &rules.Rule{ID: ruleID},
			Findings: []attack.Finding{{
				RuleID:    ruleID,
				Severity:  "high",
				Title:     title,
				TargetURL: target,
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
		return doc.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	}

	a := fp("mcp-x-001", "Same vulnerability", "https://host.example/mcp")
	b := fp("mcp-x-001", "Same vulnerability", "https://host.example/mcp/deep/path")
	if a == "" || a != b {
		t.Fatalf("endpoint drift must keep one fingerprint: %q vs %q", a, b)
	}
	if c := fp("mcp-x-001", "Different finding", "https://host.example/mcp"); c == a {
		t.Fatalf("different titles must hash differently, got %q for both", a)
	}
}
