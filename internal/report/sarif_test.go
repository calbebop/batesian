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
	if err := report.WriteSARIF(&buf, "https://agent.example.com", sarifFixture(), "test"); err != nil {
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
	if err := report.WriteSARIF(&buf, "https://agent.example.com", clean, "test"); err != nil {
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
