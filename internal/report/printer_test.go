package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

// TestPrintScanSummary_RiskIndicatorTag verifies that a finding with
// RiskIndicator confidence includes the "[indicator]" tag in output.
func TestPrintScanSummary_RiskIndicatorTag(t *testing.T) {
	var buf bytes.Buffer
	p := report.New(&buf, false)

	r := &rules.Rule{}
	r.ID = "mcp-test-001"
	finding := attack.Finding{
		RuleID:     "mcp-test-001",
		RuleName:   "Test Rule",
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title:      "Test indicator finding",
		TargetURL:  "https://example.com",
	}

	results := []engine.RunResult{
		{Rule: r, Findings: []attack.Finding{finding}},
	}

	p.PrintScanSummary(results)
	out := buf.String()

	if !strings.Contains(out, "[indicator]") {
		t.Errorf("expected [indicator] tag in output for RiskIndicator finding, got:\n%s", out)
	}
	if !strings.Contains(out, "Test indicator finding") {
		t.Errorf("expected finding title in output, got:\n%s", out)
	}
}

// TestPrintScanSummary_ConfirmedExploit verifies that a finding with
// ConfirmedExploit confidence does NOT include the "[indicator]" tag.
func TestPrintScanSummary_ConfirmedExploit(t *testing.T) {
	var buf bytes.Buffer
	p := report.New(&buf, false)

	r := &rules.Rule{}
	r.ID = "a2a-test-001"
	finding := attack.Finding{
		RuleID:     "a2a-test-001",
		RuleName:   "Test Rule",
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "Test confirmed finding",
		TargetURL:  "https://example.com",
	}

	results := []engine.RunResult{
		{Rule: r, Findings: []attack.Finding{finding}},
	}

	p.PrintScanSummary(results)
	out := buf.String()

	if strings.Contains(out, "[indicator]") {
		t.Errorf("ConfirmedExploit finding should not have [indicator] tag, got:\n%s", out)
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    report.Format
		wantErr bool
	}{
		{input: "", want: report.FormatTable, wantErr: false},
		{input: "table", want: report.FormatTable, wantErr: false},
		{input: "TABLE", want: report.FormatTable, wantErr: false},
		{input: "json", want: report.FormatJSON, wantErr: false},
		{input: "JSON", want: report.FormatJSON, wantErr: false},
		{input: "sarif", want: report.FormatSARIF, wantErr: false},
		{input: "SARIF", want: report.FormatSARIF, wantErr: false},
		{input: "markdown", want: report.FormatTable, wantErr: true},
		{input: "md", want: report.FormatTable, wantErr: true},
		{input: "jsno", want: report.FormatTable, wantErr: true},
		{input: "xml", want: report.FormatTable, wantErr: true},
		{input: "csv", want: report.FormatTable, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := report.ParseFormat(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ParseFormat(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ParseFormat(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
