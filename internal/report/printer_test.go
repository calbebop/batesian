package report_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func TestPrintScanSummary_VerboseShowsPrimaryDetails(t *testing.T) {
	finding := attack.Finding{
		RuleID: "r", Severity: "high", Title: "Access granted", TargetURL: "https://example.com",
		Description: "Cross-tenant read", Evidence: "task returned", Remediation: "Check task ownership",
		Chain: []attack.ChainStep{{Hop: 1, Principal: "tenant A", Action: "read task", Outcome: "tenant B data returned"}},
	}
	results := []engine.RunResult{{Rule: &rules.Rule{ID: "r"}, Findings: []attack.Finding{finding}}}
	var verbose, compact bytes.Buffer
	if err := report.New(&verbose, true).PrintScanSummary(results); err != nil {
		t.Fatal(err)
	}
	if err := report.New(&compact, false).PrintScanSummary(results); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"description:", "Cross-tenant read", "evidence:", "task returned", "remediation:", "Check task ownership", "chain 1 (tenant A): read task -> tenant B data returned"} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("verbose output lacks %q:\n%s", want, verbose.String())
		}
		if strings.Contains(compact.String(), want) {
			t.Errorf("compact output contains %q:\n%s", want, compact.String())
		}
	}
}

type failAfterWriter struct {
	writes int
	after  int
	err    error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.writes >= w.after {
		return 0, w.err
	}
	w.writes++
	return len(p), nil
}

func TestTerminalTablesReturnWriteErrors(t *testing.T) {
	want := errors.New("output failed")
	tests := []struct {
		name  string
		print func(*report.Printer) error
	}{
		{"a2a probe", func(p *report.Printer) error { return p.PrintProbeTable(&report.ProbeResult{Name: "agent"}) }},
		{"mcp probe", func(p *report.Printer) error {
			return p.PrintMCPProbeTable(&report.MCPProbeResult{ServerName: "server"})
		}},
		{"scan", func(p *report.Printer) error {
			return p.PrintScanSummary([]engine.RunResult{{Rule: &rules.Rule{ID: "r"}}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, after := range []int{0, 1} {
				w := &failAfterWriter{after: after, err: want}
				if err := tt.print(report.New(w, true)); !errors.Is(err, want) {
					t.Errorf("failure after %d writes: got %v, want %v", after, err, want)
				}
			}
		})
	}
}

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
		Evidence:   "Observed unauthorized task read",
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

func TestPrintScanSummary_ConfirmedWithoutEvidenceIsIndicator(t *testing.T) {
	var buf bytes.Buffer
	p := report.New(&buf, false)
	r := &rules.Rule{ID: "a2a-test-001"}
	p.PrintScanSummary([]engine.RunResult{{Rule: r, Findings: []attack.Finding{{
		RuleID: "a2a-test-001", Severity: "high", Confidence: attack.ConfirmedExploit,
		Title: "Unproven finding", TargetURL: "https://example.com",
	}}}})
	if !strings.Contains(buf.String(), "[indicator]") {
		t.Errorf("evidence-free finding was presented as confirmed:\n%s", buf.String())
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
