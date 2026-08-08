package report_test

import (
	"bytes"
	"strings"
	"testing"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

// TestPrintScanSummary_InconclusiveNotClean: when rules were skipped and there are
// no findings, the summary must NOT claim the target "appears clean".
func TestPrintScanSummary_InconclusiveNotClean(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, false).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "a2a-x"}, Skipped: true, SkipMsg: "could not reach a testable endpoint"},
		{Rule: &rules.Rule{ID: "a2a-y"}, Skipped: true, SkipMsg: "not tested: no agent card was served"},
	})
	out := buf.String()
	if strings.Contains(out, "appears clean") {
		t.Errorf("must not claim 'appears clean' when no rule was exercised:\n%s", out)
	}
	if !strings.Contains(out, "were not exercised") {
		t.Errorf("expected an inconclusive note, got:\n%s", out)
	}
}

// The zero-findings branch used to return before printing any per-rule skip
// reason, so on a scan that found nothing, which is exactly when an operator needs
// to know what went untested, the reasons were unreachable even in verbose mode.
// The summary points at -v, so -v has to actually show them.
func TestPrintScanSummary_VerboseShowsSkipReasonsWithNoFindings(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, true).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "mcp-tools-unauth-001"}, Skipped: true,
			SkipMsg: "not tested: the MCP handshake succeeded but no probe returned a verdict"},
	})
	out := buf.String()
	if !strings.Contains(out, "mcp-tools-unauth-001") {
		t.Errorf("verbose output should name each skipped rule, got:\n%s", out)
	}
	if !strings.Contains(out, "no probe returned a verdict") {
		t.Errorf("verbose output should carry the per-rule skip reason, got:\n%s", out)
	}
}

// The summary aggregates rules skipped for unrelated reasons, so it must not
// attribute them all to unreachability. Here one rule was genuinely unreachable
// and the other served no agent card; a summary claiming both could not be reached
// sends the operator looking for a network fault that does not exist.
func TestPrintScanSummary_DoesNotAttributeAllSkipsToReachability(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, false).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "a2a-x"}, Skipped: true, SkipMsg: "could not reach a testable endpoint"},
		{Rule: &rules.Rule{ID: "a2a-y"}, Skipped: true,
			SkipMsg: "not tested: the MCP handshake succeeded but no probe returned a verdict"},
	})
	out := buf.String()
	if strings.Contains(out, "could not reach a testable endpoint and were not exercised") {
		t.Errorf("summary must not attribute every skip to unreachability:\n%s", out)
	}
	if !strings.Contains(out, "-v") {
		t.Errorf("summary should point at the per-rule reasons, got:\n%s", out)
	}
}

// TestPrintScanSummary_CleanWhenAllRan: with no findings and no skips, the
// "appears clean" message is correct.
func TestPrintScanSummary_CleanWhenAllRan(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, false).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "a2a-x"}},
	})
	if !strings.Contains(buf.String(), "appears clean") {
		t.Errorf("expected 'appears clean' when rules ran with no findings, got:\n%s", buf.String())
	}
}

// A finding whose severity is not one of the recognized values used to be counted
// in the header and then never printed: the loop iterated a hardcoded list and
// skipped every other key. Rule YAML can no longer express one, but an executor
// sets its finding's severity as a plain string, so the report must not rely on
// that being correct.
func TestPrintScanSummary_UnknownSeverityIsStillPrinted(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, false).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "custom-001"}, Findings: []attackpkg.Finding{
			{RuleID: "custom-001", Severity: "Critical", Title: "typo-cased severity"},
			{RuleID: "custom-001", Severity: "sev1", Title: "wholly unknown severity"},
		}},
	})
	out := buf.String()
	if !strings.Contains(out, "typo-cased severity") {
		t.Errorf("a severity differing only in case must still print:\n%s", out)
	}
	if !strings.Contains(out, "wholly unknown severity") {
		t.Errorf("an unrecognized severity must still print rather than vanish:\n%s", out)
	}
	// And it must not be relabelled as the least severe.
	if strings.Contains(out, "INFO") {
		t.Errorf("an unplaceable severity must not be shown as INFO:\n%s", out)
	}
}

// Two severities that fold to the same canonical value must print in a stable
// order. Grouping walks a map, and map order is randomized, which is what made
// scans undiffable in the host-injection rule.
func TestPrintScanSummary_GroupingIsDeterministic(t *testing.T) {
	build := func() string {
		var buf bytes.Buffer
		report.New(&buf, false).PrintScanSummary([]engine.RunResult{
			{Rule: &rules.Rule{ID: "r"}, Findings: []attackpkg.Finding{
				{RuleID: "r", Severity: "high", Title: "lower-high"},
				{RuleID: "r", Severity: "High", Title: "upper-high"},
				{RuleID: "r", Severity: "zzz", Title: "unknown-one"},
				{RuleID: "r", Severity: "aaa", Title: "unknown-two"},
			}},
		})
		return buf.String()
	}
	first := build()
	for i := 0; i < 40; i++ {
		if got := build(); got != first {
			t.Fatalf("output differed between runs (iteration %d); grouping is not deterministic", i)
		}
	}
}
