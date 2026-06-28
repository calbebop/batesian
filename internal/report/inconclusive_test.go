package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

// TestPrintScanSummary_InconclusiveNotClean: when rules were skipped because no
// endpoint was reachable and there are no findings, the summary must NOT claim
// the target "appears clean".
func TestPrintScanSummary_InconclusiveNotClean(t *testing.T) {
	var buf bytes.Buffer
	report.New(&buf, false).PrintScanSummary([]engine.RunResult{
		{Rule: &rules.Rule{ID: "a2a-x"}, Skipped: true, SkipMsg: "could not reach a testable endpoint"},
		{Rule: &rules.Rule{ID: "a2a-y"}, Skipped: true, SkipMsg: "could not reach a testable endpoint"},
	})
	out := buf.String()
	if strings.Contains(out, "appears clean") {
		t.Errorf("must not claim 'appears clean' when no rule was exercised:\n%s", out)
	}
	if !strings.Contains(out, "could not reach a testable endpoint") {
		t.Errorf("expected an inconclusive note, got:\n%s", out)
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
