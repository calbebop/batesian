package rules

import (
	"strings"
	"testing"
)

// A severity outside the recognized set has to fail at load. Downstream, findings
// are grouped against a fixed set, so such a value was counted in the report
// header and then never printed. Failing here names the rule and the value.
func TestValidate_RejectsUnknownSeverity(t *testing.T) {
	for _, bad := range []string{"sev1", "urgent", "criticalish", "P1"} {
		r := &Rule{ID: "x-001"}
		r.Info.Name = "n"
		r.Info.Severity = bad
		r.Attack.Protocol = "mcp"
		r.Attack.Type = "t"

		err := r.Validate()
		if err == nil {
			t.Errorf("severity %q should be rejected at load", bad)
			continue
		}
		if !strings.Contains(err.Error(), "severity") {
			t.Errorf("error for %q should name the field, got: %v", bad, err)
		}
	}
}

func TestValidate_AcceptsEveryCanonicalSeverity(t *testing.T) {
	for _, ok := range []string{"critical", "high", "medium", "low", "info"} {
		r := &Rule{ID: "x-001"}
		r.Info.Name = "n"
		r.Info.Severity = ok
		r.Attack.Protocol = "mcp"
		r.Attack.Type = "t"
		if err := r.Validate(); err != nil {
			t.Errorf("severity %q must be accepted, got: %v", ok, err)
		}
	}
}

// A case variant is accepted deliberately. Severity filtering already compares
// with strings.EqualFold, and ranking, scoring and report grouping now all
// canonicalize, so "Critical" behaves identically to "critical" everywhere. What
// used to make case dangerous was the disagreement between those copies, not the
// spelling, and rejecting it here would fail rule files that work correctly.
func TestValidate_AcceptsCaseVariants(t *testing.T) {
	for _, ok := range []string{"Critical", "HIGH", " medium "} {
		r := &Rule{ID: "x-001"}
		r.Info.Name = "n"
		r.Info.Severity = ok
		r.Attack.Protocol = "mcp"
		r.Attack.Type = "t"
		if err := r.Validate(); err != nil {
			t.Errorf("severity %q should be accepted (filtering is case-insensitive), got: %v", ok, err)
		}
	}
}
