package attack

import (
	"fmt"
	"strings"
)

const (
	MCPPromptsList        = "mcp.prompts.list"
	MCPPromptsGet         = "mcp.prompts.get"
	MCPCompletionComplete = "mcp.completion.complete"
	MCPTasksGet           = "mcp.tasks.get"
	MCPTasksUpdate        = "mcp.tasks.update"
	MCPTasksCancel        = "mcp.tasks.cancel"
	A2ATasksGet           = "a2a.tasks.get"
	A2ATasksList          = "a2a.tasks.list"
	A2ATasksCancel        = "a2a.tasks.cancel"
)

// AccessObservation identifies an operation that the target demonstrably allowed.
type AccessObservation struct {
	Operation    string
	Caller       string
	CallerTenant string
	Owner        string
	OwnerTenant  string
}

// ExpectedDenial states an operator-supplied authorization boundary.
type ExpectedDenial struct {
	Operation    string
	Caller       string
	CallerTenant string
	Owner        string
	OwnerTenant  string
}

func (d ExpectedDenial) matches(o AccessObservation) bool {
	return d.Operation == o.Operation && d.Caller == o.Caller && d.Owner == o.Owner &&
		(d.CallerTenant == "" || d.CallerTenant == o.CallerTenant) &&
		(d.OwnerTenant == "" || d.OwnerTenant == o.OwnerTenant)
}

// ApplyExpectedDenial promotes a demonstrated access observation only when an
// explicit policy denies the same caller, owner, and operation.
func ApplyExpectedDenial(f *Finding, denials []ExpectedDenial) bool {
	if f == nil || f.Access == nil || f.EffectiveConfidence() != RiskIndicator ||
		strings.TrimSpace(f.Evidence) == "" {
		return false
	}
	for _, denial := range denials {
		if !denial.matches(*f.Access) {
			continue
		}
		f.Confidence = ConfirmedExploit
		f.Description += " This observed access violates the operator's expected-protection policy."
		f.Evidence += fmt.Sprintf("\nexpected denial: operation=%q caller=%q owner=%q caller_tenant=%q owner_tenant=%q",
			denial.Operation, denial.Caller, denial.Owner, denial.CallerTenant, denial.OwnerTenant)
		return true
	}
	return false
}
