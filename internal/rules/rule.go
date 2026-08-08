// Package rules loads, validates, and provides attack rules from YAML files.
package rules

import (
	"fmt"

	"github.com/calbebop/batesian/internal/severity"
)

// Rule is the catalog entry for a Batesian attack. Rules live in rules/a2a/ or
// rules/mcp/ as YAML files and carry metadata only: the executor logic lives in
// Go (internal/attack/...), and attack.Type is the key that binds a rule to its
// registered executor. The YAML deliberately does NOT encode request steps or
// assertions - findings are produced by the executor, which is the single
// source of truth for what each check does.
type Rule struct {
	// ID is the stable rule identifier, e.g. "a2a-push-ssrf-001".
	ID   string   `yaml:"id"`
	Info RuleInfo `yaml:"info"`

	// Attack binds the rule to its executor via protocol and type.
	Attack AttackBlock `yaml:"attack"`

	// Remediation is the human-readable fix recommendation surfaced in findings.
	Remediation string `yaml:"remediation"`
}

// RuleInfo holds descriptive metadata about the rule.
type RuleInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"` // critical, high, medium, low, info
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Tags        []string `yaml:"tags"`
}

// AttackBlock identifies the protocol and the executor type for the rule.
// Type must match an attack type registered via attack.Register; this binding
// is verified for every shipped rule by the engine's resolution test.
type AttackBlock struct {
	Protocol string `yaml:"protocol"` // a2a, mcp
	Type     string `yaml:"type"`     // e.g. push-notification-ssrf, extcard-unauth-disclosure
}

// Validate returns an error if the rule is missing required fields.
func (r *Rule) Validate() error {
	var errs []string
	if r.ID == "" {
		errs = append(errs, "missing id")
	}
	if r.Info.Name == "" {
		errs = append(errs, "missing info.name")
	}
	// An unrecognized severity has to fail here. Downstream, findings are grouped
	// by severity against a fixed set, so a value outside it was counted in the
	// report header and then never printed. Failing at load names the rule and the
	// bad value instead of losing its findings silently at output time.
	if r.Info.Severity == "" {
		errs = append(errs, "missing info.severity")
	} else if !severity.Valid(r.Info.Severity) {
		errs = append(errs, fmt.Sprintf("info.severity %q is not a severity (want one of: %s)",
			r.Info.Severity, severity.List()))
	}
	if r.Attack.Protocol == "" {
		errs = append(errs, "missing attack.protocol")
	}
	if r.Attack.Type == "" {
		errs = append(errs, "missing attack.type")
	}
	if len(errs) > 0 {
		return &ValidationError{RuleID: r.ID, Errors: errs}
	}
	return nil
}

// SeverityRank was a fifth independent copy of the severity ordering, keyed on the
// raw string so it disagreed with the engine's rank on case, and it had no callers
// at all. Removed rather than rewired: internal/severity.Rank is the one ranking
// function, and a duplicate with no consumers is how these drift apart.

// ValidationError is returned when a rule fails validation.
type ValidationError struct {
	RuleID string
	Errors []string
}

func (e *ValidationError) Error() string {
	msg := "rule"
	if e.RuleID != "" {
		msg += " " + e.RuleID
	}
	msg += " validation failed:"
	for _, err := range e.Errors {
		msg += " " + err + ";"
	}
	return msg
}
