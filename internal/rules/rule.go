// Package rules loads, validates, and provides attack rules from YAML files.
package rules

import (
	"fmt"

	"github.com/calbebop/batesian/internal/severity"
)

// Rule is a YAML catalog entry whose attack type selects a registered executor.
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

// AttackBlock identifies the rule's protocol and registered executor type.
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
	// Reject unknown values before fixed output buckets can hide them.
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
