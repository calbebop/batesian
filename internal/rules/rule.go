// Package rules loads, validates, and provides attack rules from YAML files.
package rules

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
	if r.Info.Severity == "" {
		errs = append(errs, "missing info.severity")
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

// SeverityRank returns a numeric rank for sorting (higher = more severe).
func (r *Rule) SeverityRank() int {
	switch r.Info.Severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
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
