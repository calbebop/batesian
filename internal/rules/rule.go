// Package rules loads, validates, and provides attack rules from YAML files.
package rules

// Rule is the top-level structure for a Batesian attack rule.
// Rules live in rules/a2a/ or rules/mcp/ as YAML files.
type Rule struct {
	// ID is the stable rule identifier, e.g. "a2a-push-ssrf-001"
	ID   string   `yaml:"id"`
	Info RuleInfo `yaml:"info"`

	// Attack describes how to execute the attack.
	Attack AttackBlock `yaml:"attack"`

	// Assert lists conditions that constitute a finding.
	Assert []Assertion `yaml:"assert"`

	// Remediation is the human-readable fix recommendation.
	Remediation string `yaml:"remediation"`
}

// RuleInfo holds metadata about the rule.
type RuleInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"` // critical, high, medium, low, info
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Tags        []string `yaml:"tags"`
}

// AttackBlock describes the protocol, attack type, and HTTP steps to execute.
type AttackBlock struct {
	Protocol string `yaml:"protocol"` // a2a, mcp
	Type     string `yaml:"type"`     // e.g. push-notification-ssrf, extcard-unauth-disclosure

	// The following are attack-type-specific sub-blocks.
	// Each executor reads the fields relevant to its type.

	// Discover is used to fetch an endpoint and extract data.
	Discover *DiscoverStep `yaml:"discover,omitempty"`

	// Probe is a simple HTTP request with no auth.
	Probe *HTTPStep `yaml:"probe,omitempty"`

	// ProbeInvalidAuth is a probe request with a fabricated invalid token.
	ProbeInvalidAuth *HTTPStep `yaml:"probe_invalid_auth,omitempty"`

	// Register is used for attacks that register a resource (e.g. push-notification-ssrf).
	Register *HTTPStep `yaml:"register,omitempty"`

	// OOB configures the out-of-band callback listener.
	OOB *OOBConfig `yaml:"oob,omitempty"`

	// BaselineRegistration and EscalatedRegistration are for DCR scope escalation.
	BaselineRegistration  *HTTPStep `yaml:"baseline_registration,omitempty"`
	EscalatedRegistration *HTTPStep `yaml:"escalated_registration,omitempty"`
	RedirectURIProbe      *HTTPStep `yaml:"redirect_uri_probe,omitempty"`
}

// DiscoverStep fetches an endpoint and optionally extracts fields for use in later steps.
type DiscoverStep struct {
	// WellKnownEndpoints is a list of URLs to try in order.
	WellKnownEndpoints []string `yaml:"well_known_endpoints,omitempty"`
	Endpoint           string   `yaml:"endpoint,omitempty"`
	Method             string   `yaml:"method,omitempty"`
	AssertField        string   `yaml:"assert_field,omitempty"`
	Extract            []string `yaml:"extract,omitempty"`
}

// HTTPStep describes a single HTTP request in an attack sequence.
type HTTPStep struct {
	Endpoint string            `yaml:"endpoint"`
	Method   string            `yaml:"method"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Body     interface{}       `yaml:"body,omitempty"`
}

// OOBConfig configures the out-of-band callback listener for SSRF detection.
type OOBConfig struct {
	// Listener is the template variable referencing the OOB listener URL, e.g. "{{OOBListener}}"
	Listener string `yaml:"listener"`
	// Timeout is how long to wait for a callback after the attack request.
	Timeout string `yaml:"timeout"`
}

// Assertion defines a condition that, if true, indicates a finding.
type Assertion struct {
	Condition   string `yaml:"condition"`
	Description string `yaml:"description"`
	Evidence    string `yaml:"evidence,omitempty"`
	Severity    string `yaml:"severity"`
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
	if len(r.Assert) == 0 {
		errs = append(errs, "missing assert (at least one assertion required)")
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
