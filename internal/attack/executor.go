// Package attack defines the Executor interface and shared utilities
// for all Batesian attack implementations.
package attack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Executor runs a single attack rule against a target and returns findings.
type Executor interface {
	// Execute runs the attack and returns a (possibly empty) list of findings.
	Execute(ctx context.Context, target string, opts Options) ([]Finding, error)
}

// RuleContext carries the metadata from a rule that executors need to populate findings.
// This avoids importing the rules package inside executor packages (preventing import cycles).
type RuleContext struct {
	ID          string
	Name        string
	Severity    string
	Remediation string
}

// Options carries per-scan configuration into each executor.
type Options struct {
	// OOBListenerURL is the base URL of the local OOB callback listener.
	// Empty if OOB is not enabled.
	OOBListenerURL string

	// Token is an optional bearer token for authenticated requests.
	Token string

	// TimeoutSeconds is the per-request HTTP timeout.
	TimeoutSeconds int

	// SkipTLS disables TLS certificate verification.
	SkipTLS bool

	// Verbose enables debug logging.
	Verbose bool

	// AudienceClaim is the operator-supplied expected JWT `aud` value for the
	// target MCP resource server. Currently consumed only by mcp-oauth-audience-002,
	// which derives canary-mismatch probes (substring/case/array-shape) from this
	// value. When empty, that rule attempts RFC 9728 protected-resource-metadata
	// auto-discovery and otherwise reports Inconclusive.
	AudienceClaim string
}

// Confidence describes how certain the finding is.
// "confirmed" means the attack demonstrably succeeded (e.g., unauthenticated data returned).
// "indicator" means a suspicious pattern was detected but exploitability is not proven (e.g., heuristic scan).
type Confidence string

const (
	ConfirmedExploit  Confidence = "confirmed"
	RiskIndicator     Confidence = "indicator"
	ConfidenceDefault Confidence = "confirmed" // legacy — callers that don't set Confidence get confirmed
)

// Finding represents a confirmed vulnerability or notable observation.
type Finding struct {
	RuleID   string
	RuleName string
	Severity string
	// Confidence describes whether the finding is a confirmed exploit or a risk indicator.
	// Confirmed findings: the attack demonstrably succeeded (auth bypass proven, data returned).
	// Indicator findings: a suspicious pattern was detected; manual verification recommended.
	Confidence  Confidence
	Title       string
	Description string
	Evidence    string
	Remediation string
	TargetURL   string
}

// Vars holds template variable substitutions for a single attack execution.
type Vars struct {
	BaseURL     string
	OOBListener string
	RandID      string
}

// NewVars creates a Vars instance for the given target, pre-populating RandID.
func NewVars(baseURL, oobListener string) Vars {
	return Vars{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		OOBListener: oobListener,
		RandID:      randomID(),
	}
}

// Expand replaces {{BaseURL}}, {{OOBListener}}, and {{RandID}} in s.
func (v Vars) Expand(s string) string {
	s = strings.ReplaceAll(s, "{{BaseURL}}", v.BaseURL)
	s = strings.ReplaceAll(s, "{{OOBListener}}", v.OOBListener)
	s = strings.ReplaceAll(s, "{{RandID}}", v.RandID)
	return s
}

// ExpandMap returns a copy of m with all values expanded.
func (v Vars) ExpandMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = v.Expand(val)
	}
	return out
}

// randomID generates a short random hex string for unique IDs within a run.
func randomID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extremely unlikely; use a deterministic fallback
		// rather than panicking, as a weak ID is better than aborting a scan.
		return "000000"
	}
	return hex.EncodeToString(b)
}
