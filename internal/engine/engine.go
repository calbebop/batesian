// Package engine orchestrates rule loading and attack execution for the scan command.
// It imports both the rules and attack packages, sitting above both in the dependency graph.
package engine

import (
	"context"
	"fmt"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
	"github.com/calbebop/batesian/internal/rules"
)

// RunResult holds the findings and any error from executing a single rule.
type RunResult struct {
	Rule     *rules.Rule
	Findings []attackpkg.Finding
	Err      error
	Skipped  bool
	SkipMsg  string
}

// Engine executes rules against a target.
type Engine struct {
	opts attackpkg.Options
}

// New creates an Engine with the given execution options.
func New(opts attackpkg.Options) *Engine {
	return &Engine{opts: opts}
}

// Run executes a slice of rules against target and returns all results.
// Errors from individual rules are captured in RunResult.Err rather than
// aborting the entire scan.
func (e *Engine) Run(ctx context.Context, target string, rs []*rules.Rule) []RunResult {
	results := make([]RunResult, 0, len(rs))
	for _, r := range rs {
		result := e.runOne(ctx, target, r)
		results = append(results, result)
	}
	return results
}

// runOne executes a single rule and returns its RunResult.
// A panic inside any executor is caught and surfaced as RunResult.Err so that
// the rest of the scan can continue rather than crashing the process.
func (e *Engine) runOne(ctx context.Context, target string, r *rules.Rule) (result RunResult) {
	// Bail out immediately if the scan context was already cancelled.
	if ctx.Err() != nil {
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: "context cancelled before executor started",
		}
	}

	executor, err := resolveExecutor(r)
	if err != nil {
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: fmt.Sprintf("no executor for attack type %q: %v", r.Attack.Type, err),
		}
	}

	defer func() {
		if p := recover(); p != nil {
			result = RunResult{
				Rule: r,
				Err:  fmt.Errorf("executor panicked: %v", p),
			}
		}
	}()

	findings, err := executor.Execute(ctx, target, e.opts)
	return RunResult{
		Rule:     r,
		Findings: findings,
		Err:      err,
	}
}

// resolveExecutor maps a rule's attack type to the corresponding Executor.
// It converts rules.Rule into attack.RuleContext to avoid import cycles between
// the rules and attack packages.
func resolveExecutor(r *rules.Rule) (attackpkg.Executor, error) {
	rc := attackpkg.RuleContext{
		ID:          r.ID,
		Name:        r.Info.Name,
		Severity:    r.Info.Severity,
		Remediation: r.Remediation,
	}
	switch r.Attack.Type {
	// A2A attack types
	case "extcard-unauth-disclosure":
		return a2aattack.NewExtCardExecutor(rc), nil
	case "push-notification-ssrf":
		return a2aattack.NewPushSSRFExecutor(rc), nil
	case "agent-role-injection":
		return a2aattack.NewSessionSmuggleExecutor(rc), nil
	case "agent-card-jws-algconf":
		return a2aattack.NewJWSAlgConfExecutor(rc), nil
	case "a2a-task-idor":
		return a2aattack.NewTaskIDORExecutor(rc), nil
	case "a2a-context-orphan":
		return a2aattack.NewContextOrphanExecutor(rc), nil
	case "a2a-peer-impersonation":
		return a2aattack.NewPeerImpersonationExecutor(rc), nil
	case "a2a-delegation-escalation":
		return a2aattack.NewDelegationEscalationExecutor(rc), nil
	// MCP attack types
	case "oauth-dcr-scope-escalation":
		return mcpattack.NewOAuthDCRExecutor(rc), nil
	case "mcp-tool-poisoning":
		return mcpattack.NewToolPoisonExecutor(rc), nil
	case "mcp-resources-unauth":
		return mcpattack.NewResourcesUnauthExecutor(rc), nil
	case "mcp-sampling-inject":
		return mcpattack.NewSamplingInjectExecutor(rc), nil
	case "mcp-token-replay":
		return mcpattack.NewTokenReplayExecutor(rc), nil
	case "mcp-oauth-audience":
		return mcpattack.NewOAuthAudienceExecutor(rc), nil
	case "a2a-json-rpc-fuzz":
		return a2aattack.NewJSONRPCFuzzExecutor(rc), nil
	case "a2a-wellknown-hostinject":
		return a2aattack.NewWellKnownHostInjectExecutor(rc), nil
	case "a2a-artifact-tamper":
		return a2aattack.NewArtifactTamperExecutor(rc), nil
	case "mcp-init-downgrade":
		return mcpattack.NewInitDowngradeExecutor(rc), nil
	case "mcp-cors-wildcard":
		return mcpattack.NewCORSWildcardExecutor(rc), nil
	case "mcp-prompt-unauth":
		return mcpattack.NewPromptUnauthExecutor(rc), nil
	case "a2a-skill-poison":
		return a2aattack.NewSkillPoisonExecutor(rc), nil
	case "a2a-url-mismatch":
		return a2aattack.NewURLMismatchExecutor(rc), nil
	case "mcp-context-flood":
		return mcpattack.NewContextFloodExecutor(rc), nil
	case "mcp-tool-namespace":
		return mcpattack.NewToolNamespaceExecutor(rc), nil
	case "mcp-sse-hijack":
		return mcpattack.NewSSEHijackExecutor(rc), nil
	case "a2a-tls-downgrade":
		return a2aattack.NewTLSDowngradeExecutor(rc), nil
	case "mcp-init-instructions-inject":
		return mcpattack.NewInitInstructionsInjectExecutor(rc), nil
	case "a2a-capability-inflation":
		return a2aattack.NewCapabilityInflationExecutor(rc), nil
	case "mcp-ratelimit-absent":
		return mcpattack.NewRateLimitAbsentExecutor(rc), nil
	case "mcp-homoglyph-tool":
		return mcpattack.NewHomoglyphToolExecutor(rc), nil
	case "mcp-injection-params":
		return mcpattack.NewInjectionParamsExecutor(rc), nil
	case "a2a-security-headers":
		return a2aattack.NewSecurityHeadersExecutor(rc), nil
	case "mcp-security-headers":
		return mcpattack.NewMCPSecurityHeadersExecutor(rc), nil
	case "a2a-registry-poison":
		return a2aattack.NewRegistryPoisonExecutor(rc), nil
	case "a2a-circular-delegation":
		return a2aattack.NewCircularDelegationExecutor(rc), nil
	default:
		return nil, fmt.Errorf("unknown attack type %q", r.Attack.Type)
	}
}

// TotalFindings counts the total number of findings across all results.
func TotalFindings(results []RunResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}

// FindingsBySeverity groups findings by severity level.
func FindingsBySeverity(results []RunResult) map[string][]attackpkg.Finding {
	out := make(map[string][]attackpkg.Finding)
	for _, r := range results {
		for _, f := range r.Findings {
			out[f.Severity] = append(out[f.Severity], f)
		}
	}
	return out
}
