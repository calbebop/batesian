package mcp

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// PromptUnauthExecutor probes whether MCP prompt templates are accessible
// without authentication (rule mcp-prompt-unauth-001).
type PromptUnauthExecutor struct {
	rule attack.RuleContext
}

// NewPromptUnauthExecutor creates an executor for mcp-prompt-unauth.
func init() {
	attack.Register("mcp-prompt-unauth", func(rc attack.RuleContext) attack.Executor { return NewPromptUnauthExecutor(rc) })
}

func NewPromptUnauthExecutor(r attack.RuleContext) *PromptUnauthExecutor {
	return &PromptUnauthExecutor{rule: r}
}

func (e *PromptUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether prompts are
	// accessible WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// A server may expose prompts on both protocol wires, and need not gate them
	// the same way on each, so every wire it serves is probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session)
	})
}

// probeSession runs the rule against one already-opened wire. determined reports
// whether the wire established anything; see classifyProbe.
func (e *PromptUnauthExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, determined bool) {
	// Skip servers that do not advertise the prompts capability - probing them
	// would produce meaningless noise. This reads the server capabilities from
	// the handshake captured by initializeMCP (no redundant second initialize),
	// and parses the structured capabilities object rather than substring-matching
	// the whole body (which could false-match "prompts" in serverInfo/instructions).
	if !session.ServerSupports("prompts") {
		// Determined: the server says it has none, so none can be open.
		return nil, true
	}

	// Call prompts/list without any auth token.
	listResp, err := session.post(ctx, client, 3, "prompts/list", nil)
	verdict, listBody := classifyProbe(listResp, err)
	if verdict != probeAnswered {
		return nil, verdict == probeRejected
	}

	// JSON-RPC error means auth is enforced - not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, true
	}

	result, _ := listBody["result"].(map[string]interface{})
	promptsRaw, _ := result["prompts"].([]interface{})
	if len(promptsRaw) == 0 {
		return nil, true
	}

	// Collect prompt names for evidence.
	var names []string
	for _, p := range promptsRaw {
		if pm, ok := p.(map[string]interface{}); ok {
			if name, ok := pm["name"].(string); ok {
				names = append(names, name)
			}
		}
	}

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title: fmt.Sprintf(
			"MCP prompts/list returned %d template(s) without authentication", len(names)),
		Description: fmt.Sprintf(
			"prompts/list at %s returned %d prompt template(s) without any authentication. "+
				"Prompt templates may encode system-level instructions, operator context, or "+
				"behavioral configuration that was not intended to be publicly readable. "+
				"An attacker can use this information to craft targeted prompt injection payloads.",
			session.Endpoint, len(names)),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprompts (%d): %v", listResp.StatusCode, session.Endpoint, len(names), names),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	// Attempt to retrieve content of the first prompt via prompts/get.
	if len(names) == 0 {
		return findings, true
	}

	getResp, err := session.post(ctx, client, 4, "prompts/get", map[string]interface{}{"name": names[0]})
	getVerdict, getBody := classifyProbe(getResp, err)
	if getVerdict != probeAnswered {
		// The list finding stands: it was confirmed before this probe.
		return findings, true
	}
	if _, hasErr := getBody["error"]; hasErr {
		return findings, true
	}

	content := string(getResp.Body)
	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title: fmt.Sprintf(
			"MCP prompt %q full content readable without authentication", names[0]),
		Description: fmt.Sprintf(
			"prompts/get for %q at %s returned full template content without authentication. "+
				"The content is now directly readable by any unauthenticated caller.",
			names[0], session.Endpoint),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprompt: %q\ncontent snippet: %.400s", getResp.StatusCode, session.Endpoint, names[0], content),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	return findings, true
}
