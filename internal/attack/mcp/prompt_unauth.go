package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// PromptUnauthExecutor probes whether MCP prompt templates are accessible
// without authentication (rule mcp-prompt-unauth-001).
type PromptUnauthExecutor struct {
	rule attack.RuleContext
}

// NewPromptUnauthExecutor creates an executor for mcp-prompt-unauth.
func NewPromptUnauthExecutor(r attack.RuleContext) *PromptUnauthExecutor {
	return &PromptUnauthExecutor{rule: r}
}

func (e *PromptUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token — the rule tests whether prompts are
	// accessible WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, nil // not an MCP server
	}

	// Check that the server advertises prompts capability.
	// If not, skip — probing would produce meaningless noise.
	initResp, _ := client.POST(ctx, session.Endpoint, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{"prompts": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if initResp != nil && !strings.Contains(initResp.BodyString(), `"prompts"`) {
		return nil, nil // server does not support prompts
	}

	// Call prompts/list without any auth token.
	listResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "prompts/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !listResp.IsSuccess() {
		return nil, nil
	}

	var listBody map[string]interface{}
	if err := json.Unmarshal(listResp.Body, &listBody); err != nil {
		return nil, nil
	}

	// JSON-RPC error means auth is enforced — not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, nil
	}

	result, _ := listBody["result"].(map[string]interface{})
	promptsRaw, _ := result["prompts"].([]interface{})
	if len(promptsRaw) == 0 {
		return nil, nil
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

	var findings []attack.Finding

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
		return findings, nil
	}

	getResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "prompts/get",
		"params":  map[string]interface{}{"name": names[0]},
	})
	if err != nil || !getResp.IsSuccess() {
		return findings, nil
	}

	var getBody map[string]interface{}
	if err := json.Unmarshal(getResp.Body, &getBody); err != nil {
		return findings, nil
	}
	if _, hasErr := getBody["error"]; hasErr {
		return findings, nil
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

	return findings, nil
}
