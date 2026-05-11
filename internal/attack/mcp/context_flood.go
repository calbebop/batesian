package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// floodSizes defines the payload sizes to test, in bytes.
// 1MB is the threshold for a medium finding; 5MB for high.
var floodSizes = []struct {
	bytes    int
	severity string
	label    string
}{
	{1 * 1024 * 1024, "medium", "1MB"},
	{5 * 1024 * 1024, "high", "5MB"},
}

// ContextFloodExecutor tests whether an MCP server enforces request size limits
// (rule mcp-context-flood-001). Servers that accept unbounded payloads are
// vulnerable to context window flooding: an attacker stuffs the LLM's context
// with attacker-controlled content, displacing system prompt instructions.
type ContextFloodExecutor struct {
	rule attack.RuleContext
}

// NewContextFloodExecutor creates an executor for mcp-context-flood.
func NewContextFloodExecutor(r attack.RuleContext) *ContextFloodExecutor {
	return &ContextFloodExecutor{rule: r}
}

func (e *ContextFloodExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Require a successful initialize to confirm MCP target.
	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, nil
	}

	// Discover a tool name to use as the call target. Oversized arguments on
	// an unknown tool name still exercise the size-limit path on compliant
	// servers, but a known tool name increases the chance of reaching actual
	// argument processing code on vulnerable ones.
	toolName := "echo"
	tools, _, tlErr := listMCPTools(ctx, client, vars.BaseURL)
	if tlErr == nil && len(tools) > 0 {
		if n, ok := tools[0]["name"].(string); ok && n != "" {
			toolName = n
		}
	}

	var findings []attack.Finding

	for _, size := range floodSizes {
		// Build a large string argument padded with repeated content.
		// Use a recognizable but non-malicious pattern: "batesian-flood " repeated.
		padUnit := "batesian-flood-test "
		repeats := size.bytes / len(padUnit)
		bigArg := strings.Repeat(padUnit, repeats)

		resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      10,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": toolName,
				"arguments": map[string]interface{}{
					"input": bigArg,
				},
			},
		})
		if err != nil {
			continue
		}

		// 413 or a JSON-RPC error code -32600 / -32602 means the server rejected
		// the payload. Anything 2xx or 5xx means it was accepted (or crashed).
		if resp.StatusCode == 413 {
			continue
		}

		// Check for a JSON-RPC error indicating size rejection.
		var body map[string]interface{}
		if jsonErr := json.Unmarshal(resp.Body, &body); jsonErr == nil {
			if errObj, hasErr := body["error"].(map[string]interface{}); hasErr {
				code, _ := errObj["code"].(float64)
				message, _ := errObj["message"].(string)
				msgLower := strings.ToLower(message)
				// Servers that explicitly reject oversized payloads are not vulnerable.
				if code == -32600 || code == -32602 ||
					strings.Contains(msgLower, "too large") ||
					strings.Contains(msgLower, "size") ||
					strings.Contains(msgLower, "limit") {
					continue
				}
			}
		}

		// Server accepted the oversized payload -- this is the vulnerability.
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   size.severity,
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP server accepted %s tools/call argument without enforcing size limit",
				size.label),
			Description: fmt.Sprintf(
				"The MCP server at %s accepted a tools/call request with a %s string argument "+
					"and returned HTTP %d without rejecting it. Without size limits, an attacker "+
					"can submit payloads large enough to fill the LLM's context window, displacing "+
					"system prompt instructions and bypassing guardrails.",
				session.Endpoint, size.label, resp.StatusCode),
			Evidence: fmt.Sprintf(
				"POST %s (tool: %q, payload size: %d bytes)\nHTTP %d\nResponse snippet: %.200s",
				session.Endpoint, toolName, len(bigArg), resp.StatusCode, string(resp.Body)),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}

	return findings, nil
}
