package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// InitInstructionsInjectExecutor reads the serverInfo.instructions field from a
// live MCP initialize response and scores it for prompt injection patterns
// (rule mcp-init-instructions-inject-001).
//
// Unlike mcp-tool-poison-001, which tests tool descriptions fetched after the
// handshake, this rule attacks the initialization channel itself: injection
// directives in instructions execute at session establishment, before any tool
// is called.
type InitInstructionsInjectExecutor struct {
	rule attack.RuleContext
}

// NewInitInstructionsInjectExecutor creates an executor for mcp-init-instructions-inject.
func NewInitInstructionsInjectExecutor(r attack.RuleContext) *InitInstructionsInjectExecutor {
	return &InitInstructionsInjectExecutor{rule: r}
}

func (e *InitInstructionsInjectExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoints := endpointCandidates(vars.BaseURL)

	for _, ep := range endpoints {
		initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || !initResp.IsSuccess() {
			continue
		}

		var body map[string]interface{}
		if err := json.Unmarshal(initResp.Body, &body); err != nil {
			continue
		}
		result, _ := body["result"].(map[string]interface{})
		if result == nil {
			continue
		}

		// Extract serverInfo.instructions (the primary injection surface).
		instructions := extractInstructions(result)
		if instructions == "" {
			continue // Field absent on this endpoint; try the next candidate.
		}

		score, matched := scoreDescription(instructions)
		if score < 2 {
			continue // Score below threshold; not actionable on this endpoint.
		}

		sev := scoreToSeverity(score)
		serverName := ""
		if si, ok := result["serverInfo"].(map[string]interface{}); ok {
			serverName, _ = si["name"].(string)
		}
		label := ep
		if serverName != "" {
			label = fmt.Sprintf("%s (%s)", ep, serverName)
		}

		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   sev,
			Confidence: attack.RiskIndicator,
			Title: fmt.Sprintf(
				"MCP server %q initialize instructions contain prompt injection patterns (score %d)",
				serverName, score),
			Description: fmt.Sprintf(
				"The serverInfo.instructions field returned by %s at initialize time "+
					"contains patterns consistent with prompt injection. MCP clients pass "+
					"this field directly to the connected LLM as setup context, so injection "+
					"directives here execute before any tool is called.",
				label),
			Evidence: fmt.Sprintf(
				"endpoint: %s\nserver: %q\npatterns matched: %v\ninstructions snippet: %.500s",
				ep, serverName, matched, instructions),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}}, nil
	}

	return nil, nil
}

// extractInstructions walks the MCP initialize result for the instructions field.
// The spec places it at result.serverInfo.instructions or result.instructions.
func extractInstructions(result map[string]interface{}) string {
	// MCP 2025-03-26: result.serverInfo.instructions
	if si, ok := result["serverInfo"].(map[string]interface{}); ok {
		if v, ok := si["instructions"].(string); ok && v != "" {
			return strings.TrimSpace(v)
		}
	}
	// Fallback: some servers put it at the top level.
	if v, ok := result["instructions"].(string); ok && v != "" {
		return strings.TrimSpace(v)
	}
	return ""
}
