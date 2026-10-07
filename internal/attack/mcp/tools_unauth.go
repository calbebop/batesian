package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolsUnauthExecutor checks whether tools/list exposes tool definitions
// without authentication. It does not invoke tools.
type ToolsUnauthExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-tools-unauth", func(rc attack.RuleContext) attack.Executor { return NewToolsUnauthExecutor(rc) })
}

func NewToolsUnauthExecutor(r attack.RuleContext) *ToolsUnauthExecutor {
	return &ToolsUnauthExecutor{rule: r}
}

func (e *ToolsUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// The rule tests access without credentials.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// A server may expose tools on both protocol wires, and need not gate them the
	// same way on each, so every wire it serves is probed.
	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session)
	})
}

// determined is false when the wire returned no usable verdict.
func (e *ToolsUnauthExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, determined bool) {
	// No advertised tools capability means there is no tool surface to check.
	if !session.ServerSupports("tools") {
		return nil, true
	}

	// Request tools/list without a bearer token.
	listResp, err := session.post(ctx, client, 3, "tools/list", nil)
	verdict, listBody := classifyProbe(listResp, err)
	if verdict != probeAnswered {
		return nil, verdict == probeRejected
	}

	if errObj, ok := listBody["error"].(map[string]interface{}); ok {
		code := rpcErrorCode(errObj["code"])
		message, _ := errObj["message"].(string)
		return nil, code == -32601 || authFlavoredError(code, message)
	}
	if _, hasErr := listBody["error"]; hasErr {
		return nil, false
	}

	result, ok := listBody["result"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	toolsRaw, ok := result["tools"].([]interface{})
	if !ok {
		return nil, false
	}
	cursor, more := result["nextCursor"].(string)
	_, hasCursor := result["nextCursor"]
	complete := !hasCursor
	seen := map[string]bool{}
	for page := 1; page < 10 && more; page++ {
		if seen[cursor] {
			break
		}
		seen[cursor] = true
		pageResp, pageErr := session.post(ctx, client, 3+page, "tools/list",
			map[string]interface{}{"cursor": cursor})
		pageVerdict, pageBody := classifyProbe(pageResp, pageErr)
		if pageVerdict != probeAnswered {
			break
		}
		if _, hasErr := pageBody["error"]; hasErr {
			break
		}
		pageResult, ok := pageBody["result"].(map[string]interface{})
		if !ok {
			break
		}
		pageTools, ok := pageResult["tools"].([]interface{})
		if !ok {
			break
		}
		toolsRaw = append(toolsRaw, pageTools...)
		next, present := pageResult["nextCursor"]
		if !present {
			complete = true
			break
		}
		cursor, more = next.(string)
		if !more {
			break
		}
	}
	if len(toolsRaw) == 0 {
		return nil, complete
	}

	// Collect tool names for evidence.
	var names []string
	for _, t := range toolsRaw {
		if tm, ok := t.(map[string]interface{}); ok {
			if name, ok := tm["name"].(string); ok && strings.TrimSpace(name) != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, false
	}
	evidence := fmt.Sprintf("HTTP %d from %s\ntools (%d): %v", listResp.StatusCode, session.Endpoint, len(names), names)
	if !complete {
		evidence += "\nlisting incomplete: pagination stopped before the final page"
	}

	findings = []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP tools/list returned %d tool(s) without authentication", len(names)),
		Description: fmt.Sprintf(
			"tools/list at %s returned %d tool(s) without any authentication, disclosing tool names "+
				"and metadata to an anonymous caller. The MCP spec "+
				"requires servers to implement proper access controls; an attacker can map the callable "+
				"functions and craft targeted invocations.", session.Endpoint, len(names)),
		Evidence:    evidence,
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}

	return findings, true
}
