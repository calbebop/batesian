package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolsUnauthExecutor probes whether MCP tools are accessible without
// authentication (rule mcp-tools-unauth-001).
//
// Tools are the primary MCP attack surface: unlike resources (data) or prompts
// (templates), tools are server-side functions a caller can invoke. The MCP spec
// requires servers to "implement proper access controls", so an unauthenticated
// tools/list disclosure (the executable surface plus input schemas) and a
// reachable tools/call dispatch are access-control failures.
//
// SAFETY: this rule NEVER invokes a real or advertised tool. It confirms that
// the tools/call path is reachable without auth by calling a guaranteed
// non-existent tool name, which the spec answers with a -32602 "Unknown tool"
// protocol error and zero execution. Destructive tool-argument fuzzing is out of
// scope.
type ToolsUnauthExecutor struct {
	rule attack.RuleContext
}

// NewToolsUnauthExecutor creates an executor for the mcp-tools-unauth attack type.
func init() {
	attack.Register("mcp-tools-unauth", func(rc attack.RuleContext) attack.Executor { return NewToolsUnauthExecutor(rc) })
}

func NewToolsUnauthExecutor(r attack.RuleContext) *ToolsUnauthExecutor {
	return &ToolsUnauthExecutor{rule: r}
}

func (e *ToolsUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token - the rule tests whether tools are
	// accessible WITHOUT authentication. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, attack.ErrInconclusive // not an MCP server
	}

	// Skip servers that do not advertise the tools capability; probing them would
	// produce meaningless noise. Read from the captured handshake capabilities
	// rather than substring-matching the body.
	if !session.ServerSupports("tools") {
		return nil, nil
	}

	// Step 1: tools/list without any auth token.
	listResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !listResp.IsSuccess() {
		return nil, nil
	}

	var listBody map[string]interface{}
	if err := json.Unmarshal(listResp.Body, &listBody); err != nil {
		return nil, nil
	}

	// A JSON-RPC error means auth is enforced on tool methods - not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, nil
	}

	result, _ := listBody["result"].(map[string]interface{})
	toolsRaw, _ := result["tools"].([]interface{})
	if len(toolsRaw) == 0 {
		return nil, nil
	}

	// Collect tool names for evidence.
	var names []string
	for _, t := range toolsRaw {
		if tm, ok := t.(map[string]interface{}); ok {
			if name, ok := tm["name"].(string); ok {
				names = append(names, name)
			}
		}
	}

	findings := []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP tools/list returned %d tool(s) without authentication", len(names)),
		Description: fmt.Sprintf(
			"tools/list at %s returned %d tool(s) without any authentication, disclosing the server's "+
				"executable surface and each tool's input schema to an anonymous caller. The MCP spec "+
				"requires servers to implement proper access controls; an attacker can map the callable "+
				"functions and craft targeted invocations.", session.Endpoint, len(names)),
		Evidence:    fmt.Sprintf("HTTP %d from %s\ntools (%d): %v", listResp.StatusCode, session.Endpoint, len(names), names),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}

	// Step 2: confirm the tools/call dispatch path is reachable without auth,
	// WITHOUT executing any real tool. Calling a guaranteed non-existent tool name
	// yields a -32602 "Unknown tool" protocol error (per the MCP spec) and runs
	// nothing. Reaching that error proves the invocation path accepts
	// unauthenticated calls; an auth-enforcing server rejects with 401/403 or an
	// auth error before tool dispatch.
	bogusTool := "batesian-nonexistent-" + vars.RandID
	callResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": bogusTool, "arguments": map[string]interface{}{}},
	})
	if err != nil || !callResp.IsSuccess() {
		return findings, nil // auth gate (401/403) or unreachable; the list finding stands
	}

	var callBody map[string]interface{}
	if err := json.Unmarshal(callResp.Body, &callBody); err != nil {
		return findings, nil
	}

	reachable, reason := callDispatchReachable(callBody)
	if !reachable {
		return findings, nil
	}

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP tools/call dispatch reachable without authentication",
		Description: fmt.Sprintf(
			"tools/call at %s accepted an unauthenticated invocation request (probed with a non-existent "+
				"tool name, so nothing was executed). The invocation path to the server's tools is open to "+
				"anonymous callers, so any listed tool can be invoked without credentials.", session.Endpoint),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nprobe tool (non-existent): %s\n%s", callResp.StatusCode, session.Endpoint, bogusTool, reason),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	return findings, nil
}

// callDispatchReachable reports whether a tools/call response for a non-existent
// tool shows the invocation path was reached without auth. A -32602 ("unknown
// tool" / invalid params) protocol error or any result envelope means the server
// dispatched the call; a -32601 (method not found) or auth-flavored error does
// not. The returned reason is used as finding evidence.
func callDispatchReachable(body map[string]interface{}) (bool, string) {
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		code, _ := errObj["code"].(float64)
		if int(code) == -32602 {
			return true, "JSON-RPC error -32602 (unknown tool) returned for a non-existent tool, so the call was dispatched without auth"
		}
		return false, ""
	}
	if _, ok := body["result"]; ok {
		return true, "tools/call returned a result envelope for a non-existent tool, so the call was dispatched without auth"
	}
	return false, ""
}
