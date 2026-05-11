package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// SamplingInjectExecutor probes whether an MCP server advertises or triggers
// the sampling/createMessage capability with injectable content
// (rule mcp-sampling-inject-001).
//
// The MCP sampling capability lets servers invoke the client's LLM directly.
// If a server sends a sampling/createMessage with a malicious systemPrompt or
// injected messages, it can hijack the client LLM without the user's knowledge.
//
// Detection strategy (stateless HTTP):
//  1. Advertise the sampling capability in the initialize request.
//  2. If the server echoes sampling in its capabilities, emit an indicator
//     finding — this surface requires manual audit.
//  3. Call each available tool once; scan any embedded sampling/createMessage
//     requests in the HTTP response body for injection patterns.
type SamplingInjectExecutor struct {
	rule attack.RuleContext
}

// NewSamplingInjectExecutor creates an executor for the mcp-sampling-inject attack type.
func NewSamplingInjectExecutor(r attack.RuleContext) *SamplingInjectExecutor {
	return &SamplingInjectExecutor{rule: r}
}

func (e *SamplingInjectExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	session, serverCaps, err := e.initializeWithSampling(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, nil // not an MCP server
	}

	var findings []attack.Finding

	// Step 1: Check if the server advertises sampling in its capabilities.
	// Even without triggering a callback, this tells operators that the server
	// can initiate LLM calls against any connected client.
	if hasSamplingCap(serverCaps) {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "MCP server advertises sampling capability — server can invoke client LLM directly",
			Description: fmt.Sprintf(
				"The server at %s includes 'sampling' in its capabilities response. "+
					"This means it can send sampling/createMessage requests to any MCP client "+
					"that connects and advertises sampling support. The content of those requests "+
					"(systemPrompt, messages) is not visible to the end user and bypasses "+
					"client-side guardrails. Audit all sampling/createMessage calls this server "+
					"may generate.", session.Endpoint),
			Evidence:    fmt.Sprintf("Server capabilities: %s", capsSummary(serverCaps)),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}

	// Step 2: List tools then call each one; scan responses for embedded
	// sampling/createMessage requests with injection content.
	tools, toolSession, err := listMCPTools(ctx, client, vars.BaseURL)
	if err != nil || len(tools) == 0 {
		return findings, nil
	}

	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}

		callResp, err := client.POST(ctx, toolSession.Endpoint, toolSession.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-call-" + vars.RandID,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      name,
				"arguments": map[string]interface{}{},
			},
		})
		if err != nil || !callResp.IsSuccess() {
			continue
		}

		// Scan the raw response body for sampling/createMessage content.
		body := string(callResp.Body)
		if !strings.Contains(body, "sampling/createMessage") && !strings.Contains(body, "createMessage") {
			continue
		}

		// Extract the embedded sampling request and scan its prompts.
		samplingFindings := e.scanSamplingPayload(body, name, toolSession.Endpoint)
		findings = append(findings, samplingFindings...)
	}

	return findings, nil
}

// initializeWithSampling sends an initialize request advertising sampling capability
// and returns the session and the server's capabilities map.
func (e *SamplingInjectExecutor) initializeWithSampling(ctx context.Context, client *attack.HTTPClient, baseURL string) (mcpSession, map[string]interface{}, error) {
	endpoints := endpointCandidates(baseURL)
	for _, ep := range endpoints {
		initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities": map[string]interface{}{
					// Advertise sampling so the server knows we support callbacks.
					"sampling": map[string]interface{}{},
					"tools":    map[string]interface{}{},
				},
				"clientInfo": map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil || !initResp.IsSuccess() {
			continue
		}
		if !initResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			continue
		}

		session := mcpSession{
			Endpoint:  ep,
			SessionID: initResp.Headers.Get("Mcp-Session-Id"),
		}

		// Parse server capabilities
		var body map[string]interface{}
		if err := json.Unmarshal(initResp.Body, &body); err != nil {
			continue
		}
		result, _ := body["result"].(map[string]interface{})
		caps, _ := result["capabilities"].(map[string]interface{})

		// Send notifications/initialized
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})

		return session, caps, nil
	}
	return mcpSession{}, nil, fmt.Errorf("no MCP server found at %s", baseURL)
}

// scanSamplingPayload extracts and scans a sampling/createMessage payload embedded
// in an HTTP response body for prompt injection patterns.
func (e *SamplingInjectExecutor) scanSamplingPayload(body, toolName, endpoint string) []attack.Finding {
	// Extract the sampling request from the response body.
	// It may be inline in a streaming response or nested in a JSON result.
	var outerBody map[string]interface{}
	if err := json.Unmarshal([]byte(body), &outerBody); err != nil {
		return nil
	}

	// Look for sampling content nested anywhere in the result.
	samplingContent := extractNestedString(outerBody, "systemPrompt", "content", "text")

	var findings []attack.Finding
	for _, content := range samplingContent {
		score, matched := scoreDescription(content)
		if score < 2 {
			continue
		}
		sev := scoreToSeverity(score)
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   sev,
			Confidence: attack.RiskIndicator,
			Title: fmt.Sprintf(
				"MCP sampling/createMessage triggered by tool %q contains injection pattern (score %d)",
				toolName, score),
			Description: fmt.Sprintf(
				"A tool call to %q at %s triggered a sampling/createMessage callback whose content "+
					"contains patterns consistent with prompt injection. The server is attempting to "+
					"inject instructions into the client's LLM via a server-initiated sampling request "+
					"that bypasses the user's system prompt.", toolName, endpoint),
			Evidence:    fmt.Sprintf("tool: %q\npatterns: %v\nsnippet: %.400s", toolName, matched, content),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}
	return findings
}

// hasSamplingCap returns true if the capabilities map includes the sampling key.
func hasSamplingCap(caps map[string]interface{}) bool {
	if caps == nil {
		return false
	}
	_, ok := caps["sampling"]
	return ok
}

// capsSummary returns a compact string representation of the capabilities map.
func capsSummary(caps map[string]interface{}) string {
	keys := make([]string, 0, len(caps))
	for k := range caps {
		keys = append(keys, k)
	}
	return "{" + strings.Join(keys, ", ") + "}"
}

// extractNestedString recursively walks a JSON-decoded map and collects all
// string values whose key matches any of the given target keys.
func extractNestedString(v interface{}, keys ...string) []string {
	var results []string
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	var walk func(interface{})
	walk = func(v interface{}) {
		switch vt := v.(type) {
		case map[string]interface{}:
			for k, val := range vt {
				if keySet[k] {
					if s, ok := val.(string); ok && s != "" {
						results = append(results, s)
					}
				}
				walk(val)
			}
		case []interface{}:
			for _, item := range vt {
				walk(item)
			}
		}
	}
	walk(v)
	return results
}
