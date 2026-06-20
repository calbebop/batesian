package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// HeaderBodySplitExecutor tests for the SEP-2243 header/body routing split-brain
// (rule mcp-header-body-split-001): a Streamable HTTP server that enforces the
// presence of the Mcp-Method routing header but does not validate that its value
// matches the JSON-RPC body method.
type HeaderBodySplitExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-header-body-split", func(rc attack.RuleContext) attack.Executor {
		return NewHeaderBodySplitExecutor(rc)
	})
}

func NewHeaderBodySplitExecutor(r attack.RuleContext) *HeaderBodySplitExecutor {
	return &HeaderBodySplitExecutor{rule: r}
}

func (e *HeaderBodySplitExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	for _, ep := range endpointCandidates(vars.BaseURL) {
		if f := e.probe(ctx, client, ep); f != nil {
			return f, nil
		}
	}
	return nil, nil
}

func (e *HeaderBodySplitExecutor) probe(ctx context.Context, client *attack.HTTPClient, ep string) []attack.Finding {
	session, ok := e.initialize(ctx, client, ep)
	if !ok {
		return nil // not an MCP endpoint here
	}

	// Probe 1: omit Mcp-Method. If the server still executes tools/list, it does
	// not enforce header presence (not SEP-2243-aware) - nothing to confirm.
	if e.toolsList(ctx, client, ep, session, nil) {
		return nil
	}

	// Probe 2: matching Mcp-Method. Must be accepted, otherwise we cannot drive
	// the mismatch test (the endpoint may require headers we are not sending).
	matched := "tools/list"
	if !e.toolsList(ctx, client, ep, session, &matched) {
		return nil
	}

	// Probe 3: mismatched Mcp-Method. A compliant server MUST reject; if it
	// executes the body's tools/list, header value is not validated.
	mismatched := "tools/call"
	if e.toolsList(ctx, client, ep, session, &mismatched) {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP server enforces Mcp-Method presence but not header/body consistency (SEP-2243 split-brain)",
			Description: fmt.Sprintf(
				"At %s, a tools/list request was REJECTED when the Mcp-Method header was omitted (the "+
					"server enforces header presence), but a tools/list request with a MISMATCHED "+
					"Mcp-Method: tools/call header was still EXECUTED as tools/list. The MCP Streamable "+
					"HTTP spec requires rejecting such a mismatch with 400 / -32020 (HeaderMismatch). "+
					"Because the header is enforced for "+
					"presence but not value, an intermediary that routes or rate-limits on Mcp-Method can "+
					"be bypassed by labelling a sensitive body operation with an innocuous method.",
				ep),
			Evidence: fmt.Sprintf(
				"endpoint: %s\nomit Mcp-Method: rejected (presence enforced)\nMcp-Method: tools/list (match): executed\n"+
					"Mcp-Method: tools/call (mismatch) + body tools/list: EXECUTED body (should be 400/-32020)",
				ep),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}}
	}
	return nil
}

// initialize performs an MCP initialize (sending a matching Mcp-Method so a
// header-enforcing server accepts it) and returns the session.
func (e *HeaderBodySplitExecutor) initialize(ctx context.Context, client *attack.HTTPClient, ep string) (mcpSession, bool) {
	resp, err := client.POST(ctx, ep, map[string]string{"Mcp-Method": "initialize"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || !resp.IsSuccess() {
		return mcpSession{}, false
	}
	if !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return mcpSession{}, false
	}
	session := mcpSession{Endpoint: ep, SessionID: resp.Headers.Get("Mcp-Session-Id"), RawInit: resp.Body}
	initedHeaders := session.header()
	if initedHeaders == nil {
		initedHeaders = map[string]string{}
	}
	initedHeaders["Mcp-Method"] = "notifications/initialized"
	_, _ = client.POST(ctx, ep, initedHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	return session, true
}

// toolsList sends a tools/list body. methodHeader controls the Mcp-Method header:
// nil omits it; otherwise it is set to the given (possibly mismatched) value. It
// reports whether the server EXECUTED tools/list (returned a result.tools array).
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, ep string, session mcpSession, methodHeader *string) bool {
	headers := session.header()
	if headers == nil {
		headers = map[string]string{}
	}
	if methodHeader != nil {
		headers["Mcp-Method"] = *methodHeader
	}
	resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return false
	}
	var b map[string]interface{}
	if json.Unmarshal(resp.Body, &b) != nil {
		return false
	}
	if _, hasErr := b["error"]; hasErr {
		return false
	}
	result, ok := b["result"].(map[string]interface{})
	if !ok {
		return false
	}
	_, hasTools := result["tools"]
	return hasTools
}
