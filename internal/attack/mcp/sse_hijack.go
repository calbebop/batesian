package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ssePaths contains the paths where MCP servers commonly expose SSE streams.
var ssePaths = []string{
	"/mcp",
	"/",
	"/sse",
	"/events",
	"/stream",
	"/api",
}

// SSEHijackExecutor tests whether an MCP server's SSE endpoint can be connected
// to without authentication (rule mcp-sse-hijack-001).
//
// The SSE channel carries JSON-RPC responses including tool results, sampling
// outputs, and resource content. An unauthenticated subscriber could passively
// receive responses intended for legitimate sessions if the server does not
// isolate streams per authenticated session.
type SSEHijackExecutor struct {
	rule attack.RuleContext
}

// NewSSEHijackExecutor creates an executor for mcp-sse-hijack.
func NewSSEHijackExecutor(r attack.RuleContext) *SSEHijackExecutor {
	return &SSEHijackExecutor{rule: r}
}

func (e *SSEHijackExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token: the whole point of this check is to
	// determine whether an SSE connection can be established WITHOUT credentials.
	client := attack.NewUnauthHTTPClient(opts, vars)

	var findings []attack.Finding
	seen := map[string]bool{}

	for _, path := range ssePaths {
		ep := vars.BaseURL + path
		if seen[ep] {
			continue
		}
		seen[ep] = true

		// Send a GET with Accept: text/event-stream and no Authorization.
		resp, err := client.GET(ctx, ep, map[string]string{
			"Accept": "text/event-stream",
		})
		if err != nil {
			continue
		}

		// We're looking for a 200 with a text/event-stream content type.
		// A 401 or 403 is the correct behavior.
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			continue
		}

		ct := strings.ToLower(resp.Headers.Get("Content-Type"))
		if !strings.Contains(ct, "text/event-stream") && !strings.Contains(ct, "application/json") {
			continue
		}

		// Check whether the server returned actual SSE data in the response.
		bodyStr := string(resp.Body)
		hasData := strings.Contains(bodyStr, "data:") ||
			strings.Contains(bodyStr, "event:") ||
			strings.Contains(bodyStr, `"jsonrpc"`)

		severity := "high"
		var confidence attack.Confidence
		title := fmt.Sprintf("MCP SSE stream at %s accepted without authentication (HTTP %d)", ep, resp.StatusCode)
		description := fmt.Sprintf(
			"A GET request to %s with Accept: text/event-stream and no Authorization header "+
				"was accepted with HTTP %d and Content-Type %q. Any network-adjacent attacker "+
				"can open an SSE connection and potentially receive JSON-RPC events intended "+
				"for authenticated sessions.",
			ep, resp.StatusCode, ct)
		evidence := fmt.Sprintf("GET %s\nAccept: text/event-stream\n(no Authorization)\nHTTP %d\nContent-Type: %s\nResponse snippet: %.300s",
			ep, resp.StatusCode, ct, bodyStr)

		if hasData {
			// Server streamed actual data -- elevated severity
			severity = "high"
			confidence = attack.ConfirmedExploit
			title = fmt.Sprintf(
				"MCP SSE stream at %s returned data events without authentication (HTTP %d)",
				ep, resp.StatusCode)
			description += "\n\nThe server returned actual SSE data events in the unauthenticated response, " +
				"confirming that real content is accessible."
		} else {
			// Connection accepted but no data yet -- still a finding
			confidence = attack.RiskIndicator
		}

		findings = append(findings, attack.Finding{
			RuleID:      e.rule.ID,
			RuleName:    e.rule.Name,
			Severity:    severity,
			Confidence:  confidence,
			Title:       title,
			Description: description,
			Evidence:    evidence,
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		})

		// Found a vulnerable endpoint; no need to check remaining paths.
		break
	}

	return findings, nil
}
