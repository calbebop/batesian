package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	burstSize       = 25 // Number of requests to send in the burst
	burstWindowSecs = 3  // Maximum seconds the burst should take
)

// RateLimitAbsentExecutor sends a burst of tool call requests and checks whether
// the server enforces rate limiting (rule mcp-ratelimit-absent-001).
type RateLimitAbsentExecutor struct {
	rule attack.RuleContext
}

// NewRateLimitAbsentExecutor creates an executor for mcp-ratelimit-absent.
func NewRateLimitAbsentExecutor(r attack.RuleContext) *RateLimitAbsentExecutor {
	return &RateLimitAbsentExecutor{rule: r}
}

func (e *RateLimitAbsentExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Initialize session to confirm MCP target and discover a tool name.
	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, nil
	}

	toolName := "echo"
	tools, _, tlErr := listMCPTools(ctx, client, vars.BaseURL)
	if tlErr == nil && len(tools) > 0 {
		if n, ok := tools[0]["name"].(string); ok && n != "" {
			toolName = n
		}
	}

	// Burst: send requests as fast as possible with a per-request timeout of 2s.
	// We don't care about the response content -- only the status codes.
	burstCtx, cancel := context.WithTimeout(ctx, time.Duration(burstWindowSecs)*time.Second)
	defer cancel()

	var (
		accepted  atomic.Int32 // 2xx + non-429 responses
		throttled atomic.Int32 // 429 or "rate limit" JSON-RPC errors
		errs      atomic.Int32
	)

	// Fire requests sequentially (not goroutines) to avoid connection pool exhaustion
	// and to keep the finding deterministic. Sequential burst is sufficient to trigger
	// server-side rate limiting.
	for i := 0; i < burstSize; i++ {
		if burstCtx.Err() != nil {
			break
		}
		resp, err := client.POST(burstCtx, session.Endpoint, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      100 + i,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      toolName,
				"arguments": map[string]interface{}{"input": "batesian-ratelimit-probe"},
			},
		})
		if err != nil {
			errs.Add(1)
			continue
		}

		if resp.StatusCode == 429 {
			throttled.Add(1)
		} else if strings.Contains(strings.ToLower(string(resp.Body)), "rate limit") ||
			strings.Contains(strings.ToLower(string(resp.Body)), "too many") {
			throttled.Add(1)
		} else {
			accepted.Add(1)
		}
	}

	sent := accepted.Load() + throttled.Load() + errs.Load()
	if sent == 0 {
		return nil, nil
	}

	// If the server throttled at least some requests, it has rate limiting.
	if throttled.Load() > 0 {
		return nil, nil
	}

	// No throttling observed across all requests.
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf(
			"MCP server accepted all %d burst tool call requests with no rate limiting (0/%d throttled)",
			accepted.Load(), sent),
		Description: fmt.Sprintf(
			"The MCP server at %s accepted %d tool call requests sent in rapid succession "+
				"without returning any HTTP 429 or rate-limit error. Without rate limiting, "+
				"a single client can monopolize server resources or downstream API quota, "+
				"and context window flooding attacks can be sustained indefinitely.",
			session.Endpoint, accepted.Load()),
		Evidence: fmt.Sprintf(
			"burst of %d requests to %s (tool: %q)\naccepted: %d, throttled: %d, errors: %d",
			burstSize, session.Endpoint, toolName,
			accepted.Load(), throttled.Load(), errs.Load()),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}}, nil
}
