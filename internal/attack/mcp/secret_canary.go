package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// SecretCanaryExecutor presents a unique canary bearer token to an MCP server and
// reports if the server reflects that credential verbatim into any response body
// (rule mcp-secret-canary-001).
type SecretCanaryExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-secret-canary", func(rc attack.RuleContext) attack.Executor {
		return NewSecretCanaryExecutor(rc)
	})
}

func NewSecretCanaryExecutor(r attack.RuleContext) *SecretCanaryExecutor {
	return &SecretCanaryExecutor{rule: r}
}

func (e *SecretCanaryExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	canary := "batesian-canary-" + randomHex(16)

	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Override the token with the canary so it is the only credential presented.
	canaryOpts := opts
	canaryOpts.Token = canary
	client := attack.NewHTTPClient(canaryOpts, vars)

	return probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		return e.probe(ctx, client, ep, canary)
	})
}

func (e *SecretCanaryExecutor) probe(ctx context.Context, client *attack.HTTPClient, ep, canary string) ([]attack.Finding, bool) {
	applicable := false
	reflectedIn := ""

	record := func(body string) {
		if body == "" {
			return
		}
		if looksJSONRPC(body) {
			applicable = true
		}
		if reflectedIn == "" && strings.Contains(body, canary) {
			reflectedIn = body
		}
	}

	// initialize
	initResp, err := client.POST(ctx, ep, map[string]string{"Mcp-Method": "initialize"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	var session mcpSession
	if err == nil {
		record(initResp.BodyString())
		session = mcpSession{Endpoint: ep, SessionID: initResp.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(initResp.Body)}
	}

	// A handful of further calls, including a malformed one to elicit verbose
	// errors that naive servers fill with request/auth context.
	probes := []map[string]interface{}{
		{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]interface{}{}},
		{"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": map[string]interface{}{}},
		{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]interface{}{"name": ""}},
	}
	for _, p := range probes {
		resp, perr := client.POST(ctx, ep, session.header(), p)
		if perr == nil {
			record(resp.BodyString())
		}
	}

	if !applicable || reflectedIn == "" {
		// applicable == false means no JSON-RPC/MCP-shaped response was seen
		// (not an MCP endpoint); applicable == true with no reflection is secure.
		return nil, applicable
	}

	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server reflects the caller's bearer credential into a response",
		Description: fmt.Sprintf(
			"At %s, a unique canary bearer token presented by the client was returned verbatim in an MCP "+
				"response body. Copying credentials into protocol output means the secret flows into any sink that "+
				"records responses - server logs, distributed traces, error trackers, shared SSE streams, and "+
				"client-side console output - exposing it to anyone with access to those sinks.", ep),
		Evidence: fmt.Sprintf("endpoint: %s\ncanary token: %s\nreflected in response: %s",
			ep, canary, snippetAround(reflectedIn, canary)),
		Remediation: e.rule.Remediation,
		TargetURL:   ep,
	}}, true
}

// looksJSONRPC reports whether a response body resembles a JSON-RPC / MCP reply,
// used to scope the rule to MCP endpoints rather than arbitrary HTTP servers.
func looksJSONRPC(body string) bool {
	return strings.Contains(body, `"jsonrpc"`) || strings.Contains(body, `"result"`) ||
		strings.Contains(body, `"error"`) || strings.Contains(body, `"protocolVersion"`)
}

// snippetAround returns a short window of text surrounding the first occurrence
// of needle, so evidence shows the reflection context without dumping the body.
func snippetAround(body, needle string) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 40
	if end > len(body) {
		end = len(body)
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "..."
	}
	if end < len(body) {
		suffix = "..."
	}
	return prefix + body[start:end] + suffix
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "fallbackcanary"
	}
	return hex.EncodeToString(b)
}
