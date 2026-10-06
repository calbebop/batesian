package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

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
	suffix, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generating canary: %w", err)
	}
	canary := "batesian-canary-" + suffix

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
	reflectedAt := ""

	record := func(resp *attack.Response, at string) {
		if resp == nil {
			return
		}
		body := resp.BodyString()
		if reflectedIn == "" && strings.Contains(body, canary) {
			reflectedIn = body
			reflectedAt = at
		}
	}

	// initialize
	initResp, err := client.POST(ctx, ep, map[string]string{"Mcp-Method": "initialize"}, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": latestStable,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err == nil && initResp != nil {
		record(initResp, "legacy initialize")
		if isMCPInitialize(initResp) {
			applicable = true
			session := mcpSession{Endpoint: ep, Era: EraLegacy, SessionID: initResp.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(initResp.Body)}
			initialized, _ := client.POST(ctx, ep, session.header(), map[string]interface{}{
				"jsonrpc": "2.0", "method": "notifications/initialized",
			})
			record(initialized, "legacy notifications/initialized")
			for i, method := range []string{"tools/list", "resources/list"} {
				resp, _ := session.post(ctx, client, i+2, method, nil)
				record(resp, "legacy "+method)
			}
		}
	}

	modern := mcpSession{Endpoint: ep, Era: EraModern}
	discover, _ := modern.post(ctx, client, 4, "server/discover", nil)
	record(discover, "modern server/discover")
	if discover != nil && ((discover.IsAccepted() && modernWireAdvertised(discover.Body)) ||
		(authRefusal(discover) && hasBearerChallenge(discover))) {
		applicable = true
	}
	for i, method := range []string{"tools/list", "resources/list"} {
		resp, _ := modern.post(ctx, client, i+5, method, nil)
		record(resp, "modern "+method)
	}

	if !applicable && reflectedIn != "" && looksJSONRPC(reflectedIn) {
		applicable = true
	}

	if !applicable || reflectedIn == "" {
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
		Evidence: fmt.Sprintf("endpoint: %s\nrequest: %s\ncanary token: %s\nreflected in response: %s",
			ep, reflectedAt, canary, snippetAround(reflectedIn, canary)),
		Remediation: e.rule.Remediation,
		TargetURL:   ep,
	}}, true
}

// looksJSONRPC rejects generic JSON errors that only resemble MCP replies.
func looksJSONRPC(body string) bool {
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	return json.Unmarshal([]byte(body), &envelope) == nil && envelope.JSONRPC == "2.0" &&
		(envelope.Result != nil || envelope.Error != nil)
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
	// Both window edges are byte offsets into arbitrary response text. Move each
	// to a rune boundary so a multi-byte character is never split: the snippet
	// ends up in Finding.Evidence, which is marshalled to JSON/SARIF, where a
	// partial rune is silently rewritten to U+FFFD.
	for start < end && !utf8.RuneStart(body[start]) {
		start++
	}
	for end > start && end < len(body) && !utf8.RuneStart(body[end]) {
		end--
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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
