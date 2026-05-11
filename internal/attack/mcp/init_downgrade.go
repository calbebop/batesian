package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// InitDowngradeExecutor probes whether an MCP server accepts the pre-auth
// protocol version "2024-11-05" and, if so, whether it still returns
// capabilities or data without requiring authentication
// (rule mcp-init-downgrade-001).
type InitDowngradeExecutor struct {
	rule attack.RuleContext
}

// NewInitDowngradeExecutor creates an executor for mcp-init-downgrade.
func NewInitDowngradeExecutor(r attack.RuleContext) *InitDowngradeExecutor {
	return &InitDowngradeExecutor{rule: r}
}

// legacyVersion is the pre-OAuth MCP spec version published before authorization
// was mandated. Advertising this version may bypass server-side auth checks.
const legacyVersion = "2024-11-05"

func (e *InitDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	endpoints := endpointCandidates(vars.BaseURL)

	for _, ep := range endpoints {
		findings := e.probeEndpoint(ctx, client, ep)
		if findings == nil {
			continue
		}
		return findings, nil
	}
	return nil, nil
}

func (e *InitDowngradeExecutor) probeEndpoint(ctx context.Context, client *attack.HTTPClient, ep string) []attack.Finding {
	// Step 1: send initialize with the legacy pre-auth protocol version.
	initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": legacyVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || !initResp.IsSuccess() {
		return nil
	}

	body := initResp.BodyString()

	// Server rejected the version explicitly -- not vulnerable.
	if strings.Contains(body, `"error"`) && !strings.Contains(body, `"protocolVersion"`) {
		return nil
	}

	// Must look like a real MCP initialize response.
	if !initResp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return nil
	}

	// Parse what version the server actually negotiated back.
	var parsed map[string]interface{}
	_ = json.Unmarshal(initResp.Body, &parsed)
	result, _ := parsed["result"].(map[string]interface{})
	negotiated, _ := result["protocolVersion"].(string)

	sessionID := initResp.Headers.Get("Mcp-Session-Id")
	session := mcpSession{Endpoint: ep, SessionID: sessionID}

	// Send notifications/initialized.
	_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	var findings []attack.Finding

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.RiskIndicator,
		Title: fmt.Sprintf(
			"MCP server accepted legacy protocol version %q (expected rejection)", legacyVersion),
		Description: fmt.Sprintf(
			"The server at %s accepted an initialize request with protocolVersion %q, "+
				"which predates the MCP authorization specification. The server negotiated "+
				"version %q in its response. A server that does not reject unsupported or "+
				"outdated versions may bypass auth enforcement tied to specific protocol versions.",
			ep, legacyVersion, negotiated),
		Evidence:    fmt.Sprintf("POST %s\nRequest protocolVersion: %q\nServer negotiated: %q\nHTTP %d", ep, legacyVersion, negotiated, initResp.StatusCode),
		Remediation: e.rule.Remediation,
		TargetURL:   ep,
	})

	// Step 2: try to call resources/list — if it succeeds, downgrade bypassed auth.
	resourcesResp, err := client.POST(ctx, ep, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	})
	if err == nil && resourcesResp.IsSuccess() {
		var rb map[string]interface{}
		_ = json.Unmarshal(resourcesResp.Body, &rb)
		if _, hasErr := rb["error"]; !hasErr {
			if result, ok := rb["result"].(map[string]interface{}); ok {
				if resources, ok := result["resources"].([]interface{}); ok && len(resources) > 0 {
					findings = append(findings, attack.Finding{
						RuleID:     e.rule.ID,
						RuleName:   e.rule.Name,
						Severity:   "critical",
						Confidence: attack.ConfirmedExploit,
						Title: fmt.Sprintf(
							"resources/list returned %d resource(s) after protocol version downgrade to %q",
							len(resources), legacyVersion),
						Description: fmt.Sprintf(
							"After initializing with the legacy protocol version %q, the server at %s "+
								"returned %d resource(s) from resources/list without requiring authentication. "+
								"This confirms that the version downgrade bypasses auth enforcement on the "+
								"resources endpoint.",
							legacyVersion, ep, len(resources)),
						Evidence:    fmt.Sprintf("HTTP %d from %s after downgrade\nresources/list returned %d item(s)", resourcesResp.StatusCode, ep, len(resources)),
						Remediation: e.rule.Remediation,
						TargetURL:   ep,
					})
				}
			}
		}
	}

	return findings
}
