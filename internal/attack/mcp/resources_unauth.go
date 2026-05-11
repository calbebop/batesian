package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/calbebop/batesian/internal/attack"
)

// credentialPatterns detects secrets and credentials in resource content.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),                              // AWS access key
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{32,}`),                           // OpenAI API key
	regexp.MustCompile(`(?i)(api[_-]?key|api[_-]?secret)\s*[=:]\s*\S{10,}`), // Generic API key
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S{6,}`),         // Password
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),   // Private keys
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),                           // GitHub token
	regexp.MustCompile(`(?i)(bearer|authorization)\s*[=:]\s*\S{10,}`),       // Bearer/auth token
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}`),     // JWT
}

// ResourcesUnauthExecutor probes MCP resources/list and resources/read without
// authentication (rule mcp-resources-unauth-001).
//
// Unlike tool poisoning (LLM-mediated), resource disclosure is immediate:
// the attacker retrieves data directly. Resources can contain file system
// contents, database records, environment variables, or API credentials.
type ResourcesUnauthExecutor struct {
	rule attack.RuleContext
}

// NewResourcesUnauthExecutor creates an executor for the mcp-resources-unauth attack type.
func NewResourcesUnauthExecutor(r attack.RuleContext) *ResourcesUnauthExecutor {
	return &ResourcesUnauthExecutor{rule: r}
}

func (e *ResourcesUnauthExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Deliberately omit the bearer token so the probe represents unauthenticated
	// access. Findings claim resources are accessible WITHOUT authentication; if
	// opts.Token were injected the finding would be misleading.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// MCP requires an initialize handshake before any method calls.
	session, err := initializeMCP(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, nil // not an MCP server
	}

	var findings []attack.Finding

	// Step 1: resources/list — enumerate available resources
	listResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !listResp.IsSuccess() {
		return nil, nil
	}

	var listBody map[string]interface{}
	if err := json.Unmarshal(listResp.Body, &listBody); err != nil {
		return nil, nil
	}

	// JSON-RPC error means the endpoint exists but rejected the call — not vulnerable.
	if _, hasErr := listBody["error"]; hasErr {
		return nil, nil
	}

	result, _ := listBody["result"].(map[string]interface{})
	resourcesRaw, _ := result["resources"].([]interface{})
	if len(resourcesRaw) == 0 {
		return nil, nil
	}

	// Build a display list of resource URIs
	var uris []string
	for _, r := range resourcesRaw {
		if rm, ok := r.(map[string]interface{}); ok {
			if uri, ok := rm["uri"].(string); ok {
				uris = append(uris, uri)
			}
		}
	}

	findings = append(findings, attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("MCP resources/list accessible without authentication (%d resources)", len(uris)),
		Description: fmt.Sprintf(
			"resources/list at %s returned %d resources without any authentication. "+
				"An attacker can enumerate all available data sources and then read their contents "+
				"using resources/read.", session.Endpoint, len(uris)),
		Evidence:    fmt.Sprintf("HTTP %d from %s\nresources (%d): %v", listResp.StatusCode, session.Endpoint, len(uris), uris),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	// Step 2: read the first resource
	if len(uris) == 0 {
		return findings, nil
	}

	readResp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": uris[0]},
	})
	if err != nil || !readResp.IsSuccess() {
		return findings, nil
	}

	var readBody map[string]interface{}
	if err := json.Unmarshal(readResp.Body, &readBody); err != nil {
		return findings, nil
	}
	if _, hasErr := readBody["error"]; hasErr {
		return findings, nil
	}

	content := string(readResp.Body)
	sev := "critical"

	// Escalate severity if credentials are found in the content
	var credEvidence string
	for _, re := range credentialPatterns {
		if loc := re.FindStringIndex(content); loc != nil {
			credEvidence = fmt.Sprintf("Pattern matched: %s at byte offset %d", re.String(), loc[0])
			sev = "critical"
			break
		}
	}

	evidenceLines := fmt.Sprintf("HTTP %d from %s\nresource URI: %s\ncontent snippet: %.400s", readResp.StatusCode, session.Endpoint, uris[0], content)
	title := fmt.Sprintf("MCP resource %q content readable without authentication", uris[0])
	description := fmt.Sprintf("resources/read for %s returned content without authentication. "+
		"Resource data is directly accessible to any unauthenticated caller.", uris[0])

	if credEvidence != "" {
		title = fmt.Sprintf("MCP resource %q contains potential credentials and is readable without authentication", uris[0])
		description += "\n\nCredential pattern detected in content: " + credEvidence
		evidenceLines += "\n" + credEvidence
	}

	findings = append(findings, attack.Finding{
		RuleID:      e.rule.ID,
		RuleName:    e.rule.Name,
		Severity:    sev,
		Confidence:  attack.ConfirmedExploit,
		Title:       title,
		Description: description,
		Evidence:    evidenceLines,
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	})

	return findings, nil
}

// initializeMCP performs the MCP initialize handshake and returns a session
// containing the working endpoint and the Mcp-Session-Id header value (if any).
// Servers implementing MCP 2025-03-26 require the session ID on all follow-up
// requests; omitting it causes 4xx errors that silently suppress findings.
func initializeMCP(ctx context.Context, client *attack.HTTPClient, baseURL string) (mcpSession, error) {
	endpoints := endpointCandidates(baseURL)
	for _, ep := range endpoints {
		initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
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

		// notifications/initialized — fire and forget
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})

		return session, nil
	}

	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}
