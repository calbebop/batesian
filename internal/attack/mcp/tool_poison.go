package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// poisonPattern is a named regex pattern with a heuristic score and category.
type poisonPattern struct {
	name     string
	re       *regexp.Regexp
	score    int
	category string
}

// poisonPatterns covers the major classes of MCP tool description injection.
// Scoring is additive; thresholds map to CVSS-inspired severity levels.
var poisonPatterns = []poisonPattern{
	// Instruction override — high signal, core injection patterns
	{"instruction_override", regexp.MustCompile(`(?i)IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS`), 5, "injection"},
	{"system_directive", regexp.MustCompile(`(?i)[\[<(]SYSTEM\s*:`), 5, "injection"},
	{"chatml_injection", regexp.MustCompile(`(?i)<\|im_start\|>\s*(system|assistant|user)\b`), 5, "injection"},
	{"llama_injection", regexp.MustCompile(`(?i)(\[INST\]|<<SYS>>|\[/INST\]|</s>)`), 5, "injection"},
	{"openai_role_tag", regexp.MustCompile(`(?i)<\|(system|assistant|endoftext)\|>`), 4, "injection"},
	{"important_tag", regexp.MustCompile(`(?i)<IMPORTANT>|<CRITICAL>|<URGENT>`), 3, "injection"},
	{"note_override", regexp.MustCompile(`(?i)\[NOTE\s*:.*(?:ignore|override|bypass|disregard)`), 4, "injection"},

	// LLM behavioral directives
	{"you_must", regexp.MustCompile(`(?i)\byou\s+(must|should|need to|have to|are required to)\b`), 2, "directive"},
	{"always_first", regexp.MustCompile(`(?i)\b(always|first)\s+(send|include|add|provide|attach|append)\b`), 2, "directive"},
	{"before_responding", regexp.MustCompile(`(?i)before\s+(responding|answering|executing|proceeding)`), 2, "directive"},
	{"do_not_tell", regexp.MustCompile(`(?i)\bdo\s+not\s+(tell|inform|reveal|mention|disclose)\b`), 3, "directive"},

	// Exfiltration patterns
	{"exfil_url_with_path", regexp.MustCompile(`https?://[^\s"']{15,}`), 2, "exfiltration"},
	{"exfil_verbs", regexp.MustCompile(`(?i)\b(exfiltrate|exfil|leak|steal|collect|capture|harvest)\b`), 4, "exfiltration"},
	{"send_to_url", regexp.MustCompile(`(?i)(send|post|upload|transmit)\s+.{0,50}\s+to\s+https?://`), 4, "exfiltration"},
	{"sensitive_file_path", regexp.MustCompile(`(?i)(~/\.ssh|/etc/passwd|/etc/shadow|\.env\b|id_rsa|\.aws/credentials|\.netrc)`), 5, "exfiltration"},
	{"env_variable_access", regexp.MustCompile(`(?i)\b(env|environment|process\.env)\b.{0,30}\b(key|secret|password|token)\b`), 3, "exfiltration"},

	// Obfuscation
	{"base64_blob", regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`), 3, "obfuscation"},
	{"html_comment", regexp.MustCompile(`(?s)<!--.{5,}-->`), 3, "obfuscation"},
	// Unicode tag block (U+E0000-U+E007F) used for invisible text injection
	{"unicode_tag_block", regexp.MustCompile(`[\x{E0000}-\x{E007F}]`), 4, "obfuscation"},
	{"zero_width_chars", regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}`), 3, "obfuscation"},

	// Cross-server manipulation
	{"disable_other_tools", regexp.MustCompile(`(?i)(disable|override|ignore|bypass|shadow|replace).{0,40}(tool|server|plugin|function)`), 3, "cross_server"},

	// Credential harvesting
	{"credential_keywords", regexp.MustCompile(`(?i)\b(password|secret|api.?key|auth.?token|bearer|private.?key|ssh.?key)\b`), 2, "credential"},
}

func scoreToSeverity(score int) string {
	switch {
	case score >= 12:
		return "critical"
	case score >= 8:
		return "high"
	case score >= 5:
		return "medium"
	case score >= 3:
		return "low"
	default:
		return "info"
	}
}

func scoreDescription(desc string) (totalScore int, matched []string) {
	for _, p := range poisonPatterns {
		if p.re.MatchString(desc) {
			totalScore += p.score
			matched = append(matched, fmt.Sprintf("%s(+%d)", p.name, p.score))
		}
	}
	return totalScore, matched
}

// ToolPoisonExecutor implements the MCP tool description poisoning / rug pull
// scanner (rule mcp-tool-poison-001).
type ToolPoisonExecutor struct {
	rule attack.RuleContext
}

// NewToolPoisonExecutor creates an executor for the mcp-tool-poisoning attack type.
func NewToolPoisonExecutor(r attack.RuleContext) *ToolPoisonExecutor {
	return &ToolPoisonExecutor{rule: r}
}

func (e *ToolPoisonExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// First call to tools/list
	tools1, session, err := listMCPTools(ctx, client, vars.BaseURL)
	if err != nil || len(tools1) == 0 {
		return nil, nil // not an MCP server or no tools available
	}

	var findings []attack.Finding

	for _, tool := range tools1 {
		name, _ := tool["name"].(string)
		desc, _ := tool["description"].(string)

		// Scan tool description
		if f := e.scanDescription(ctx, name, desc, "description", session.Endpoint); f != nil {
			findings = append(findings, f...)
		}

		// Scan inputSchema property descriptions
		if schema, ok := tool["inputSchema"].(map[string]interface{}); ok {
			if props, ok := schema["properties"].(map[string]interface{}); ok {
				for propName, propRaw := range props {
					prop, _ := propRaw.(map[string]interface{})
					propDesc, _ := prop["description"].(string)
					field := fmt.Sprintf("inputSchema.properties.%s.description", propName)
					if f := e.scanDescription(ctx, name, propDesc, field, session.Endpoint); f != nil {
						findings = append(findings, f...)
					}
				}
			}
		}
	}

	// Rug pull: call tools/list a second time after a short delay and compare.
	// Use context-aware sleep so the executor respects cancellation.
	select {
	case <-ctx.Done():
		return findings, ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}
	tools2, _, _ := listMCPTools(ctx, client, vars.BaseURL)
	if rugEvidence := diffTools(tools1, tools2); rugEvidence != "" {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.RiskIndicator, // changed descriptions detected; malicious intent not proven
			Title:      "MCP tool definitions changed between consecutive tools/list calls (rug pull indicator)",
			Description: "Tool descriptions or schemas changed between two consecutive tools/list requests. " +
				"This is characteristic of a rug pull attack: benign definitions are served during trust " +
				"establishment, then switched to malicious ones after the client begins processing.",
			Evidence:    rugEvidence,
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		})
	}

	return findings, nil
}

// scanDescription scores a single description string and emits a finding if it exceeds threshold.
func (e *ToolPoisonExecutor) scanDescription(_ context.Context, toolName, desc, field, endpoint string) []attack.Finding {
	if desc == "" {
		return nil
	}
	score, matched := scoreDescription(desc)
	if score < 2 {
		return nil
	}
	sev := scoreToSeverity(score)
	return []attack.Finding{{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   sev,
		Confidence: attack.RiskIndicator, // pattern match only; LLM behavior not verified
		Title: fmt.Sprintf("MCP tool %q %s contains potential injection pattern (score %d)",
			toolName, field, score),
		Description: fmt.Sprintf(
			"The %s for MCP tool %q at %s contains patterns consistent with prompt injection / "+
				"tool poisoning. An LLM consuming this tool definition may interpret these instructions "+
				"as authoritative and execute unintended actions including data exfiltration or "+
				"unauthorized tool invocations.", field, toolName, endpoint),
		Evidence:    fmt.Sprintf("tool: %q\nfield: %s\npatterns matched: %v\nsnippet: %.400s", toolName, field, matched, desc),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}}
}

// listMCPTools performs the MCP initialize -> notifications/initialized -> tools/list
// handshake and returns the tools array along with the session for follow-up requests.
// Tries common MCP endpoint paths.
func listMCPTools(ctx context.Context, client *attack.HTTPClient, baseURL string) ([]map[string]interface{}, mcpSession, error) {
	endpoints := endpointCandidates(baseURL)
	for _, ep := range endpoints {
		// Step 1: initialize
		initResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
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

		// Step 2: initialized notification (fire-and-forget)
		_, _ = client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})

		// Step 3: list tools
		toolsResp, err := client.POST(ctx, ep, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/list",
			"params":  map[string]interface{}{},
		})
		if err != nil || !toolsResp.IsSuccess() {
			continue
		}

		var body map[string]interface{}
		if err := json.Unmarshal(toolsResp.Body, &body); err != nil {
			continue
		}
		result, _ := body["result"].(map[string]interface{})
		toolsRaw, _ := result["tools"].([]interface{})
		if len(toolsRaw) == 0 {
			continue
		}

		tools := make([]map[string]interface{}, 0, len(toolsRaw))
		for _, t := range toolsRaw {
			if tm, ok := t.(map[string]interface{}); ok {
				tools = append(tools, tm)
			}
		}
		return tools, session, nil
	}

	return nil, mcpSession{}, fmt.Errorf("no MCP tools/list endpoint found at %s", baseURL)
}

// diffTools compares two tools/list snapshots and returns evidence of changes, or "" if identical.
func diffTools(tools1, tools2 []map[string]interface{}) string {
	if len(tools1) != len(tools2) {
		return fmt.Sprintf("tool count changed: first call=%d, second call=%d", len(tools1), len(tools2))
	}

	// Index by name
	index1 := make(map[string]string)
	for _, t := range tools1 {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		index1[name] = desc
	}

	var diffs []string
	for _, t := range tools2 {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		if orig, ok := index1[name]; ok {
			if orig != desc {
				diffs = append(diffs, fmt.Sprintf("tool %q description changed:\nbefore: %.200s\nafter:  %.200s", name, orig, desc))
			}
		} else {
			diffs = append(diffs, fmt.Sprintf("new tool appeared in second call: %q", name))
		}
	}

	return strings.Join(diffs, "\n---\n")
}
