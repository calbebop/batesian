package mcp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// injectionPayload pairs a payload string with its attack class and severity.
type injectionPayload struct {
	class    string
	payload  string
	severity string
}

// injectionPayloads covers the major injection classes that can reach tool handlers.
var injectionPayloads = []injectionPayload{
	// SQL injection -- error-based detection
	{"sql", `' OR '1'='1`, "high"},
	{"sql", `' OR 1=1 --`, "high"},
	{"sql", `"; DROP TABLE users; --`, "high"},
	// OS command injection
	{"command", `; id`, "critical"},
	{"command", "` id `", "critical"},
	{"command", `| whoami`, "critical"},
	{"command", `$(id)`, "critical"},
	// Path traversal
	{"path_traversal", `../../../../etc/passwd`, "high"},
	{"path_traversal", `..\..\..\..\windows\win.ini`, "high"},
	// XSS / script injection (tests for reflection)
	{"xss", `<script>alert(1)</script>`, "medium"},
	{"xss", `"><img src=x onerror=alert(1)>`, "medium"},
	// Template injection
	{"template", `{{7*7}}`, "medium"},
	{"template", `${7*7}`, "medium"},
}

// sqlErrorPatterns matches common database error messages.
var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sql syntax|mysql_fetch|ORA-\d+|PG::|sqlite3\.OperationalError`),
	regexp.MustCompile(`(?i)you have an error in your sql`),
	regexp.MustCompile(`(?i)unclosed quotation mark|quoted string not properly terminated`),
	regexp.MustCompile(`(?i)syntax error.*near|unexpected.*near`),
	regexp.MustCompile(`(?i)pg_query\(\)|pg_exec\(\)|mysqli_`),
}

// commandOutputPatterns matches artifacts of OS command execution.
// No line-start anchors: the output appears embedded inside a JSON string,
// not at the beginning of a line in the raw response body.
var commandOutputPatterns = []*regexp.Regexp{
	regexp.MustCompile(`uid=\d+\(\w+\)`),
	regexp.MustCompile(`root:x:0:0:`),
	regexp.MustCompile(`(?i)command not found|sh:\s*\d+:`),
}

// pathTraversalPatterns matches successful path traversal artifacts.
var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`root:.*:/bin/`),                      // /etc/passwd content
	regexp.MustCompile(`(?i)\[extensions\].*MCI extensions`), // win.ini content
	regexp.MustCompile(`#.*passwd`),
}

// InjectionParamsExecutor tests MCP tool call parameters for SQL, command,
// path traversal, and XSS injection vulnerabilities (rule mcp-injection-params-001).
type InjectionParamsExecutor struct {
	rule attack.RuleContext
}

// NewInjectionParamsExecutor creates an executor for mcp-injection-params.
func NewInjectionParamsExecutor(r attack.RuleContext) *InjectionParamsExecutor {
	return &InjectionParamsExecutor{rule: r}
}

func (e *InjectionParamsExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	tools, session, err := listMCPTools(ctx, client, vars.BaseURL)
	if err != nil || len(tools) == 0 {
		return nil, nil
	}

	// Test the first two tools to keep scan time reasonable.
	limit := 2
	if len(tools) < limit {
		limit = len(tools)
	}

	var findings []attack.Finding
	seen := map[string]bool{}

	for i := 0; i < limit; i++ {
		toolName, _ := tools[i]["name"].(string)
		if toolName == "" {
			continue
		}

		// Discover argument names from the inputSchema.
		argNames := extractArgNames(tools[i])
		if len(argNames) == 0 {
			argNames = []string{"input", "query", "text", "data", "value", "path", "command"}
		}

		for _, payload := range injectionPayloads {
			// Build arguments map with the payload in each known arg.
			args := make(map[string]interface{}, len(argNames))
			for _, arg := range argNames {
				args[arg] = payload.payload
			}

			resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      200,
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name":      toolName,
					"arguments": args,
				},
			})
			if err != nil {
				continue
			}

			bodyStr := string(resp.Body)
			finding := e.analyzeResponse(bodyStr, payload, toolName, session.Endpoint)
			if finding != nil {
				key := payload.class + toolName
				if !seen[key] {
					seen[key] = true
					findings = append(findings, *finding)
				}
			}
		}
	}

	return findings, nil
}

// analyzeResponse inspects a tool call response for injection artifacts.
func (e *InjectionParamsExecutor) analyzeResponse(body string, p injectionPayload, toolName, endpoint string) *attack.Finding {
	switch p.class {
	case "sql":
		for _, re := range sqlErrorPatterns {
			if re.MatchString(body) {
				return &attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   p.severity,
					Confidence: attack.ConfirmedExploit,
					Title:      fmt.Sprintf("SQL error exposed via tool %q with injection payload", toolName),
					Description: fmt.Sprintf(
						"A SQL injection payload sent as a tool call argument to %q at %s "+
							"caused the server to return a database error message. This confirms "+
							"unsanitized argument values are passed directly to SQL queries.",
						toolName, endpoint),
					Evidence:    fmt.Sprintf("payload: %q\nSQL error detected\nsnippet: %.400s", p.payload, body),
					Remediation: e.rule.Remediation,
					TargetURL:   endpoint,
				}
			}
		}

	case "command":
		for _, re := range commandOutputPatterns {
			if re.MatchString(body) {
				return &attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   p.severity,
					Confidence: attack.ConfirmedExploit,
					Title:      fmt.Sprintf("OS command execution confirmed via tool %q", toolName),
					Description: fmt.Sprintf(
						"An OS command injection payload sent as a tool call argument to %q at %s "+
							"caused the server to return command output in the response. This confirms "+
							"remote code execution via unsanitized tool arguments.",
						toolName, endpoint),
					Evidence:    fmt.Sprintf("payload: %q\nCommand output detected\nsnippet: %.400s", p.payload, body),
					Remediation: e.rule.Remediation,
					TargetURL:   endpoint,
				}
			}
		}

	case "path_traversal":
		for _, re := range pathTraversalPatterns {
			if re.MatchString(body) {
				return &attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   p.severity,
					Confidence: attack.ConfirmedExploit,
					Title:      fmt.Sprintf("Path traversal confirmed via tool %q", toolName),
					Description: fmt.Sprintf(
						"A path traversal payload sent as a tool call argument to %q at %s "+
							"caused the server to return file system content from outside the "+
							"intended base directory.",
						toolName, endpoint),
					Evidence:    fmt.Sprintf("payload: %q\nPath traversal content detected\nsnippet: %.400s", p.payload, body),
					Remediation: e.rule.Remediation,
					TargetURL:   endpoint,
				}
			}
		}

	case "xss":
		if strings.Contains(body, "<script>") || strings.Contains(body, "onerror=") {
			return &attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   p.severity,
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("XSS payload reflected unescaped in tool %q response", toolName),
				Description: fmt.Sprintf(
					"An XSS payload sent as a tool call argument to %q at %s was reflected "+
						"unescaped in the JSON-RPC response. If this content is rendered in a "+
						"browser-based MCP client, it may execute as script.",
					toolName, endpoint),
				Evidence:    fmt.Sprintf("payload: %q\nReflected unescaped\nsnippet: %.400s", p.payload, body),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			}
		}

	case "template":
		// Template injection: {{7*7}} -> 49 or ${7*7} -> 49.
		// Require the payload itself to appear in the body (echo) OR the result "49"
		// to appear adjacent to a recognizable pattern, reducing false positives from
		// benign responses that happen to contain the string "49".
		payloadEchoed := strings.Contains(body, p.payload)
		resultPresent := strings.Contains(body, `"49"`) ||
			strings.Contains(body, ": 49") ||
			strings.Contains(body, "=49") ||
			strings.Contains(body, ">49<")
		if payloadEchoed || resultPresent {
			return &attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   p.severity,
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("Possible template injection in tool %q (evaluated expression detected)", toolName),
				Description: fmt.Sprintf(
					"A template injection payload (%q) sent to tool %q at %s "+
						"produced a response that may indicate expression evaluation. "+
						"This may indicate server-side template injection.",
					p.payload, toolName, endpoint),
				Evidence:    fmt.Sprintf("payload: %q\nsnippet: %.400s", p.payload, body),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			}
		}
	}

	return nil
}

// extractArgNames reads the inputSchema.properties keys from a tool definition.
func extractArgNames(tool map[string]interface{}) []string {
	schema, _ := tool["inputSchema"].(map[string]interface{})
	if schema == nil {
		return nil
	}
	props, _ := schema["properties"].(map[string]interface{})
	if len(props) == 0 {
		return nil
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	return names
}
