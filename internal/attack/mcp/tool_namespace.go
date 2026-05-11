package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolNamespaceExecutor connects to an MCP server twice with independent
// sessions and compares the tools/list responses (rule mcp-tool-namespace-001).
//
// Differences between sessions indicate that the server's tool registry is
// mutable, which is the precondition for a rug pull attack and can cause
// namespace collisions in multi-server MCP deployments.
type ToolNamespaceExecutor struct {
	rule attack.RuleContext
}

// NewToolNamespaceExecutor creates an executor for mcp-tool-namespace.
func NewToolNamespaceExecutor(r attack.RuleContext) *ToolNamespaceExecutor {
	return &ToolNamespaceExecutor{rule: r}
}

func (e *ToolNamespaceExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)

	// Session A: first independent connection
	clientA := attack.NewHTTPClient(opts, vars)
	toolsA, sessionA, err := listMCPTools(ctx, clientA, vars.BaseURL)
	if err != nil || len(toolsA) == 0 {
		return nil, nil
	}

	// Session B: second independent connection using a fresh HTTP client.
	// NewHTTPClient creates a new transport, so there is no shared state.
	clientB := attack.NewHTTPClient(opts, vars)
	toolsB, _, err := listMCPTools(ctx, clientB, vars.BaseURL)
	if err != nil || len(toolsB) == 0 {
		return nil, nil
	}

	var findings []attack.Finding

	// Build indexes for comparison
	indexA := indexTools(toolsA)
	indexB := indexTools(toolsB)

	// Check for count mismatch
	if len(toolsA) != len(toolsB) {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title: fmt.Sprintf(
				"MCP tools/list returned different tool counts across sessions (%d vs %d)",
				len(toolsA), len(toolsB)),
			Description: fmt.Sprintf(
				"The MCP server at %s returned %d tools on the first connection and %d tools "+
					"on an independent second connection. This indicates the tool registry is "+
					"mutable and non-deterministic, which is the precondition for a rug pull "+
					"attack and can cause tool namespace collisions in multi-server deployments.",
				sessionA.Endpoint, len(toolsA), len(toolsB)),
			Evidence: fmt.Sprintf(
				"Session A tools (%d): %s\nSession B tools (%d): %s",
				len(toolsA), toolNames(toolsA), len(toolsB), toolNames(toolsB)),
			Remediation: e.rule.Remediation,
			TargetURL:   sessionA.Endpoint,
		})
	}

	// Check for description and schema differences on same-named tools
	for name, toolA := range indexA {
		toolB, exists := indexB[name]
		if !exists {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("MCP tool %q present in Session A but absent in Session B", name),
				Description: fmt.Sprintf(
					"Tool %q was returned by tools/list on the first connection to %s but was "+
						"not present in the second independent connection. A server that exposes "+
						"different tools per session enables session-targeted rug pull attacks.",
					name, sessionA.Endpoint),
				Evidence:    fmt.Sprintf("tool: %q\nSession A endpoint: %s", name, sessionA.Endpoint),
				Remediation: e.rule.Remediation,
				TargetURL:   sessionA.Endpoint,
			})
			continue
		}

		descA, _ := toolA["description"].(string)
		descB, _ := toolB["description"].(string)
		if descA != descB {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"MCP tool %q description differs between sessions", name),
				Description: fmt.Sprintf(
					"Tool %q at %s returned a different description on two independent "+
						"connections. Orchestrators and LLMs that rely on descriptions to make "+
						"dispatch decisions may behave differently depending on which session "+
						"they observed first.",
					name, sessionA.Endpoint),
				Evidence: fmt.Sprintf(
					"tool: %q\nSession A description: %.300s\nSession B description: %.300s",
					name, descA, descB),
				Remediation: e.rule.Remediation,
				TargetURL:   sessionA.Endpoint,
			})
		}

		schemaA := marshalSchema(toolA["inputSchema"])
		schemaB := marshalSchema(toolB["inputSchema"])
		if schemaA != schemaB {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"MCP tool %q inputSchema differs between sessions", name),
				Description: fmt.Sprintf(
					"Tool %q at %s returned a different inputSchema on two independent "+
						"connections. Clients that cache the schema from the first session may "+
						"generate invalid calls on subsequent connections.",
					name, sessionA.Endpoint),
				Evidence: fmt.Sprintf(
					"tool: %q\nSession A schema: %.300s\nSession B schema: %.300s",
					name, schemaA, schemaB),
				Remediation: e.rule.Remediation,
				TargetURL:   sessionA.Endpoint,
			})
		}
	}

	return findings, nil
}

// indexTools returns a name -> tool map for quick lookup.
func indexTools(tools []map[string]interface{}) map[string]map[string]interface{} {
	idx := make(map[string]map[string]interface{}, len(tools))
	for _, t := range tools {
		name, _ := t["name"].(string)
		if name != "" {
			// Ensure description is always a string to avoid nil assertions later
			if _, ok := t["description"]; !ok {
				t["description"] = ""
			}
			idx[name] = t
		}
	}
	return idx
}

// toolNames returns a comma-separated list of tool names for display.
func toolNames(tools []map[string]interface{}) string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if n, ok := t["name"].(string); ok {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

// marshalSchema serialises an inputSchema to a canonical string for comparison.
func marshalSchema(v interface{}) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
