package mcp

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/calbebop/batesian/internal/attack"
)

// homoglyphMap maps ASCII characters to visually similar Unicode codepoints.
// Cyrillic lookalikes are the most common homoglyph attack vector because
// they share glyphs with Latin characters in the overwhelming majority of fonts.
var homoglyphMap = map[rune]rune{
	'a': '\u0430', // Cyrillic small a
	'e': '\u0435', // Cyrillic small e
	'o': '\u043E', // Cyrillic small o
	'p': '\u0440', // Cyrillic small p
	'c': '\u0441', // Cyrillic small c
	'x': '\u0445', // Cyrillic small x
	'A': '\u0410', // Cyrillic capital A
	'E': '\u0415', // Cyrillic capital E
	'O': '\u041E', // Cyrillic capital O
	'P': '\u0420', // Cyrillic capital P
	'C': '\u0421', // Cyrillic capital C
	'X': '\u0425', // Cyrillic capital X
	'B': '\u0412', // Cyrillic capital B
	'H': '\u041D', // Cyrillic capital H
	'T': '\u0422', // Cyrillic capital T
	'M': '\u041C', // Cyrillic capital M
	'K': '\u041A', // Cyrillic capital K
}

// HomoglyphToolExecutor sends tools/call with tool names containing Unicode
// lookalike characters and checks whether the server accepts them as valid tool
// names (rule mcp-homoglyph-tool-001).
type HomoglyphToolExecutor struct {
	rule attack.RuleContext
}

// NewHomoglyphToolExecutor creates an executor for mcp-homoglyph-tool.
func NewHomoglyphToolExecutor(r attack.RuleContext) *HomoglyphToolExecutor {
	return &HomoglyphToolExecutor{rule: r}
}

func (e *HomoglyphToolExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	tools, session, err := listMCPTools(ctx, client, vars.BaseURL)
	if err != nil || len(tools) == 0 {
		return nil, nil
	}

	var findings []attack.Finding

	// Test the first two tools to keep scan time bounded.
	limit := 2
	if len(tools) < limit {
		limit = len(tools)
	}

	for i := 0; i < limit; i++ {
		name, _ := tools[i]["name"].(string)
		if name == "" {
			continue
		}

		spoofed := substituteHomoglyphs(name)
		if spoofed == name {
			continue // No substitutable characters in this tool name.
		}

		resp, err := client.POST(ctx, session.Endpoint, session.header(), map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      50 + i,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      spoofed,
				"arguments": map[string]interface{}{},
			},
		})
		if err != nil {
			continue
		}

		// A method-not-found error (-32601) or a validation error (-32602) is correct.
		// Anything else (including a 200 with a result) indicates the server processed
		// the homoglyphic name -- identity normalization is absent.
		bodyStr := string(resp.Body)
		isMethodNotFound := strings.Contains(bodyStr, "-32601") ||
			strings.Contains(strings.ToLower(bodyStr), "not found") ||
			strings.Contains(strings.ToLower(bodyStr), "unknown tool") ||
			strings.Contains(strings.ToLower(bodyStr), "no such tool")
		isValidationError := strings.Contains(bodyStr, "-32602")

		if isMethodNotFound || isValidationError {
			continue // Correct behavior.
		}

		if resp.IsSuccess() {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"MCP server accepted tools/call with homoglyphic name %q (original: %q)",
					spoofed, name),
				Description: fmt.Sprintf(
					"The MCP server at %s accepted a tools/call request where the tool name "+
						"contained Unicode homoglyph substitutions (Cyrillic characters replacing "+
						"visually identical ASCII characters). The substituted name %q looks identical "+
						"to %q in most fonts but is a different byte sequence. Accepting it without "+
						"normalization enables identity confusion attacks in multi-server environments.",
					session.Endpoint, spoofed, name),
				Evidence: fmt.Sprintf(
					"original name: %q (bytes: %x)\nhomoglyph name: %q (bytes: %x)\n"+
						"HTTP %d\nresponse snippet: %.300s",
					name, []byte(name), spoofed, []byte(spoofed),
					resp.StatusCode, bodyStr),
				Remediation: e.rule.Remediation,
				TargetURL:   session.Endpoint,
			})
		}
	}

	return findings, nil
}

// substituteHomoglyphs replaces ASCII characters in s with Cyrillic homoglyphs.
// It substitutes only the first substitutable character to keep the name
// visually identical while producing a different byte sequence.
func substituteHomoglyphs(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		// Only substitute ASCII characters (Basic Latin block).
		if r > unicode.MaxASCII {
			continue
		}
		if sub, ok := homoglyphMap[r]; ok {
			runes[i] = sub
			return string(runes) // Substitute just one character.
		}
	}
	return s // No substitutable characters.
}
