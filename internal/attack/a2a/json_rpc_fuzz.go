package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// stackTraceKeywords are substrings that indicate a leaked runtime stack trace
// or unhandled panic in the response body.
var stackTraceKeywords = []string{
	"goroutine",
	"panic",
	"runtime error",
	"traceback",
	"at line",
	"stack trace",
}

// fuzzProbe is a single malformed JSON-RPC payload with its human-readable label.
type fuzzProbe struct {
	name string
	body string
}

// buildFuzzProbes returns the eight mutation probes for the JSON-RPC fuzzer.
// The oversized method string is generated inline to avoid a package-level
// allocation; 10 240 bytes matches the "10 KB" requirement.
func buildFuzzProbes() []fuzzProbe {
	oversizedMethod := strings.Repeat("A", 10240)
	return []fuzzProbe{
		{name: "null-method", body: `{"jsonrpc":"2.0","method":null,"id":1}`},
		{name: "integer-method", body: `{"jsonrpc":"2.0","method":12345,"id":1}`},
		{name: "missing-id", body: `{"jsonrpc":"2.0","method":"SendMessage","params":{}}`},
		{name: "oversized-method", body: fmt.Sprintf(`{"jsonrpc":"2.0","method":%q,"id":1}`, oversizedMethod)},
		{name: "nested-object-id", body: `{"jsonrpc":"2.0","method":"SendMessage","id":{"nested":true}}`},
		{name: "wrong-version", body: `{"jsonrpc":"1.0","method":"SendMessage","id":1}`},
		{name: "empty-body", body: `{}`},
		{name: "params-as-array", body: `{"jsonrpc":"2.0","method":"SendMessage","params":[],"id":1}`},
	}
}

// JSONRPCFuzzExecutor sends structurally malformed JSON-RPC 2.0 payloads to the
// A2A endpoint and checks responses for server crashes and leaked stack traces
// (rule a2a-json-rpc-fuzz-001).
//
// Attack sequence:
//  1. Send each of the eight mutation probes as POST to {target}/ with
//     Content-Type: application/json.
//  2. HTTP 5xx response: emit a medium finding (server crashed).
//  3. Stack trace keywords in the body: emit a high finding (information disclosure).
//  4. All 4xx or valid JSON-RPC error responses: no finding.
type JSONRPCFuzzExecutor struct {
	rule attack.RuleContext
}

// NewJSONRPCFuzzExecutor creates an executor for the a2a-json-rpc-fuzz attack type.
func NewJSONRPCFuzzExecutor(r attack.RuleContext) *JSONRPCFuzzExecutor {
	return &JSONRPCFuzzExecutor{rule: r}
}

// Execute runs the JSON-RPC fuzz test against the A2A endpoint.
func (e *JSONRPCFuzzExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	endpoint := vars.BaseURL + "/"

	probes := buildFuzzProbes()
	var findings []attack.Finding

	for _, p := range probes {
		headers := map[string]string{"Content-Type": "application/json"}
		// Pass the pre-serialized payload as json.RawMessage so that
		// attack.HTTPClient.POST does not re-encode it as a JSON string.
		resp, err := client.POST(ctx, endpoint, headers, json.RawMessage(p.body))
		if err != nil {
			continue // network error is not a finding
		}

		// Check for HTTP 5xx (server crash / unhandled error).
		if resp.StatusCode >= http.StatusInternalServerError {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("A2A server returned HTTP %d on malformed JSON-RPC input (%s)", resp.StatusCode, p.name),
				Description: fmt.Sprintf(
					"The A2A endpoint returned HTTP %d when sent the malformed JSON-RPC probe %q. "+
						"A spec-compliant server must return a JSON-RPC error object with a 4xx or 200 "+
						"status for all invalid requests. HTTP 5xx indicates an unhandled error or crash "+
						"that could be exploited for denial-of-service.", resp.StatusCode, p.name),
				Evidence: fmt.Sprintf(
					"probe: %s\nbody: %s\nHTTP %d\nresponse: %s",
					p.name, p.body, resp.StatusCode, snippetA2A(resp.Body, 400),
				),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
			continue
		}

		// Check for stack trace / panic keywords in the response body regardless
		// of status code (some servers return 200 with a plaintext panic dump).
		if resp.ContainsAny(stackTraceKeywords...) {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("A2A server leaked stack trace on malformed JSON-RPC input (%s)", p.name),
				Description: fmt.Sprintf(
					"The A2A endpoint response to the %q probe contained stack trace or panic keywords. "+
						"Leaking internal runtime details (goroutine dumps, file paths, line numbers) "+
						"gives attackers a map of the application internals and aids in crafting "+
						"further targeted exploits.", p.name),
				Evidence: fmt.Sprintf(
					"probe: %s\nbody: %s\nHTTP %d\nresponse: %s",
					p.name, p.body, resp.StatusCode, snippetA2A(resp.Body, 600),
				),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}
	}

	return findings, nil
}

func snippetA2A(body []byte, n int) string {
	if len(body) > n {
		return string(body[:n]) + "..."
	}
	return string(body)
}
