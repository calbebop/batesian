// Package a2a contains attack executors for the A2A protocol.
package a2a

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

const (
	extCardHTTPPath = "/extendedAgentCard"
)

// ExtCardExecutor tests whether the A2A extended agent card is accessible
// without authentication (rule a2a-extcard-unauth-001).
//
// The A2A spec evolved: in older SDK versions the extended card was served via
// HTTP GET /extendedAgentCard. In the current SDK (a2a-sdk >=1.0.0) it is only
// accessible via the JSON-RPC method agent/authenticatedExtendedCard at POST /.
// This executor probes BOTH paths for maximum real-world coverage.
//
// For each transport (JSON-RPC method + legacy HTTP GET) the executor reports at
// most one finding, preferring the stronger signal: if a fabricated INVALID
// bearer token is accepted, the server claims authentication but does not
// validate it (critical bypass); otherwise if the card is returned with NO
// credentials at all, the endpoint is simply public (high disclosure). The
// invalid-token result strictly implies the no-token result, so they are not
// reported as two separate findings.
type ExtCardExecutor struct {
	rule attack.RuleContext
}

// NewExtCardExecutor creates an executor for the extcard-unauth-disclosure attack type.
func init() {
	attack.Register("extcard-unauth-disclosure", func(rc attack.RuleContext) attack.Executor { return NewExtCardExecutor(rc) })
}

func NewExtCardExecutor(r attack.RuleContext) *ExtCardExecutor {
	return &ExtCardExecutor{rule: r}
}

func (e *ExtCardExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// All probes test whether the endpoint is accessible without (or with an invalid)
	// token, so we always use an unauthClient. The fabricated-token probes inject the
	// bad token explicitly via the per-request header map rather than via opts.Token.
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	invalidToken := "batesian-invalid-" + vars.RandID
	var findings []attack.Finding

	// JSON-RPC transport - the primary path in the current SDK. Both / and
	// /v1/message:send are tried since the endpoint varies by binding type. One
	// finding max, preferring the invalid-token (critical) signal.
	jsonrpcEP, _ := resolveA2AEndpoint(ctx, unauthClient, vars.BaseURL)
	for _, ep := range []string{jsonrpcEP, vars.BaseURL + "/v1/message:send"} {
		if resp, ok := e.probeJSONRPC(ctx, unauthClient, ep, invalidToken, vars.RandID); ok {
			findings = append(findings, e.finding("JSON-RPC", ep, invalidToken, resp))
			break
		}
		if resp, ok := e.probeJSONRPC(ctx, unauthClient, ep, "", vars.RandID); ok {
			findings = append(findings, e.finding("JSON-RPC", ep, "", resp))
			break
		}
	}

	// HTTP GET transport - legacy path (a2a-sdk < 1.0.0, a2a-samples reference impl).
	extURL := vars.BaseURL + extCardHTTPPath
	if resp, err := unauthClient.GET(ctx, extURL, map[string]string{"Authorization": "Bearer " + invalidToken}); err == nil && resp.IsSuccess() && !isJSONRPCError(resp.Body) {
		findings = append(findings, e.finding("HTTP GET", extURL, invalidToken, resp))
	} else if resp, err := unauthClient.GET(ctx, extURL, nil); err == nil && resp.IsSuccess() && !isJSONRPCError(resp.Body) {
		findings = append(findings, e.finding("HTTP GET", extURL, "", resp))
	}

	return findings, nil
}

// finding builds an extended-card disclosure finding. A non-empty token means a
// fabricated invalid bearer token was accepted (critical auth bypass); an empty
// token means the card was returned with no credentials (high disclosure).
func (e *ExtCardExecutor) finding(transport, endpoint, token string, resp *attack.Response) attack.Finding {
	if token != "" {
		return attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title:      fmt.Sprintf("Extended Agent Card (%s) returned to a fabricated Bearer token", transport),
			Description: fmt.Sprintf(
				"%s %s returned HTTP %d for the extended agent card while presenting an invalid "+
					"token %q. The server claims authentication but does not validate it, so any "+
					"caller can read the privileged extended card.", transport, endpoint, resp.StatusCode, token),
			Evidence:    fmt.Sprintf("transport: %s\nHTTP %d from %s\nAuthorization: Bearer %s\n%s", transport, resp.StatusCode, endpoint, token, snippet(resp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		}
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      fmt.Sprintf("Extended Agent Card (%s) accessible without authentication", transport),
		Description: fmt.Sprintf(
			"%s %s returned HTTP %d for the extended agent card without any Authorization header. "+
				"The extended card discloses privileged capability listings intended only for "+
				"authenticated callers.", transport, endpoint, resp.StatusCode),
		Evidence:    fmt.Sprintf("transport: %s\nHTTP %d from %s (no auth)\n%s", transport, resp.StatusCode, endpoint, snippet(resp.Body, 400)),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// probeJSONRPC sends GetExtendedAgentCard (a2a-sdk v1.0 PascalCase method) via
// JSON-RPC and reports whether the server returned a non-error result. If token
// is empty, no Authorization header is sent. The a2a-sdk v1.0.x uses gRPC-style
// PascalCase methods and requires the A2A-Version: 1.0 header for the dispatcher
// to accept the call.
func (e *ExtCardExecutor) probeJSONRPC(ctx context.Context, client *attack.HTTPClient, endpoint, token, randID string) (*attack.Response, bool) {
	headers := map[string]string{"A2A-Version": "1.0"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	resp, err := client.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-" + randID,
		"method":  "GetExtendedAgentCard",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() || isJSONRPCError(resp.Body) {
		return nil, false
	}
	return resp, true
}

// isJSONRPCError returns true if the body contains a JSON-RPC error object.
func isJSONRPCError(body []byte) bool {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	_, hasError := m["error"]
	return hasError
}

// snippet returns the first n bytes of body as a string.
func snippet(body []byte, n int) string {
	if len(body) > n {
		return string(body[:n]) + "..."
	}
	return string(body)
}
