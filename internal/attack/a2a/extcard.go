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
// Attack sequence:
//  1. JSON-RPC probe: POST / with method agent/authenticatedExtendedCard, no auth
//  2. JSON-RPC probe: same method with a fabricated invalid Bearer token
//  3. HTTP GET /extendedAgentCard: legacy path, no auth
//  4. HTTP GET /extendedAgentCard: with fabricated invalid token
type ExtCardExecutor struct {
	rule attack.RuleContext
}

// NewExtCardExecutor creates an executor for the extcard-unauth-disclosure attack type.
func NewExtCardExecutor(r attack.RuleContext) *ExtCardExecutor {
	return &ExtCardExecutor{rule: r}
}

func (e *ExtCardExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// All probes test whether the endpoint is accessible without (or with an invalid)
	// token, so we always use an unauthClient. The fabricated-token probes inject the
	// bad token explicitly via the per-request header map rather than via opts.Token.
	unauthClient := attack.NewUnauthHTTPClient(opts, vars)

	var findings []attack.Finding

	// JSON-RPC probe — the primary path in the current SDK.
	// Both / and /v1/message:send are tried since the endpoint varies by binding type.
	jsonrpcEndpoints := []string{vars.BaseURL + "/", vars.BaseURL + "/v1/message:send"}
	for _, ep := range jsonrpcEndpoints {
		// Probe 1: No auth — must use unauthClient so --token is not injected.
		f := e.probeJSONRPC(ctx, unauthClient, ep, "", vars.RandID)
		findings = append(findings, f...)

		// Probe 2: Fabricated invalid token (explicitly set via header, not opts.Token).
		f = e.probeJSONRPC(ctx, unauthClient, ep, "batesian-invalid-"+vars.RandID, vars.RandID)
		findings = append(findings, f...)

		if len(findings) > 0 {
			break // Found vuln on this endpoint; no need to try the next binding
		}
	}

	// HTTP GET probe — legacy path (a2a-sdk < 1.0.0, a2a-samples reference impl).
	extURL := vars.BaseURL + extCardHTTPPath

	// Probe 3: No auth via HTTP GET — must use unauthClient.
	unauthResp, err := unauthClient.GET(ctx, extURL, nil)
	if err == nil && unauthResp.IsSuccess() {
		findings = append(findings, attack.Finding{
			RuleID:      e.rule.ID,
			RuleName:    e.rule.Name,
			Severity:    "high",
			Confidence:  attack.ConfirmedExploit,
			Title:       "Extended Agent Card (HTTP GET) accessible without authentication",
			Description: fmt.Sprintf("GET %s returned HTTP %d without any Authorization header.", extURL, unauthResp.StatusCode),
			Evidence:    fmt.Sprintf("HTTP %d from %s (no auth)\n%s", unauthResp.StatusCode, extURL, snippet(unauthResp.Body, 300)),
			Remediation: e.rule.Remediation,
			TargetURL:   extURL,
		})
	}

	// Probe 4: Fabricated invalid token via HTTP GET (explicit header overrides the unauth client's no-token default).
	invalidToken := "batesian-invalid-" + vars.RandID
	invalidHTTPResp, err := unauthClient.GET(ctx, extURL, map[string]string{
		"Authorization": "Bearer " + invalidToken,
	})
	if err == nil && invalidHTTPResp.IsSuccess() {
		findings = append(findings, attack.Finding{
			RuleID:      e.rule.ID,
			RuleName:    e.rule.Name,
			Severity:    "critical",
			Confidence:  attack.ConfirmedExploit,
			Title:       "Extended Agent Card (HTTP GET) returned HTTP 200 with fabricated Bearer token",
			Description: fmt.Sprintf("GET %s returned HTTP %d with invalid token %q — auth is not enforced.", extURL, invalidHTTPResp.StatusCode, invalidToken),
			Evidence:    fmt.Sprintf("HTTP %d from %s\nAuthorization: Bearer %s\n%s", invalidHTTPResp.StatusCode, extURL, invalidToken, snippet(invalidHTTPResp.Body, 300)),
			Remediation: e.rule.Remediation,
			TargetURL:   extURL,
		})
	}

	return findings, nil
}

// probeJSONRPC sends GetExtendedAgentCard (a2a-sdk v1.0 PascalCase method) via JSON-RPC.
// If token is empty, no Authorization header is sent.
// The a2a-sdk v1.0.x uses gRPC-style PascalCase methods and requires the
// A2A-Version: 1.0 header for _process_non_streaming_request to accept the call.
func (e *ExtCardExecutor) probeJSONRPC(ctx context.Context, client *attack.HTTPClient, endpoint, token, randID string) []attack.Finding {
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-" + randID,
		"method":  "GetExtendedAgentCard",
		"params":  map[string]interface{}{},
	}

	headers := map[string]string{
		"A2A-Version": "1.0", // Required by a2a-sdk v1.0.x dispatcher
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	resp, err := client.POST(ctx, endpoint, headers, body)
	if err != nil || !resp.IsSuccess() {
		return nil
	}

	// Check if the response looks like a real extended card (not an error)
	if isJSONRPCError(resp.Body) {
		return nil
	}

	// Got a 200 with a non-error result
	var findings []attack.Finding
	if token == "" {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "Extended Agent Card (JSON-RPC) accessible without authentication",
			Description: fmt.Sprintf(
				"POST %s with method agent/authenticatedExtendedCard returned HTTP %d without any "+
					"Authorization header. The extended card discloses privileged capability listings "+
					"intended only for authenticated callers.", endpoint, resp.StatusCode),
			Evidence:    fmt.Sprintf("HTTP %d from %s (no auth)\n%s", resp.StatusCode, endpoint, snippet(resp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	} else {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "critical",
			Confidence: attack.ConfirmedExploit,
			Title:      "Extended Agent Card (JSON-RPC) returned HTTP 200 with fabricated Bearer token",
			Description: fmt.Sprintf(
				"POST %s with method agent/authenticatedExtendedCard returned HTTP %d with invalid "+
					"token %q — authentication is not enforced at the application layer.", endpoint, resp.StatusCode, token),
			Evidence:    fmt.Sprintf("HTTP %d from %s\nAuthorization: Bearer %s\n%s", resp.StatusCode, endpoint, token, snippet(resp.Body, 400)),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}
	return findings
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
