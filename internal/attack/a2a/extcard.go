// Package a2a contains attack executors for the A2A protocol.
package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
	protocola2a "github.com/calbebop/batesian/internal/protocol/a2a"
)

const (
	extCardHTTPPath = "/extendedAgentCard"
)

// ExtCardExecutor checks whether an extended A2A card is disclosed without a
// valid credential over JSON-RPC or HTTP GET.
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
	reached := false
	jsonrpcEP, endpointOK := resolveA2AEndpoint(ctx, unauthClient, vars.BaseURL)
	for _, ep := range []string{jsonrpcEP, endpoint.AppendPath(vars.BaseURL, "/v1/message:send")} {
		resp, usable := e.probeJSONRPC(ctx, unauthClient, ep, invalidToken, vars.RandID)
		if resp != nil && resp.StatusCode != 404 {
			reached = true
		}
		if usable {
			findings = append(findings, e.finding("JSON-RPC", ep, invalidToken, resp))
			break
		}
		resp, usable = e.probeJSONRPC(ctx, unauthClient, ep, "", vars.RandID)
		if resp != nil && resp.StatusCode != 404 {
			reached = true
		}
		if usable {
			findings = append(findings, e.finding("JSON-RPC", ep, "", resp))
			break
		}
	}

	// HTTP+JSON transport uses GET /extendedAgentCard.
	extURL := endpoint.AppendPath(vars.BaseURL, extCardHTTPPath)
	respA, errA := unauthClient.GET(ctx, extURL, map[string]string{"Authorization": "Bearer " + invalidToken})
	if errA == nil && respA.StatusCode != 404 {
		reached = true
	}
	if errA == nil && extCardDisclosed(respA) {
		findings = append(findings, e.finding("HTTP GET", extURL, invalidToken, respA))
	} else if respB, errB := unauthClient.GET(ctx, extURL, nil); errB == nil && extCardDisclosed(respB) {
		findings = append(findings, e.finding("HTTP GET", extURL, "", respB))
	} else if errB == nil && respB.StatusCode != 404 {
		reached = true
	}

	// No disclosure found. If nothing was even reachable, the rule could not be
	// exercised against a testable endpoint.
	if len(findings) == 0 {
		if !reached {
			return nil, attack.ErrInconclusive
		}
		// reached only records a response that was not a 404. Confirm the target
		// is an A2A agent before reporting no disclosure as a clean result.
		return nil, notTestableGiven(ctx, unauthClient, vars.BaseURL, endpointOK)
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

// probeJSONRPC accepts only a matching reply containing a complete Agent Card.
func (e *ExtCardExecutor) probeJSONRPC(ctx context.Context, client *attack.HTTPClient, endpoint, token, randID string) (*attack.Response, bool) {
	requestID := "batesian-" + randID
	headers := map[string]string{"A2A-Version": "1.0"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	resp, err := client.POST(ctx, endpoint, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "GetExtendedAgentCard",
		"params":  map[string]interface{}{},
	})
	if err != nil {
		return nil, false
	}
	if !resp.IsSuccess() {
		return resp, false
	}
	result, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	return resp, valid && !hasError && protocola2a.IsCompleteAgentCard(result)
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

// extCardDisclosed accepts a successful HTTP response with a complete card.
func extCardDisclosed(resp *attack.Response) bool {
	return resp != nil && resp.IsSuccess() && protocola2a.IsCompleteAgentCard(resp.Body)
}

// snippet returns at most the first n bytes of body as a string, appending an
// ellipsis when it truncates.
//
// Truncation backs up to a UTF-8 rune boundary so a multi-byte character is
// never split. Snippets are taken from the scanned target's raw response and end
// up in Finding.Evidence, which is marshalled into JSON and SARIF; a trailing
// partial rune would be silently rewritten to U+FFFD there, corrupting the
// evidence for any target that returns non-ASCII text.
func snippet(body []byte, n int) string {
	if len(body) <= n {
		return string(body)
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	return string(body[:cut]) + "..."
}
