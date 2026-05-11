package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// privilegeClaims are the configuration fields injected to simulate capability inflation.
// None of these are part of the A2A specification; a compliant server should reject
// or ignore them entirely.
var privilegeClaims = map[string]interface{}{
	"permissions": []string{"admin", "unrestricted", "superuser"},
	"scope":       "system",
	"runAs":       "root",
	"elevated":    true,
	"bypass_auth": true,
}

// CapabilityInflationExecutor tests whether an A2A agent silently accepts tasks
// with elevated privilege claims not declared in the Agent Card
// (rule a2a-capability-inflation-001).
type CapabilityInflationExecutor struct {
	rule attack.RuleContext
}

// NewCapabilityInflationExecutor creates an executor for a2a-capability-inflation.
func NewCapabilityInflationExecutor(r attack.RuleContext) *CapabilityInflationExecutor {
	return &CapabilityInflationExecutor{rule: r}
}

func (e *CapabilityInflationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	rpcPaths := []string{"", "/a2a", "/rpc", "/api"}

	for _, path := range rpcPaths {
		ep := vars.BaseURL + path

		// Baseline: send a plain tasks/send with no configuration.
		baseResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tasks/send",
			"params": map[string]interface{}{
				"id": "batesian-capinflation-base",
				"message": map[string]interface{}{
					"role":  1,
					"parts": []interface{}{map[string]interface{}{"text": "ping"}},
				},
			},
		})
		if err != nil || baseResp.StatusCode == 0 {
			continue
		}
		if !looksLikeA2A(baseResp.Body) {
			continue
		}

		// Elevated request: same task but with injected privilege claims.
		elevResp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tasks/send",
			"params": map[string]interface{}{
				"id": "batesian-capinflation-elevated",
				"message": map[string]interface{}{
					"role":  1,
					"parts": []interface{}{map[string]interface{}{"text": "ping"}},
				},
				"configuration": privilegeClaims,
			},
		})
		if err != nil {
			continue
		}

		var findings []attack.Finding

		// A compliant server should return a JSON-RPC error for the elevated request
		// or at minimum ignore the unknown configuration fields.
		// A 2xx response without a JSON-RPC error means the server accepted the call.
		if elevResp.IsSuccess() {
			var elevBody map[string]interface{}
			_ = json.Unmarshal(elevResp.Body, &elevBody)
			_, hasError := elevBody["error"]

			if !hasError {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "high",
					Confidence: attack.RiskIndicator,
					Title:      "A2A tasks/send with undeclared elevated configuration accepted without validation error",
					Description: fmt.Sprintf(
						"The A2A endpoint at %s accepted a tasks/send request containing undeclared "+
							"privilege claims in the configuration field (permissions: admin, scope: system, "+
							"runAs: root) with HTTP %d and no JSON-RPC error. A compliant server should "+
							"reject or ignore unknown configuration keys. Silent acceptance suggests the "+
							"server may process these claims.",
						ep, elevResp.StatusCode),
					Evidence: fmt.Sprintf(
						"POST %s\nconfiguration: %v\nHTTP %d\nbaseline HTTP %d\nresponse snippet: %.300s",
						ep, privilegeClaims, elevResp.StatusCode, baseResp.StatusCode, string(elevResp.Body)),
					Remediation: e.rule.Remediation,
					TargetURL:   ep,
				})
			}
		}

		// Check whether any privilege claim keyword appears in the elevated response
		// but not the baseline -- indicates the server is reflecting/acknowledging the claims.
		elevStr := strings.ToLower(string(elevResp.Body))
		baseStr := strings.ToLower(string(baseResp.Body))
		for _, keyword := range []string{"admin", "root", "elevated", "superuser", "bypass_auth"} {
			if strings.Contains(elevStr, keyword) && !strings.Contains(baseStr, keyword) {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "high",
					Confidence: attack.RiskIndicator,
					Title: fmt.Sprintf(
						"A2A server response reflects injected privilege claim %q", keyword),
					Description: fmt.Sprintf(
						"The response from %s to the elevated tasks/send request contained the "+
							"keyword %q which was not present in the baseline response. This suggests "+
							"the server read and reflected the injected configuration claim.",
						ep, keyword),
					Evidence: fmt.Sprintf(
						"keyword %q present in elevated response, absent in baseline\n"+
							"elevated snippet: %.300s\nbaseline snippet: %.300s",
						keyword, elevStr, baseStr),
					Remediation: e.rule.Remediation,
					TargetURL:   ep,
				})
				break
			}
		}

		if len(findings) > 0 {
			return findings, nil
		}
		// Server returned a JSON-RPC error for elevated request -- correct behavior.
		return nil, nil
	}

	return nil, nil
}

// looksLikeA2A checks whether a response body contains A2A JSON-RPC indicators.
func looksLikeA2A(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"jsonrpc"`) ||
		strings.Contains(s, `"taskId"`) ||
		strings.Contains(s, `"error"`) ||
		strings.Contains(s, `"result"`)
}
