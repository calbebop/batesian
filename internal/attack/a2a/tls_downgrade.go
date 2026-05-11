package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// TLSDowngradeExecutor tests whether A2A endpoints accept plain HTTP connections
// without enforcing HTTPS (rule a2a-tls-downgrade-001).
type TLSDowngradeExecutor struct {
	rule attack.RuleContext
}

// NewTLSDowngradeExecutor creates an executor for a2a-tls-downgrade.
func NewTLSDowngradeExecutor(r attack.RuleContext) *TLSDowngradeExecutor {
	return &TLSDowngradeExecutor{rule: r}
}

func (e *TLSDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)

	// Rewrite the target URL to plain HTTP regardless of the original scheme.
	httpBase, err := toHTTP(vars.BaseURL)
	if err != nil {
		return nil, nil
	}

	// Use a fresh HTTP client so TLS skip settings don't mask the finding.
	client := attack.NewHTTPClient(opts, attack.NewVars(httpBase, opts.OOBListenerURL))

	var findings []attack.Finding

	// 1. Probe the agent card endpoints over HTTP.
	cardPaths := []string{
		"/.well-known/agent.json",
		"/.well-known/agent-card.json",
	}
	for _, path := range cardPaths {
		resp, err := client.GET(ctx, httpBase+path, nil)
		if err != nil {
			continue
		}
		if isHTTPSRedirect(resp.StatusCode) {
			continue // Server correctly redirects to HTTPS.
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			// Accepted over plain HTTP without redirect.
			var card map[string]interface{}
			_ = json.Unmarshal(resp.Body, &card)
			hasCard := len(card) > 0

			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A Agent Card endpoint accepts plain HTTP connections (HTTP %d, no HTTPS redirect)",
					resp.StatusCode),
				Description: fmt.Sprintf(
					"GET %s returned HTTP %d over plain HTTP without redirecting to HTTPS. "+
						"All traffic to this endpoint (including bearer tokens and task content) "+
						"is transmitted in the clear.", httpBase+path, resp.StatusCode),
				Evidence: fmt.Sprintf(
					"GET %s\nHTTP %d\nhas_card_json: %v\nsnippet: %.300s",
					httpBase+path, resp.StatusCode, hasCard, string(resp.Body)),
				Remediation: e.rule.Remediation,
				TargetURL:   httpBase + path,
			})
			break // One card finding is sufficient.
		}
	}

	// 2. Probe the JSON-RPC endpoint over HTTP.
	rpcPaths := []string{"", "/a2a", "/rpc", "/api"}
	for _, path := range rpcPaths {
		ep := httpBase + path
		resp, err := client.POST(ctx, ep, nil, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tasks/send",
			"params": map[string]interface{}{
				"id": "batesian-tls-probe",
				"message": map[string]interface{}{
					"role":  1,
					"parts": []interface{}{map[string]interface{}{"text": "ping"}},
				},
			},
		})
		if err != nil {
			continue
		}
		if isHTTPSRedirect(resp.StatusCode) {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 600 && !isHTTPSRedirect(resp.StatusCode) {
			// Any response (including 400 Bad Request or 401 Unauthorized) confirms
			// the server received the HTTP request: the TCP connection was accepted
			// over plain HTTP.
			if resp.StatusCode == 400 && !strings.Contains(string(resp.Body), "jsonrpc") {
				continue // Likely a different service on this port.
			}
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A JSON-RPC endpoint accepts plain HTTP connections (HTTP %d at %s)",
					resp.StatusCode, ep),
				Description: fmt.Sprintf(
					"POST %s returned HTTP %d over plain HTTP. The server accepted the "+
						"connection and processed the request without redirecting to HTTPS. "+
						"A2A JSON-RPC traffic including authentication tokens and task payloads "+
						"is exposed in the clear.",
					ep, resp.StatusCode),
				Evidence: fmt.Sprintf(
					"POST %s\nHTTP %d\nsnippet: %.300s",
					ep, resp.StatusCode, string(resp.Body)),
				Remediation: e.rule.Remediation,
				TargetURL:   ep,
			})
			break
		}
	}

	return findings, nil
}

// toHTTP rewrites the URL scheme to http.
func toHTTP(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Scheme = "http"
	// Preserve port: if original was https on 443, switch to 80. If a non-standard
	// port was specified, keep it (the server may run HTTP and HTTPS on the same port).
	if u.Port() == "443" {
		u.Host = u.Hostname() + ":80"
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// isHTTPSRedirect returns true if the status code is a redirect that could
// indicate HTTPS enforcement (301, 302, 307, 308).
func isHTTPSRedirect(code int) bool {
	return code == 301 || code == 302 || code == 307 || code == 308
}
