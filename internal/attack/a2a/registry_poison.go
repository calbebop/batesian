package a2a

import (
	"context"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// registryPaths are common paths where A2A agent registries expose registration endpoints.
var registryPaths = []string{
	"/registry",
	"/registry/agents",
	"/agents",
	"/agents/register",
	"/api/agents",
	"/api/registry",
	"/v1/agents",
	"/v1/registry",
	"/.well-known/agents",
}

// poisonCard is the crafted agent card submitted for unauthenticated registration.
// It claims to be a trusted-sounding agent to test whether the server validates identity.
var poisonCard = map[string]interface{}{
	"name":        "batesian-probe-agent",
	"version":     "1.0",
	"url":         "https://batesian.invalid/a2a",
	"description": "Batesian security probe -- testing unauthenticated registry registration",
	"capabilities": map[string]interface{}{
		"streaming": false,
	},
	"skills": []interface{}{
		map[string]interface{}{
			"id":          "probe",
			"name":        "Probe",
			"description": "Security probe skill",
		},
	},
}

// RegistryPoisonExecutor tests whether A2A agent registry endpoints accept
// unauthenticated agent card registration (rule a2a-registry-poison-001).
type RegistryPoisonExecutor struct {
	rule attack.RuleContext
}

// NewRegistryPoisonExecutor creates an executor for a2a-registry-poison.
func NewRegistryPoisonExecutor(r attack.RuleContext) *RegistryPoisonExecutor {
	return &RegistryPoisonExecutor{rule: r}
}

func (e *RegistryPoisonExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Use an unauthenticated client — the rule tests whether an unauthenticated
	// caller can poison the registry. Injecting opts.Token would mask the finding.
	client := attack.NewUnauthHTTPClient(opts, vars)

	var findings []attack.Finding

	for _, path := range registryPaths {
		ep := vars.BaseURL + path

		// First, probe whether the path exists at all (GET).
		getResp, err := client.GET(ctx, ep, nil)
		if err != nil || getResp.StatusCode == 404 || getResp.StatusCode == 0 {
			continue
		}

		// Path exists -- attempt unauthenticated registration via POST.
		postResp, err := client.POST(ctx, ep, nil, poisonCard)
		if err != nil {
			continue
		}

		// 401 or 403 is the correct behavior.
		if postResp.StatusCode == 401 || postResp.StatusCode == 403 {
			continue
		}

		// 404 on POST but 200 on GET -- different method, not a registration endpoint.
		if postResp.StatusCode == 404 || postResp.StatusCode == 405 {
			continue
		}

		// Any 2xx indicates the server accepted the registration without auth.
		if postResp.IsSuccess() {
			bodyStr := string(postResp.Body)
			// Confirm this looks like a registry response, not an unrelated handler.
			if isRegistryLike(getResp.Body) || isRegistryLike(postResp.Body) || postResp.StatusCode == 201 {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "high",
					Confidence: attack.ConfirmedExploit,
					Title: fmt.Sprintf(
						"A2A agent registry at %s accepted unauthenticated agent card registration (HTTP %d)",
						ep, postResp.StatusCode),
					Description: fmt.Sprintf(
						"POST %s accepted an agent card registration request without any authentication "+
							"challenge. An attacker can register a crafted agent card claiming a trusted "+
							"identity, injecting malicious skill descriptions or attacker-controlled "+
							"callback URLs into the registry.",
						ep),
					Evidence: fmt.Sprintf(
						"GET %s\nHTTP %d (registry path exists)\n\nPOST %s (no auth headers)\nHTTP %d\nresponse snippet: %.400s",
						ep, getResp.StatusCode, ep, postResp.StatusCode, bodyStr),
					Remediation: e.rule.Remediation,
					TargetURL:   ep,
				})
			}
		}
	}

	return findings, nil
}

// isRegistryLike checks whether a response body looks like an agent registry listing.
func isRegistryLike(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "agent") ||
		strings.Contains(s, "registry") ||
		strings.Contains(s, "skill") ||
		strings.Contains(s, "capability")
}
