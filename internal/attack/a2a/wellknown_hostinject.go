package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// hostInjectCanary is the value injected into host-related headers.
// It is clearly synthetic to avoid false positives from real allowlists.
const hostInjectCanary = "evil.batesian.invalid"

// WellKnownHostInjectExecutor tests whether the A2A agent card endpoint
// reflects attacker-controlled Host/X-Forwarded-Host values into the
// returned Agent Card JSON (rule a2a-wellknown-hostinject-001).
type WellKnownHostInjectExecutor struct {
	rule attack.RuleContext
}

// NewWellKnownHostInjectExecutor creates an executor for a2a-wellknown-hostinject.
func NewWellKnownHostInjectExecutor(r attack.RuleContext) *WellKnownHostInjectExecutor {
	return &WellKnownHostInjectExecutor{rule: r}
}

// headerProbe pairs a header name with the injected value.
type headerProbe struct {
	header string
	value  string
}

func (e *WellKnownHostInjectExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Try both the v1.0 and legacy well-known paths.
	cardPaths := []string{
		"/.well-known/agent-card.json",
		"/.well-known/agent.json",
	}

	// Headers to inject, in order of severity.
	probes := []headerProbe{
		{"Host", hostInjectCanary},
		{"X-Forwarded-Host", hostInjectCanary},
		{"X-Original-Host", hostInjectCanary},
		{"X-Forwarded-For", hostInjectCanary},
	}

	var findings []attack.Finding
	seen := map[string]bool{}

	for _, path := range cardPaths {
		for _, probe := range probes {
			resp, err := client.GET(ctx, vars.BaseURL+path, map[string]string{
				probe.header: probe.value,
			})
			if err != nil || !resp.IsSuccess() {
				continue
			}

			// Parse the agent card and check if the canary appears in URL fields.
			var card map[string]interface{}
			if err := json.Unmarshal(resp.Body, &card); err != nil {
				continue
			}

			reflectedIn := findReflection(card, hostInjectCanary)
			if len(reflectedIn) == 0 {
				continue
			}

			key := probe.header + strings.Join(reflectedIn, ",")
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title: fmt.Sprintf(
					"A2A Agent Card reflects %q header value in field(s): %s",
					probe.header, strings.Join(reflectedIn, ", ")),
				Description: fmt.Sprintf(
					"The Agent Card endpoint at %s%s reflects the value of the %q header (%q) "+
						"into the %s field(s) of the returned JSON. An attacker who can send requests "+
						"through a caching layer or influence this header (e.g., via HTTP request "+
						"smuggling or cache poisoning) can cause other agents or registries that "+
						"cache this card to believe the agent's service URL is under attacker control.",
					vars.BaseURL, path, probe.header, probe.value, strings.Join(reflectedIn, ", ")),
				Evidence: fmt.Sprintf(
					"GET %s%s\n%s: %s\nReflected in field(s): %v\nResponse snippet: %.300s",
					vars.BaseURL, path, probe.header, probe.value, reflectedIn, string(resp.Body)),
				Remediation: e.rule.Remediation,
				TargetURL:   vars.BaseURL + path,
			})
		}
	}

	return findings, nil
}

// findReflection recursively walks a JSON object and returns the dot-paths of
// any string field whose value contains the canary substring.
func findReflection(v interface{}, canary string) []string {
	var paths []string
	walkJSON(v, "", canary, &paths)
	return paths
}

func walkJSON(v interface{}, prefix, canary string, paths *[]string) {
	switch vt := v.(type) {
	case map[string]interface{}:
		for k, val := range vt {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			walkJSON(val, key, canary, paths)
		}
	case string:
		if strings.Contains(vt, canary) {
			*paths = append(*paths, prefix)
		}
	case []interface{}:
		for i, item := range vt {
			walkJSON(item, fmt.Sprintf("%s[%d]", prefix, i), canary, paths)
		}
	}
}
