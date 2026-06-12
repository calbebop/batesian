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
func init() {
	attack.Register("a2a-wellknown-hostinject", func(rc attack.RuleContext) attack.Executor { return NewWellKnownHostInjectExecutor(rc) })
}

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

			reflections := findReflections(card, hostInjectCanary)
			if len(reflections) == 0 {
				continue
			}

			// Split reflections by trust-relevance. The dangerous case is the
			// canary landing in an authority/URL field (url, endpoint, *.url, or
			// any value that is itself a URL) - that is the agent's advertised
			// service location which other agents and registries trust and cache.
			// Reflection into a non-URL field (e.g. name, description) is a real
			// injection primitive but far lower direct impact, so it is reported
			// as a RiskIndicator rather than a confirmed host-injection exploit.
			var urlPaths, otherPaths []string
			for _, rf := range reflections {
				if isAuthorityField(rf.path) || strings.Contains(rf.value, "://") {
					urlPaths = append(urlPaths, rf.path)
				} else {
					otherPaths = append(otherPaths, rf.path)
				}
			}

			severity, confidence, reflectedIn := "medium", attack.RiskIndicator, otherPaths
			impact := "a non-URL field, which is a reflection primitive but not directly a " +
				"service-URL takeover; verify whether any consumer trusts this field"
			if len(urlPaths) > 0 {
				severity, confidence, reflectedIn = "high", attack.ConfirmedExploit, urlPaths
				impact = "an authority/URL field. An attacker who can influence this header " +
					"(via a caching layer, HTTP request smuggling, or cache poisoning) can make " +
					"other agents or registries that cache this card resolve the agent's service " +
					"URL to attacker-controlled infrastructure"
			}

			key := probe.header + strings.Join(reflectedIn, ",")
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   severity,
				Confidence: confidence,
				Title: fmt.Sprintf(
					"A2A Agent Card reflects %q header value in field(s): %s",
					probe.header, strings.Join(reflectedIn, ", ")),
				Description: fmt.Sprintf(
					"The Agent Card endpoint at %s%s reflects the value of the %q header (%q) "+
						"into %s: %s.",
					vars.BaseURL, path, probe.header, probe.value, impact, strings.Join(reflectedIn, ", ")),
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

// reflection records where the canary was found and the value it appeared in.
type reflection struct {
	path  string
	value string
}

// findReflections recursively walks a JSON object and returns the dot-paths and
// values of any string field whose value contains the canary substring.
func findReflections(v interface{}, canary string) []reflection {
	var out []reflection
	walkJSON(v, "", canary, &out)
	return out
}

func walkJSON(v interface{}, prefix, canary string, out *[]reflection) {
	switch vt := v.(type) {
	case map[string]interface{}:
		for k, val := range vt {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			walkJSON(val, key, canary, out)
		}
	case string:
		if strings.Contains(vt, canary) {
			*out = append(*out, reflection{path: prefix, value: vt})
		}
	case []interface{}:
		for i, item := range vt {
			walkJSON(item, fmt.Sprintf("%s[%d]", prefix, i), canary, out)
		}
	}
}

// isAuthorityField reports whether a dot-path's leaf key denotes a URL/authority
// field (url, uri, endpoint, or any key ending in "url"/"uri"). Array suffixes
// like "interfaces[2].url" are handled by splitting on the last dot.
func isAuthorityField(path string) bool {
	leaf := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		leaf = path[i+1:]
	}
	if j := strings.Index(leaf, "["); j >= 0 {
		leaf = leaf[:j]
	}
	leaf = strings.ToLower(leaf)
	switch leaf {
	case "url", "uri", "endpoint":
		return true
	}
	return strings.HasSuffix(leaf, "url") || strings.HasSuffix(leaf, "uri")
}
