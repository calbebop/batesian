package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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
	// A card has to be served for the reflection test to mean anything. Without
	// one, every probe falls through the continues below and the rule returns an
	// empty slice, which reads as "no reflection" rather than "never tested".
	cardParsed := false

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
			cardParsed = true

			reflections := findReflections(card, hostInjectCanary)
			if len(reflections) == 0 {
				continue
			}

			// Split reflections by trust-relevance. The dangerous case is the
			// canary landing in an authority/URL field (url, endpoint, *.url, or
			// any value that is itself a URL) - that is the agent's advertised
			// service location which other agents and registries trust and cache.
			// Both cases are RiskIndicators: the scanner proves only that the
			// server reflects the header into the card, not that an attacker can
			// set that header for a victim or that a cache serves the poisoned
			// card. A URL-field reflection carries higher severity because its
			// impact, if the header is influenceable, is service-URL takeover.
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
				severity, confidence, reflectedIn = "high", attack.RiskIndicator, urlPaths
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

	if len(findings) == 0 && !cardParsed {
		return nil, attack.ErrInconclusive
	}
	return findings, nil
}

// reflection records where the canary was found and the value it appeared in.
type reflection struct {
	path  string
	value string
}

// findReflections recursively walks a JSON object and returns the dot-paths and
// values of any string field whose value contains the canary substring, sorted by
// path.
//
// The sort is load-bearing, not cosmetic. walkJSON ranges a
// map[string]interface{}, and Go randomizes map iteration order, so without it the
// reflection order changed between runs. Everything downstream inherits that
// order: the caller joins the paths into the dedup key that collapses the same
// reflection across the two well-known paths, so the key differed run to run and
// the dedup hit or missed at random. The same header was reported twice, once as
// "provider.url, url" and once as "url, provider.url", and one fixture yielded 3,
// 4 or 5 findings on identical input. The finding title, description and evidence
// list the fields too, so a stable order also makes two scans of an unchanged
// target diffable.
func findReflections(v interface{}, canary string) []reflection {
	var out []reflection
	walkJSON(v, "", canary, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
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
