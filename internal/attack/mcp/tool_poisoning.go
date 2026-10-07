package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolPoisoningExecutor inspects a server's tool manifest for the integrity
// failures behind rug-pull and description-injection attacks
// (rule mcp-tool-poisoning-001, OWASP MCP03).
//
// The client is the trust boundary here: an agent reads tool descriptions as
// instructions, so whatever a manifest says is what the model does. Four
// checks, all judged on bytes rather than semantics:
//
//  1. Hidden characters. Format characters can obscure tool definitions but
//     may also be legitimate Unicode text. Indicator, medium.
//  2. Duplicate tool names. Name-based approval and dispatch may be ambiguous.
//     Indicator, medium.
//  3. Instruction-injection patterns. Imperative phrases aimed at the model
//     ("ignore previous instructions"), credential paths paired with send/
//     upload verbs, and fetch-and-post chains are the recurring shapes of
//     published poisoning samples. Pattern matches are reported as an
//     indicator at medium: a security scanner's own description can trip a
//     pattern without being malicious, and the finding says so.
//  4. Manifest drift between consecutive reads. Rapid changes may affect
//     clients that cache or approve tool definitions. Indicator, medium.
//
// Every check reads only the listing; nothing is invoked, so no tool ever
// runs because of this rule.
type ToolPoisoningExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-tool-poisoning", func(rc attack.RuleContext) attack.Executor { return NewToolPoisoningExecutor(rc) })
}

func NewToolPoisoningExecutor(r attack.RuleContext) *ToolPoisoningExecutor {
	return &ToolPoisoningExecutor{rule: r}
}

func (e *ToolPoisoningExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// The manifest is inspected however the caller can read it: a gated server
	// should be testable with the operator's credential, an open one without.
	client := attack.NewHTTPClient(opts, vars)

	return runOnEachWire(ctx, client, vars.BaseURL, func(session mcpSession) ([]attack.Finding, bool) {
		return e.probeSession(ctx, client, session)
	})
}

func (e *ToolPoisoningExecutor) probeSession(ctx context.Context, client *attack.HTTPClient, session mcpSession) ([]attack.Finding, bool) {
	if !session.ServerSupports("tools") {
		return nil, true
	}

	first, ok := listToolPages(ctx, client, session, 3)
	if !ok {
		return nil, false
	}
	firstText := canonicalTools(first)
	// Compare a second listing on the same wire for rapid changes.
	second, ok := listToolPages(ctx, client, session, 3+toolListPageCap)
	if !ok {
		return e.manifestFindings(session.Endpoint, firstText, ""), false
	}
	secondText := canonicalTools(second)

	drift := ""
	if !sameToolManifest(firstText, secondText) {
		drift = diffSummary(firstText, secondText)
	}
	return e.manifestFindings(session.Endpoint, firstText, drift), true
}

// canonicalTools serializes each entry compactly and sorts the results, so
// manifest comparison is independent of the server's array order.
func canonicalTools(tools []json.RawMessage) string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		var v interface{}
		if json.Unmarshal(t, &v) == nil {
			if b, err := json.Marshal(v); err == nil {
				out = append(out, string(b))
			} else {
				out = append(out, string(t))
			}
		} else {
			out = append(out, string(t))
		}
	}
	sort.Strings(out)
	sum := sha256.Sum256([]byte(strings.Join(out, "\n")))
	return hex.EncodeToString(sum[:]) + "\n" + strings.Join(out, "\n")
}

// sameToolManifest compares two canonical serializations byte for byte.
func sameToolManifest(a, b string) bool { return a == b }

// diffSummary names the tool-level differences between two manifests: names
// added, removed, and present in both but altered.
func diffSummary(oldCanon, newCanon string) string {
	oldSet := canonNameMap(oldCanon)
	newSet := canonNameMap(newCanon)
	var added, removed, changed []string
	for name, oldEntry := range oldSet {
		newEntry, ok := newSet[name]
		if !ok {
			removed = append(removed, name)
			continue
		}
		if oldEntry != newEntry {
			changed = append(changed, name)
		}
	}
	for name := range newSet {
		if _, ok := oldSet[name]; !ok {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	parts := []string{}
	if len(added) > 0 {
		parts = append(parts, "added: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed: "+strings.Join(removed, ", "))
	}
	if len(changed) > 0 {
		parts = append(parts, "changed: "+strings.Join(changed, ", "))
	}
	if len(parts) == 0 {
		return "manifest hash changed (entry order or unnamed fields)"
	}
	return strings.Join(parts, "; ")
}

// canonNameMap extracts name -> canonical entry pairs from a canonical
// serialization (hash line first, then one JSON object per line).
func canonNameMap(canon string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(canon, "\n")
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var probe struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(line), &probe) == nil && probe.Name != "" {
			out[probe.Name] = line
		}
	}
	return out
}

// hiddenRunes includes zero-width and bidirectional format characters.
const hiddenRunes = "\u200B\u200C\u200D\u2060\uFEFF\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069"

var (
	injectionImperative = regexp.MustCompile(`(?i)(ignore|disregard|forget)[^\n.]{0,40}(previous|prior|above|earlier|system|instructions)`)
	injectionCredential = regexp.MustCompile(`(?i)(read|send|upload|post|exfiltrat\w*)[^\n.]{0,60}(\.env\b|\.ssh|id_rsa|credential|\bpassword\b|api[_ ]?key|access[_ ]?token)`)
	injectionFetchPost  = regexp.MustCompile(`(?i)(post|send|upload|curl|wget|fetch)\b[^\n.]{0,40}https?://`)
)

var injectionPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"instruction override", injectionImperative},
	{"credential access instruction", injectionCredential},
	{"fetch-and-exfiltrate chain", injectionFetchPost},
}

// manifestFindings runs the four checks over one manifest. drift is empty
// when the second listing matched or was unavailable.
func (e *ToolPoisoningExecutor) manifestFindings(endpoint string, canon, drift string) []attack.Finding {
	lines := strings.Split(canon, "\n")
	entries := lines[1:]

	var findings []attack.Finding

	// Check 2: duplicate names.
	seen := map[string]int{}
	for i, line := range entries {
		var t struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(line), &t) != nil || t.Name == "" {
			continue
		}
		if firstAt, dup := seen[t.Name]; dup {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("MCP manifest declares %q more than once (ambiguous tool identity)", t.Name),
				Description: fmt.Sprintf(
					"The tools/list response from %s contains two entries named %q (positions %d and %d). "+
						"The spec recommends unique names per server. Duplicates can make name-based approval "+
						"and dispatch ambiguous, but this listing does not show which definition a client or "+
						"server will use.", endpoint, t.Name, firstAt+1, i+1),
				Evidence:    fmt.Sprintf("endpoint: %s\nduplicate tool name: %s", endpoint, t.Name),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		} else {
			seen[t.Name] = i
		}
	}

	// Checks 1 and 3 scan each entry's raw bytes: name, description and schema
	// all reach the model, so all three are candidates.
	for i, line := range entries {
		name := toolDisplayName(line, i)

		if idx := strings.IndexAny(line, hiddenRunes); idx >= 0 {
			r, _ := utf8.DecodeRuneInString(line[idx:])
			contextEnd := idx + 24
			if contextEnd > len(line) {
				contextEnd = len(line)
			}
			snippet := strings.Map(func(r rune) rune {
				if strings.ContainsRune(hiddenRunes, r) {
					return '\u25A1' // visible placeholder for the invisible rune
				}
				return r
			}, line[max(0, idx-24):contextEnd])
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("MCP tool %q carries hidden characters in its definition", name),
				Description: fmt.Sprintf(
					"Entry %d of the tools/list response from %s contains U+%04X (shown as \u25A1 in the evidence). "+
						"Format characters can obscure text or alter its rendering, but may be legitimate in Unicode text. "+
						"Review the code point and surrounding text before treating the definition as poisoned.",
					i+1, endpoint, r),
				Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\ncharacter: U+%04X\nbyte offset: %d\n...%s...", endpoint, name, r, idx, snippet),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}

		for _, p := range injectionPatterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "medium",
					Confidence: attack.RiskIndicator,
					Title:      fmt.Sprintf("MCP tool %q description matches an injection pattern (%s)", name, p.name),
					Description: fmt.Sprintf(
						"Entry %d of the tools/list response from %s contains %s phrasing aimed at the model "+
							"rather than documentation aimed at a developer. Tool descriptions are read by agents "+
							"as instructions, so imperative text about prior instructions, credentials, or "+
							"outbound URLs is the shape of a poisoned definition. This check is heuristic: "+
							"security tooling legitimately describes such operations, so treat it as a lead and "+
							"read the flagged text before trusting the tool.",
						i+1, endpoint, p.name),
					Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\npattern: %s\n...%s...", endpoint, name, p.name, matchSnippet(line, loc)),
					Remediation: e.rule.Remediation,
					TargetURL:   endpoint,
				})
				break // one pattern finding per entry keeps the report readable
			}
		}
	}

	// Check 4: drift between the two consecutive listings.
	if drift != "" {
		findings = append(findings, attack.Finding{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "medium",
			Confidence: attack.RiskIndicator,
			Title:      "MCP tool manifest changed between two consecutive reads",
			Description: fmt.Sprintf(
				"Two tools/list requests to %s returned different manifests (%s). MCP permits the tool set "+
					"to change over time. Rapid changes merit review where clients cache or approve definitions, "+
					"but these responses do not show whether a client used an outdated definition.", endpoint, drift),
			Evidence:    fmt.Sprintf("endpoint: %s\ndifferences: %s", endpoint, drift),
			Remediation: e.rule.Remediation,
			TargetURL:   endpoint,
		})
	}

	return findings
}

// toolDisplayName extracts a tool's name for finding titles, falling back to
// its position when the entry has none.
func toolDisplayName(line string, pos int) string {
	var t struct {
		Name string `json:"name"`
	}
	if json.Unmarshal([]byte(line), &t) == nil && t.Name != "" {
		return t.Name
	}
	return fmt.Sprintf("<entry %d>", pos+1)
}

// matchSnippet returns a short window around a regex match for evidence.
func matchSnippet(s string, loc []int) string {
	start := loc[0] - 20
	if start < 0 {
		start = 0
	}
	end := loc[1] + 20
	if end > len(s) {
		end = len(s)
	}
	return "..." + s[start:end] + "..."
}
