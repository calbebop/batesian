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
//  1. Hidden characters. Zero-width spaces and bidi control codes inside a
//     name or description are concealment, full stop: no legitimate
//     description needs invisible text or direction overrides, and both are
//     how payloads hide from the human who approved the tool. Confirmed,
//     high.
//  2. Duplicate tool names. The spec requires names unique per server; a
//     repeated name lets whichever entry sorts last shadow the trusted one.
//     Confirmed, medium.
//  3. Instruction-injection patterns. Imperative phrases aimed at the model
//     ("ignore previous instructions"), credential paths paired with send/
//     upload verbs, and fetch-and-post chains are the recurring shapes of
//     published poisoning samples. Pattern matches are reported as an
//     indicator at medium: a security scanner's own description can trip a
//     pattern without being malicious, and the finding says so.
//  4. Manifest drift between two consecutive reads. A manifest that changes
//     between one listing and the next - same wire, same session, seconds
//     apart - is exactly the rug-pull primitive: approval-time content and
//     execution-time content disagreeing. Confirmed, high. What this cannot
//     see is slow drift across deployments, which belongs to scheduled scans
//     diffing their own output, not to a single connection.
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

	first, firstText := e.listTools(ctx, client, session, 3)
	if first == nil {
		return nil, false // no protocol-level verdict: never assessed
	}
	// Second read for the drift oracle, back to back with the first. No sleep:
	// the round trip is the spacing, and a manifest that differs across two
	// immediate reads is unstable by any definition that matters here.
	second, secondText := e.listTools(ctx, client, session, 4)
	if second == nil {
		// Drift cannot be judged, but the first listing still supports checks
		// 1 through 3, which stand on their own.
		return e.manifestFindings(session.Endpoint, firstText, ""), true
	}

	drift := ""
	if !sameToolManifest(firstText, secondText) {
		drift = diffSummary(firstText, secondText)
	}
	return e.manifestFindings(session.Endpoint, firstText, drift), true
}

// listTools fetches one listing and returns the raw per-tool entries plus a
// canonical serialization used for hashing and diffs. A nil slice means no
// protocol-level verdict came back.
func (e *ToolPoisoningExecutor) listTools(ctx context.Context, client *attack.HTTPClient, s mcpSession, id int) ([]json.RawMessage, string) {
	resp, err := s.post(ctx, client, id, "tools/list", nil)
	if verdict, _ := classifyProbe(resp, err); verdict != probeAnswered {
		return nil, ""
	}
	var body struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
		Error map[string]interface{} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &body) != nil || body.Error != nil {
		return nil, ""
	}
	canonical := canonicalTools(body.Result.Tools)
	return body.Result.Tools, canonical
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

// hiddenRunes are zero-width and bidirectional control characters: invisible
// in any review surface, load-bearing in a prompt.
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
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("MCP manifest declares %q more than once (tool shadowing)", t.Name),
				Description: fmt.Sprintf(
					"The tools/list response from %s contains two entries named %q (positions %d and %d). "+
						"The spec requires tool names to be unique per server; a duplicated name lets one "+
						"definition shadow whichever definition the caller approved, which is the "+
						"tool-squatting half of description injection.", endpoint, t.Name, firstAt+1, i+1),
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
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      fmt.Sprintf("MCP tool %q carries hidden characters in its definition", name),
				Description: fmt.Sprintf(
					"Entry %d of the tools/list response from %s contains zero-width or bidirectional "+
						"control characters (shown as \u25A1 in the evidence). Invisible text and direction "+
						"overrides have no legitimate use in a tool definition; they exist to hide payload "+
						"content from whoever reviews and approves the tool while it still reaches the model.",
					i+1, endpoint),
				Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\nhidden character at byte offset %d\n...%s...", endpoint, name, idx, snippet),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
			continue // one concealment finding per entry; patterns add nothing here
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
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP tool manifest changed between two consecutive reads (rug-pull primitive)",
			Description: fmt.Sprintf(
				"Two tools/list requests issued back to back on the same session at %s returned different "+
					"manifests (%s). Approval-time content and execution-time content disagreeing is the "+
					"primitive every rug-pull attack relies on: a tool approved under one definition runs "+
					"under another. Whatever mechanism mutates the manifest between immediate reads also "+
					"serves mutated definitions to clients that listed tools once and connected later.", endpoint, drift),
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
