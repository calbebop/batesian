package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/calbebop/batesian/internal/attack"
)

// ToolPoisoningExecutor inspects a server's tool manifest for the integrity
// failures behind rug-pull and description-injection attacks
// (rule mcp-tool-poisoning-001, OWASP MCP03).
//
// Agents may pass tool definitions to models as context. Four heuristic checks:
//
//  1. Hidden characters. Format characters can obscure tool definitions but
//     may also be legitimate Unicode text. Indicator, medium.
//  2. Duplicate names or JSON members. Dispatch or parsing may be ambiguous.
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
// Completed listings are inspected without invoking tools.
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
	findings := e.manifestFindings(session.Endpoint, firstText, drift)
	if drift == "" {
		return findings, true
	}
	type findingKey struct{ title, evidence string }
	seen := make(map[findingKey]struct{}, len(findings))
	for _, finding := range findings {
		seen[findingKey{finding.Title, finding.Evidence}] = struct{}{}
	}
	for _, finding := range e.manifestFindings(session.Endpoint, secondText, "") {
		key := findingKey{finding.Title, finding.Evidence}
		if _, ok := seen[key]; ok {
			continue
		}
		findings = append(findings, finding)
		seen[key] = struct{}{}
	}
	return findings, true
}

// canonicalTools preserves numbers and duplicate-member order while sorting keys.
func canonicalTools(tools []json.RawMessage) string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if entry, err := canonicalToolEntry(t); err == nil {
			out = append(out, entry)
		} else {
			out = append(out, string(t))
		}
	}
	sort.Strings(out)
	sum := sha256.Sum256([]byte(strings.Join(out, "\n")))
	return hex.EncodeToString(sum[:]) + "\n" + strings.Join(out, "\n")
}

func canonicalToolEntry(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out strings.Builder
	if err := writeCanonicalJSON(dec, &out); err != nil {
		return "", err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("multiple JSON values")
		}
		return "", err
	}
	return out.String(), nil
}

func writeCanonicalJSON(dec *json.Decoder, out *strings.Builder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			type member struct{ key, value string }
			var members []member
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("invalid JSON member name")
				}
				var nested strings.Builder
				if err := writeCanonicalJSON(dec, &nested); err != nil {
					return err
				}
				members = append(members, member{key, nested.String()})
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			sort.SliceStable(members, func(i, j int) bool { return members[i].key < members[j].key })
			out.WriteByte('{')
			for i, member := range members {
				if i > 0 {
					out.WriteByte(',')
				}
				key, _ := json.Marshal(member.key)
				out.Write(key)
				out.WriteByte(':')
				out.WriteString(member.value)
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := writeCanonicalJSON(dec, out); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			out.WriteByte(']')
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", value)
		}
	case string:
		encoded, _ := json.Marshal(value)
		out.Write(encoded)
	case json.Number:
		out.WriteString(value.String())
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("unexpected JSON token %T", token)
	}
	return nil
}

func duplicateJSONMember(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return duplicateMemberValue(dec)
}

func duplicateMemberValue(dec *json.Decoder) (string, bool) {
	token, err := dec.Token()
	if err != nil {
		return "", false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return "", false
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return "", false
			}
			key, ok := keyToken.(string)
			if !ok {
				return "", false
			}
			if seen[key] {
				return key, true
			}
			seen[key] = true
			if duplicate, found := duplicateMemberValue(dec); found {
				return duplicate, true
			}
		}
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if duplicate, found := duplicateMemberValue(dec); found {
				return duplicate, true
			}
		}
		_, _ = dec.Token()
	}
	return "", false
}

// sameToolManifest compares two canonical serializations byte for byte.
func sameToolManifest(a, b string) bool { return a == b }

// diffSummary names the tool-level differences between two manifests: names
// added, removed, and present in both but altered.
func diffSummary(oldCanon, newCanon string) string {
	oldSet := canonEntriesByName(oldCanon)
	newSet := canonEntriesByName(newCanon)
	var added, removed, changed []string
	for name, oldEntry := range oldSet {
		newEntry, ok := newSet[name]
		if !ok {
			removed = append(removed, name)
			continue
		}
		if !slices.Equal(oldEntry, newEntry) {
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
		return "manifest hash changed (unnamed or unparseable entries)"
	}
	return strings.Join(parts, "; ")
}

// canonEntriesByName keeps every definition for each name.
func canonEntriesByName(canon string) map[string][]string {
	out := map[string][]string{}
	lines := strings.Split(canon, "\n")
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var probe struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(line), &probe) == nil && probe.Name != "" {
			out[probe.Name] = append(out[probe.Name], line)
		}
	}
	for name := range out {
		sort.Strings(out[name])
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

func jsonStringValues(line string) []string {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var values []string
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		if value, ok := token.(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func matchHiddenText(values []string) (rune, int, string, bool) {
	for _, value := range values {
		if idx := strings.IndexAny(value, hiddenRunes); idx >= 0 {
			r, _ := utf8.DecodeRuneInString(value[idx:])
			runes := []rune(value)
			pos := utf8.RuneCountInString(value[:idx])
			start := max(0, pos-12)
			end := min(len(runes), pos+13)
			snippet := strings.Map(func(r rune) rune {
				if strings.ContainsRune(hiddenRunes, r) {
					return '\u25A1'
				}
				return r
			}, string(runes[start:end]))
			return r, idx, snippet, true
		}
	}
	return 0, 0, "", false
}

func matchInjectionText(values []string) (string, string, bool) {
	for _, pattern := range injectionPatterns {
		for _, value := range values {
			if loc := pattern.re.FindStringIndex(value); loc != nil {
				return pattern.name, matchSnippet(value, loc), true
			}
		}
	}
	return "", "", false
}

// manifestFindings inspects one listing and optionally reports drift.
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

	// Check ambiguous members, format characters, and injection patterns.
	for i, line := range entries {
		name := toolDisplayName(line, i)
		values := jsonStringValues(line)
		if member, duplicate := duplicateJSONMember([]byte(line)); duplicate {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("MCP tool %q repeats JSON member %q (ambiguous definition)", name, member),
				Description: fmt.Sprintf(
					"Entry %d of the tools/list response from %s repeats the JSON member %q. "+
						"Clients may keep different values or reject the definition, so review the raw entry.",
					i+1, endpoint, member),
				Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\nrepeated member: %q", endpoint, name, member),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}

		if r, idx, snippet, ok := matchHiddenText(values); ok {
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
				Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\ncharacter: U+%04X\nstring byte offset: %d\n...%s...", endpoint, name, r, idx, snippet),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
		}

		if pattern, snippet, ok := matchInjectionText(values); ok {
			findings = append(findings, attack.Finding{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "medium",
				Confidence: attack.RiskIndicator,
				Title:      fmt.Sprintf("MCP tool %q definition matches an injection pattern (%s)", name, pattern),
				Description: fmt.Sprintf(
					"Entry %d of the tools/list response from %s contains %s phrasing in a tool-definition string. "+
						"Agents may consume names, descriptions, and schemas, so imperative text about prior "+
						"instructions, credentials, or outbound URLs can signal poisoning. This check is "+
						"heuristic; review the matched text before treating it as malicious.", i+1, endpoint, pattern),
				Evidence:    fmt.Sprintf("endpoint: %s\ntool: %s\npattern: %s\n%s", endpoint, name, pattern, snippet),
				Remediation: e.rule.Remediation,
				TargetURL:   endpoint,
			})
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
