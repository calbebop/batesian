package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// skillPoisonPattern is a named regex with a heuristic score.
// The pattern set mirrors mcp/tool_poison.go intentionally: the same injection
// directives that work in MCP tool descriptions work equally well in A2A skill
// fields because both are consumed by LLMs making routing decisions.
type skillPoisonPattern struct {
	name  string
	re    *regexp.Regexp
	score int
}

var skillPoisonPatterns = []skillPoisonPattern{
	{"instruction_override", regexp.MustCompile(`(?i)IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS`), 5},
	{"system_directive", regexp.MustCompile(`(?i)[\[<(]SYSTEM\s*:`), 5},
	{"chatml_injection", regexp.MustCompile(`(?i)<\|im_start\|>\s*(system|assistant|user)\b`), 5},
	{"llama_injection", regexp.MustCompile(`(?i)(\[INST\]|<<SYS>>|\[/INST\]|</s>)`), 5},
	{"openai_role_tag", regexp.MustCompile(`(?i)<\|(system|assistant|endoftext)\|>`), 4},
	{"important_tag", regexp.MustCompile(`(?i)<IMPORTANT>|<CRITICAL>|<URGENT>`), 3},
	{"note_override", regexp.MustCompile(`(?i)\[NOTE\s*:.*(?:ignore|override|bypass|disregard)`), 4},
	{"you_must", regexp.MustCompile(`(?i)\byou\s+(must|should|need to|have to|are required to)\b`), 2},
	{"always_first", regexp.MustCompile(`(?i)\b(always|first)\s+(send|include|add|provide|attach|append)\b`), 2},
	{"before_responding", regexp.MustCompile(`(?i)before\s+(responding|answering|executing|proceeding)`), 2},
	{"do_not_tell", regexp.MustCompile(`(?i)\bdo\s+not\s+(tell|inform|reveal|mention|disclose)\b`), 3},
	{"exfil_url", regexp.MustCompile(`https?://[^\s"']{15,}`), 2},
	{"exfil_verbs", regexp.MustCompile(`(?i)\b(exfiltrate|exfil|leak|steal|collect|capture|harvest)\b`), 4},
	{"send_to_url", regexp.MustCompile(`(?i)(send|post|upload|transmit)\s+.{0,50}\s+to\s+https?://`), 4},
	{"credential_keywords", regexp.MustCompile(`(?i)\b(password|secret|api.?key|auth.?token|bearer|private.?key|ssh.?key)\b`), 2},
	{"unicode_tag_block", regexp.MustCompile(`[\x{E0000}-\x{E007F}]`), 4},
}

func scoreDescription(desc string) (int, []string) {
	var total int
	var matched []string
	for _, p := range skillPoisonPatterns {
		if p.re.MatchString(desc) {
			total += p.score
			matched = append(matched, fmt.Sprintf("%s(+%d)", p.name, p.score))
		}
	}
	return total, matched
}

func scoreToSeverity(score int) string {
	switch {
	case score >= 12:
		return "critical"
	case score >= 8:
		return "high"
	case score >= 5:
		return "medium"
	case score >= 3:
		return "low"
	default:
		return "info"
	}
}

// SkillPoisonExecutor scans A2A Agent Card skill descriptions for prompt
// injection patterns using the same heuristic scoring model as
// mcp-tool-poison-001 (rule a2a-skill-poison-001).
//
// The attack surface is the Agent Card skills array rather than tools/list,
// but the injection mechanism and LLM-mediated risk are identical.
type SkillPoisonExecutor struct {
	rule attack.RuleContext
}

// NewSkillPoisonExecutor creates an executor for a2a-skill-poison.
func NewSkillPoisonExecutor(r attack.RuleContext) *SkillPoisonExecutor {
	return &SkillPoisonExecutor{rule: r}
}

// skill represents the relevant fields from an A2A skill object.
type skill struct {
	ID          string
	Name        string
	Description string
	Tags        []string
	Examples    []string
}

func (e *SkillPoisonExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	cardPaths := []string{
		"/.well-known/agent.json",
		"/.well-known/agent-card.json",
	}

	for _, path := range cardPaths {
		cardURL := vars.BaseURL + path
		resp, err := client.GET(ctx, cardURL, nil)
		if err != nil || !resp.IsSuccess() {
			continue
		}

		var card map[string]interface{}
		if err := json.Unmarshal(resp.Body, &card); err != nil {
			continue
		}

		skillsRaw, _ := card["skills"].([]interface{})
		if len(skillsRaw) == 0 {
			continue
		}

		skills := parseSkills(skillsRaw)
		return e.scanSkills(skills, cardURL), nil
	}

	return nil, nil
}

func (e *SkillPoisonExecutor) scanSkills(skills []skill, cardURL string) []attack.Finding {
	var findings []attack.Finding

	for _, s := range skills {
		label := s.Name
		if label == "" {
			label = s.ID
		}

		// Scan description
		if s.Description != "" {
			score, matched := scoreDescription(s.Description)
			if score >= 2 {
				sev := scoreToSeverity(score)
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   sev,
					Confidence: attack.RiskIndicator,
					Title: fmt.Sprintf("A2A skill %q description contains potential injection patterns (score %d)",
						label, score),
					Description: fmt.Sprintf(
						"The description field for skill %q in the Agent Card at %s contains patterns "+
							"consistent with prompt injection. An orchestrator LLM that reads skill "+
							"descriptions to make routing decisions may execute attacker-controlled "+
							"instructions before a task is submitted.",
						label, cardURL),
					Evidence: fmt.Sprintf(
						"skill: %q\nfield: description\npatterns matched: %v\nsnippet: %.400s",
						label, matched, s.Description),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}

		// Scan examples array (each example is a natural-language prompt)
		for i, ex := range s.Examples {
			score, matched := scoreDescription(ex)
			if score >= 2 {
				sev := scoreToSeverity(score)
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   sev,
					Confidence: attack.RiskIndicator,
					Title: fmt.Sprintf("A2A skill %q examples[%d] contains potential injection patterns (score %d)",
						label, i, score),
					Description: fmt.Sprintf(
						"The examples[%d] field for skill %q at %s contains patterns that could "+
							"cause prompt injection if an orchestrator LLM reads examples to understand "+
							"usage context.",
						i, label, cardURL),
					Evidence: fmt.Sprintf(
						"skill: %q\nfield: examples[%d]\npatterns matched: %v\nsnippet: %.400s",
						label, i, matched, ex),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}

		// Scan tags (lower threshold since tags are short strings)
		for _, tag := range s.Tags {
			score, matched := scoreDescription(tag)
			if score >= 3 {
				findings = append(findings, attack.Finding{
					RuleID:     e.rule.ID,
					RuleName:   e.rule.Name,
					Severity:   "medium",
					Confidence: attack.RiskIndicator,
					Title: fmt.Sprintf("A2A skill %q tag contains potential injection pattern (score %d)",
						label, score),
					Description: fmt.Sprintf(
						"A tag value for skill %q at %s contains a high-confidence injection pattern. "+
							"Tags are short strings so a single high-scoring match warrants attention.",
						label, cardURL),
					Evidence: fmt.Sprintf(
						"skill: %q\nfield: tags\npatterns matched: %v\ntag value: %.200s",
						label, matched, tag),
					Remediation: e.rule.Remediation,
					TargetURL:   cardURL,
				})
			}
		}
	}

	return findings
}

// parseSkills converts the raw JSON skills array into typed skill structs.
func parseSkills(raw []interface{}) []skill {
	var out []skill
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		s := skill{
			ID:          stringField(m, "id"),
			Name:        stringField(m, "name"),
			Description: stringField(m, "description"),
		}
		if tagsRaw, ok := m["tags"].([]interface{}); ok {
			for _, t := range tagsRaw {
				if ts, ok := t.(string); ok {
					s.Tags = append(s.Tags, ts)
				}
			}
		}
		if exsRaw, ok := m["examples"].([]interface{}); ok {
			for _, ex := range exsRaw {
				if es, ok := ex.(string); ok {
					s.Examples = append(s.Examples, es)
				}
			}
		}
		out = append(out, s)
	}
	return out
}

// stringField is a nil-safe map string accessor.
func stringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}
