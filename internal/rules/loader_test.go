package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const validRuleYAML = `
id: a2a-test-001
info:
  name: Test Rule
  author: test
  severity: high
  description: A test rule
  tags:
    - a2a
    - test
attack:
  protocol: a2a
  type: extcard-unauth-disclosure
remediation: Fix it.
`

const missingIDYAML = `
info:
  name: Missing ID
  severity: high
  description: No ID
attack:
  protocol: a2a
  type: extcard-unauth-disclosure
`

const missingTypeYAML = `
id: a2a-test-002
info:
  name: No Attack Type
  severity: medium
  description: Missing attack.type
attack:
  protocol: mcp
`

func TestParseRule_Valid(t *testing.T) {
	rule, err := parseRule([]byte(validRuleYAML), "test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.ID != "a2a-test-001" {
		t.Errorf("ID = %q", rule.ID)
	}
	if rule.Info.Severity != "high" {
		t.Errorf("Severity = %q", rule.Info.Severity)
	}
	if rule.Attack.Protocol != "a2a" {
		t.Errorf("Protocol = %q", rule.Attack.Protocol)
	}
	if rule.Attack.Type != "extcard-unauth-disclosure" {
		t.Errorf("Type = %q", rule.Attack.Type)
	}
}

func TestParseRule_MissingID(t *testing.T) {
	_, err := parseRule([]byte(missingIDYAML), "test.yaml")
	if err == nil {
		t.Fatal("expected validation error for missing id, got nil")
	}
}

func TestParseRule_MissingType(t *testing.T) {
	_, err := parseRule([]byte(missingTypeYAML), "test.yaml")
	if err == nil {
		t.Fatal("expected validation error for missing attack.type, got nil")
	}
}

func TestParseRule_RejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		field string
	}{
		{"root", validRuleYAML + "unexpected: true\n", "unexpected"},
		{"info", strings.Replace(validRuleYAML, "  name: Test Rule\n", "  name: Test Rule\n  referencez: []\n", 1), "referencez"},
		{"attack", strings.Replace(validRuleYAML, "  protocol: a2a\n", "  protocol: a2a\n  protcol: mcp\n", 1), "protcol"},
		{"merged info", strings.Replace(validRuleYAML, "  name: Test Rule\n", "  <<: &defaults\n    name: Default\n    unexpected: true\n  name: Test Rule\n", 1), "unexpected"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRule([]byte(tc.yaml), "test.yaml")
			if err == nil || !strings.Contains(err.Error(), "field "+tc.field+" not found") {
				t.Fatalf("expected unknown field error, got %v", err)
			}
		})
	}
}

func TestParseRule_RejectsDuplicateFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"root", validRuleYAML + "id: duplicate\n"},
		{"info", strings.Replace(validRuleYAML, "  name: Test Rule\n", "  name: Test Rule\n  name: Duplicate\n", 1)},
		{"attack", strings.Replace(validRuleYAML, "  protocol: a2a\n", "  protocol: a2a\n  protocol: mcp\n", 1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRule([]byte(tc.yaml), "test.yaml")
			if err == nil || !strings.Contains(err.Error(), "already defined") {
				t.Fatalf("expected duplicate field error, got %v", err)
			}
		})
	}
}

func TestParseRule_RejectsTrailingDocuments(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"valid", validRuleYAML + "---\n" + validRuleYAML},
		{"empty", validRuleYAML + "---\n"},
		{"null", validRuleYAML + "---\nnull\n"},
		{"malformed", validRuleYAML + "---\ninfo: [invalid\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRule([]byte(tc.yaml), "test.yaml"); err == nil {
				t.Fatal("expected trailing document to fail")
			}
		})
	}
}

func TestParseRule_AllowsSupportedYAMLFeatures(t *testing.T) {
	data := `---
id: a2a-test-001
info:
  <<: &defaults
    name: Default Name
    author: inherited
    severity: medium
  name: Test Rule
  severity: high
  references: &refs [https://example.com]
  tags: *refs
attack:
  protocol: a2a
  type: extcard-unauth-disclosure
remediation: Fix it.
...
`
	rule, err := parseRule([]byte(data), "test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.Info.Name != "Test Rule" || rule.Info.Author != "inherited" || rule.Info.Severity != "high" {
		t.Fatalf("merge override failed: %+v", rule.Info)
	}
	if len(rule.Info.Tags) != 1 || rule.Info.Tags[0] != "https://example.com" {
		t.Fatalf("alias failed: %v", rule.Info.Tags)
	}
}

func TestParseRule_EmptyContentStillValidates(t *testing.T) {
	for _, data := range []string{"", "# comment only\n", "null\n"} {
		_, err := parseRule([]byte(data), "test.yaml")
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("expected validation error, got %v", err)
		}
	}
}

func TestLoadFS_WarnsOnStrictDecodeError(t *testing.T) {
	fsys := fstest.MapFS{
		"valid.yaml":   {Data: []byte(validRuleYAML)},
		"invalid.yaml": {Data: []byte(validRuleYAML + "unexpected: true\n")},
	}

	loaded, warns, err := loadFS(fsys)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	if len(loaded) != 1 || len(warns) != 1 {
		t.Fatalf("loaded %d rules with %d warnings, want 1 and 1", len(loaded), len(warns))
	}
	if warns[0].Path != "invalid.yaml" {
		t.Fatalf("warning path = %q, want invalid.yaml", warns[0].Path)
	}
}

func TestFilter_Protocol(t *testing.T) {
	rules := []*Rule{
		{ID: "a2a-1", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
		{ID: "mcp-1", Attack: AttackBlock{Protocol: "mcp", Type: "x"}, Info: RuleInfo{Severity: "high"}},
		{ID: "a2a-2", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "low"}},
	}

	f := &Filter{Protocols: []string{"a2a"}}
	got := f.Apply(rules)
	if len(got) != 2 {
		t.Errorf("protocol filter: got %d rules, want 2", len(got))
	}
	for _, r := range got {
		if r.Attack.Protocol != "a2a" {
			t.Errorf("unexpected protocol %q in filtered results", r.Attack.Protocol)
		}
	}
}

func TestFilter_Severity(t *testing.T) {
	rules := []*Rule{
		{ID: "r1", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: " critical "}},
		{ID: "r2", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
		{ID: "r3", Attack: AttackBlock{Protocol: "mcp", Type: "x"}, Info: RuleInfo{Severity: "low"}},
	}

	f := &Filter{Severities: []string{"critical", " high "}}
	got := f.Apply(rules)
	if len(got) != 2 {
		t.Errorf("severity filter: got %d rules, want 2", len(got))
	}
}

func TestFilter_IDs(t *testing.T) {
	rules := []*Rule{
		{ID: "a2a-ext-001", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
		{ID: "a2a-ext-002", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
	}

	f := &Filter{IDs: []string{"a2a-ext-001"}}
	got := f.Apply(rules)
	if len(got) != 1 {
		t.Errorf("ID filter: got %d rules, want 1", len(got))
	}
	if got[0].ID != "a2a-ext-001" {
		t.Errorf("ID = %q", got[0].ID)
	}
}

func TestFilter_Nil(t *testing.T) {
	rules := []*Rule{
		{ID: "r1", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
	}
	var f *Filter
	got := f.Apply(rules)
	if len(got) != 1 {
		t.Errorf("nil filter should return all rules, got %d", len(got))
	}
}

func TestLoadFS_SkipsOversizedFile(t *testing.T) {
	tmp := t.TempDir()

	smallYAML := []byte(validRuleYAML)
	if err := os.WriteFile(filepath.Join(tmp, "small.yaml"), smallYAML, 0644); err != nil {
		t.Fatalf("writing small rule: %v", err)
	}

	big := make([]byte, maxRuleFileBytes+1)
	copy(big, []byte("id: too-big\n"))
	for i := len("id: too-big\n"); i < len(big); i++ {
		big[i] = ' '
	}
	if err := os.WriteFile(filepath.Join(tmp, "toobig.yaml"), big, 0644); err != nil {
		t.Fatalf("writing oversized rule: %v", err)
	}

	loaded, warns, err := loadFS(os.DirFS(tmp))
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("expected 1 loaded rule (small.yaml), got %d", len(loaded))
	}
	if len(warns) != 1 {
		t.Errorf("expected 1 warning for oversized file, got %d", len(warns))
	}
}
