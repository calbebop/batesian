package rules

import (
	"os"
	"path/filepath"
	"testing"
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
		{ID: "r1", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "critical"}},
		{ID: "r2", Attack: AttackBlock{Protocol: "a2a", Type: "x"}, Info: RuleInfo{Severity: "high"}},
		{ID: "r3", Attack: AttackBlock{Protocol: "mcp", Type: "x"}, Info: RuleInfo{Severity: "low"}},
	}

	f := &Filter{Severities: []string{"critical", "high"}}
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

	// Write a valid small rule alongside an oversized one.
	smallYAML := []byte(validRuleYAML)
	if err := os.WriteFile(filepath.Join(tmp, "small.yaml"), smallYAML, 0644); err != nil {
		t.Fatalf("writing small rule: %v", err)
	}

	// Create a file larger than maxRuleFileBytes (4 MiB).
	big := make([]byte, maxRuleFileBytes+1)
	copy(big, []byte("id: too-big\n"))
	// Fill the rest with spaces so it's valid but huge.
	for i := len("id: too-big\n"); i < len(big); i++ {
		big[i] = ' '
	}
	if err := os.WriteFile(filepath.Join(tmp, "toobig.yaml"), big, 0644); err != nil {
		t.Fatalf("writing oversized rule: %v", err)
	}

	loaded, warns, err := loadFS(os.DirFS(tmp), ".")
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
