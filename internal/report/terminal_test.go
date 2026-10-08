package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func TestEscapeTerminal(t *testing.T) {
	input := "safe 🌍\x1b]8;;https://evil.example\x07label\rreplace\tcell\b\u009B\u202E\u2066\u2028\u200D\U000E0001"
	want := "safe 🌍\\u001B]8;;https://evil.example\\u0007label\\u000Dreplace\\u0009cell\\u0008\\u009B\\u202E\\u2066\\u2028\\u200D\\U000E0001"
	if got := report.EscapeTerminal(input); got != want {
		t.Fatalf("EscapeTerminal() = %q, want %q", got, want)
	}
	if got := report.EscapeTerminal("line one\nline two"); got != "line one\\u000Aline two" {
		t.Fatalf("newline escaped as %q", got)
	}
}

func TestPrinterEscapesProbeFields(t *testing.T) {
	var buf bytes.Buffer
	p := report.New(&buf, false)
	p.ProbeHeader("https://agent.example/\x1b[2J", "a2a")
	p.PrintProbeTable(&report.ProbeResult{
		Name: "agent\rspoof", Description: "first\nsecond", URL: "https://agent.example/\x1b[2J",
		Skills: []report.SkillSummary{{ID: "skill\tcolumn", Name: "name\u202E", Tags: []string{"tag\x1b[31m"}}},
		Flags:  []report.AttackFlag{{Severity: "high", RuleID: "rule\b", Message: "alert\x1b]8;;https://evil.example\x07"}},
	})
	p.PrintMCPProbeTable(&report.MCPProbeResult{
		ServerName: "server\rspoof", Tools: []report.MCPToolSummary{{Name: "tool\tcell", Description: "desc\x1b[2J"}},
		Resources: []report.MCPResourceSummary{{URI: "uri\nforged", MimeType: "type\u202E"}},
		Prompts:   []report.MCPPromptSummary{{Name: "prompt\x1b[31m"}},
	})
	out := buf.String()
	for _, want := range []string{"\\u001B", "\\u000D", "\\u0009", "\\u000A", "\\u0008", "\\u202E"} {
		if !strings.Contains(out, want) {
			t.Errorf("probe output lacks %q:\n%s", want, out)
		}
	}
	for _, raw := range []string{"\x1b", "\r", "\b", "\u202E"} {
		if strings.Contains(out, raw) {
			t.Errorf("probe output contains raw control %q", raw)
		}
	}
}

func TestPrinterEscapesFindingsAndStatus(t *testing.T) {
	var buf bytes.Buffer
	p := report.New(&buf, true)
	p.Info("target\n[+] forged status")
	p.PrintScanSummary([]engine.RunResult{
		{
			Rule: &rules.Rule{ID: "rule-1"},
			Findings: []attack.Finding{{
				RuleID: "rule-1", Severity: "high\x1b[2J", Title: "title\x1b[2J", TargetURL: "https://agent.example/\rforged",
				Evidence: "evidence\x1b]8;;https://evil.example\x07", Related: []attack.Finding{{
					RuleID: "related\tfield", Evidence: "detail\b", Remediation: "fix\u202E",
					Chain: []attack.ChainStep{{Hop: 1, Principal: "actor\r", Action: "read\x1b[31m", Outcome: "accepted\u2066"}},
				}},
			}},
		},
		{Rule: &rules.Rule{ID: "rule-2"}, Skipped: true, SkipMsg: "skip\n[+] forged"},
		{Rule: &rules.Rule{ID: "rule-3"}, Err: errors.New("failure\x1b[2J")},
	})
	out := buf.String()
	for _, want := range []string{"target\\u000A[+] forged status", "title\\u001B", "forged", "related\\u0009field", "fix\\u202E", "accepted\\u2066", "failure\\u001B"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output lacks %q:\n%s", want, out)
		}
	}
	for _, raw := range []string{"\x1b", "\r", "\b", "\u202E", "\u2066"} {
		if strings.Contains(out, raw) {
			t.Errorf("scan output contains raw control %q", raw)
		}
	}
}

func TestTerminalEscapingDoesNotChangeJSON(t *testing.T) {
	value := "line\n\x1b[31m\u202E"
	var buf bytes.Buffer
	if err := report.New(&buf, false).PrintJSON(map[string]string{"value": value}); err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if decoded["value"] != value {
		t.Fatalf("JSON value changed: %q", decoded["value"])
	}
}
