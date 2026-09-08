package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRulesRejectsUnsupportedOutput(t *testing.T) {
	tests := []struct {
		name   string
		format string
		args   []string
		want   string
	}{
		{
			name:   "unknown list format",
			format: "jsno",
			want:   `unknown output format "jsno"; supported: table, json`,
		},
		{
			name:   "unknown detail format",
			format: "xml",
			args:   []string{"a2a-artifact-tamper-001"},
			want:   `unknown output format "xml"; supported: table, json`,
		},
		{
			name:   "sarif",
			format: "sarif",
			want:   `--output sarif is not supported for rules; use table or json`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setRulesOutputFlag(t, tc.format)
			var out bytes.Buffer
			setRulesOutput(t, &out)

			err := runRules(rulesCmd, tc.args)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("unexpected output: %q", out.String())
			}
		})
	}
}

func TestRulesJSONOutput(t *testing.T) {
	t.Run("list is case insensitive", func(t *testing.T) {
		setRulesOutputFlag(t, "JSON")
		var out bytes.Buffer
		setRulesOutput(t, &out)

		if err := runRules(rulesCmd, nil); err != nil {
			t.Fatalf("runRules: %v", err)
		}
		var got []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("decoding output: %v\n%s", err, out.String())
		}
		if len(got) == 0 || got[0].ID == "" {
			t.Fatalf("expected rules, got %#v", got)
		}
	})

	t.Run("detail", func(t *testing.T) {
		setRulesOutputFlag(t, "json")
		var out bytes.Buffer
		setRulesOutput(t, &out)

		if err := runRules(rulesCmd, []string{"a2a-artifact-tamper-001"}); err != nil {
			t.Fatalf("runRules: %v", err)
		}
		var got struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			References  []string `json:"references"`
			Remediation string   `json:"remediation"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("decoding output: %v\n%s", err, out.String())
		}
		if got.ID != "a2a-artifact-tamper-001" {
			t.Fatalf("id = %q", got.ID)
		}
		if strings.TrimSpace(got.Description) == "" || len(got.References) == 0 || strings.TrimSpace(got.Remediation) == "" {
			t.Fatalf("detail fields missing: %#v", got)
		}
	})
}

func TestRulesTableOutput(t *testing.T) {
	setRulesOutputFlag(t, "table")
	var out bytes.Buffer
	setRulesOutput(t, &out)

	if err := runRules(rulesCmd, nil); err != nil {
		t.Fatalf("runRules: %v", err)
	}
	if !strings.Contains(out.String(), "PROTOCOL") || !strings.Contains(out.String(), "a2a-artifact-tamper-001") || !strings.Contains(out.String(), "rule(s)") {
		t.Fatalf("unexpected table output: %.200s", out.String())
	}
}

func setRulesOutputFlag(t *testing.T, value string) {
	t.Helper()
	if rulesCmd.Flags().Lookup("output") == nil {
		rulesCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	flag := rulesCmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("rules output flag is not registered")
	}
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		_ = flag.Value.Set(oldValue)
		flag.Changed = oldChanged
	})
	if err := flag.Value.Set(value); err != nil {
		t.Fatalf("setting output: %v", err)
	}
	flag.Changed = true
}

func setRulesOutput(t *testing.T, out *bytes.Buffer) {
	t.Helper()
	rulesCmd.SetOut(out)
	t.Cleanup(func() { rulesCmd.SetOut(nil) })
}
