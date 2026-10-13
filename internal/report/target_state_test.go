package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func TestCleanScanReportsTargetObjects(t *testing.T) {
	results := []engine.RunResult{{
		Rule: &rules.Rule{ID: "a2a-test-001"},
		TargetObjects: []attack.TargetObject{{
			Kind: "a2a_task", Creation: "confirmed", ID: "task-123",
			Cleanup: attack.CleanupUnavailable, CleanupDetail: "A2A has no task deletion operation",
		}},
	}}
	var table bytes.Buffer
	report.New(&table, false).PrintScanSummary(results)
	if !strings.Contains(table.String(), "task-123") || !strings.Contains(table.String(), "cleanup: unavailable") {
		t.Fatalf("clean table omitted target state: %s", table.String())
	}

	var sarif bytes.Buffer
	if err := report.WriteSARIF(&sarif, results, "test", "https://agent.example"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Invocations []struct {
				Properties struct {
					TargetObjects []struct {
						RuleID  string `json:"ruleId"`
						Kind    string `json:"kind"`
						ID      string `json:"id"`
						Cleanup string `json:"cleanup"`
					} `json:"targetObjects"`
				} `json:"properties"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	objects := doc.Runs[0].Invocations[0].Properties.TargetObjects
	if len(objects) != 1 || objects[0].RuleID != "a2a-test-001" || objects[0].ID != "task-123" ||
		objects[0].Kind != "a2a_task" || objects[0].Cleanup != "unavailable" {
		t.Fatalf("SARIF target objects = %+v", objects)
	}
}
