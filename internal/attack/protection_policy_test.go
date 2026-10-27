package attack_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestApplyExpectedDenial(t *testing.T) {
	observation := attack.AccessObservation{
		Operation: attack.A2ATasksCancel, Caller: "tenant-b", CallerTenant: "B",
		Owner: "tenant-a", OwnerTenant: "A",
	}
	tests := []struct {
		name   string
		denial attack.ExpectedDenial
		want   bool
	}{
		{"exact relationship", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"}, true},
		{"names without tenant constraints", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "tenant-a"}, true},
		{"different operation", attack.ExpectedDenial{Operation: attack.A2ATasksGet, Caller: "tenant-b", Owner: "tenant-a"}, false},
		{"different caller", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-c", Owner: "tenant-a"}, false},
		{"different owner", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "tenant-c"}, false},
		{"different caller tenant", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-b", CallerTenant: "C", Owner: "tenant-a"}, false},
		{"different owner tenant", attack.ExpectedDenial{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "tenant-a", OwnerTenant: "C"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := attack.Finding{Confidence: attack.RiskIndicator, Evidence: "owner read-back showed canceled", Access: &observation}
			got := attack.ApplyExpectedDenial(&finding, []attack.ExpectedDenial{tt.denial})
			if got != tt.want {
				t.Fatalf("promotion = %v, want %v", got, tt.want)
			}
			if tt.want {
				if finding.Confidence != attack.ConfirmedExploit || !strings.Contains(finding.Evidence, "expected denial:") {
					t.Fatalf("missing policy-backed confirmation: %+v", finding)
				}
			} else if finding.Confidence != attack.RiskIndicator || strings.Contains(finding.Evidence, "expected denial:") {
				t.Fatalf("unmatched policy changed finding: %+v", finding)
			}
		})
	}
}

func TestAccessObservationIsNotSerialized(t *testing.T) {
	finding := attack.Finding{Access: &attack.AccessObservation{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "tenant-a"}}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "tenant-b") || strings.Contains(string(encoded), "Access") {
		t.Fatalf("internal access metadata leaked into JSON: %s", encoded)
	}
}

func TestApplyExpectedDenialRequiresObservedAccess(t *testing.T) {
	denial := attack.ExpectedDenial{Operation: attack.MCPPromptsList, Caller: "anonymous"}
	tests := []attack.Finding{
		{Confidence: attack.RiskIndicator, Evidence: "names returned"},
		{Confidence: attack.RiskIndicator, Access: &attack.AccessObservation{Operation: attack.MCPPromptsList, Caller: "anonymous"}},
		{Confidence: attack.ConfirmedExploit, Evidence: "already confirmed", Access: &attack.AccessObservation{Operation: attack.MCPPromptsList, Caller: "anonymous"}},
	}
	for i, finding := range tests {
		if attack.ApplyExpectedDenial(&finding, []attack.ExpectedDenial{denial}) {
			t.Errorf("case %d promoted without a new access observation", i)
		}
	}
}
