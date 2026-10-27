package engine_test

import (
	"context"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

type accessFake struct{}

func (accessFake) Execute(context.Context, string, attack.Options) ([]attack.Finding, error) {
	return []attack.Finding{{
		RuleID: "test-access", Confidence: attack.RiskIndicator, Evidence: "anonymous task read returned owner marker",
		Access: &attack.AccessObservation{Operation: attack.A2ATasksGet, Caller: "anonymous", Owner: "default"},
	}}, nil
}

func init() {
	attack.Register("test-expected-denial", func(attack.RuleContext) attack.Executor { return accessFake{} })
}

func TestEngineExpectedDenial(t *testing.T) {
	rule := &rules.Rule{ID: "test-access", Info: rules.RuleInfo{Name: "Task read", Severity: "medium"},
		Attack: rules.AttackBlock{Protocol: "a2a", Type: "test-expected-denial"}}
	for _, tt := range []struct {
		name    string
		denials []attack.ExpectedDenial
		want    attack.Confidence
	}{
		{"no policy", nil, attack.RiskIndicator},
		{"matching policy", []attack.ExpectedDenial{{Operation: attack.A2ATasksGet, Caller: "anonymous", Owner: "default"}}, attack.ConfirmedExploit},
		{"unrelated policy", []attack.ExpectedDenial{{Operation: attack.A2ATasksList, Caller: "anonymous", Owner: "default"}}, attack.RiskIndicator},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.New(attack.Options{ExpectedDenials: tt.denials}).Run(t.Context(), "http://example.test", []*rules.Rule{rule})
			if len(got) != 1 || len(got[0].Findings) != 1 || got[0].Findings[0].Confidence != tt.want {
				t.Fatalf("unexpected policy verdict: %+v", got)
			}
		})
	}
}
