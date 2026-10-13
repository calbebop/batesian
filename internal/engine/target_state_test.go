package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/rules"
)

type statefulTestExecutor struct {
	err   error
	panic bool
}

func (e statefulTestExecutor) Execute(_ context.Context, _ string, opts attack.Options) ([]attack.Finding, error) {
	opts.TargetState.Record(attack.TargetObject{Kind: "oauth_client", ID: "client-1", Cleanup: attack.CleanupUnavailable})
	if e.panic {
		panic("test panic")
	}
	return nil, e.err
}

func TestRunOneRetainsTargetObjectsOnIncompleteRules(t *testing.T) {
	for _, tt := range []struct {
		name     string
		executor statefulTestExecutor
	}{
		{"inconclusive", statefulTestExecutor{err: attack.ErrInconclusive}},
		{"error", statefulTestExecutor{err: errors.New("probe failed")}},
		{"panic", statefulTestExecutor{panic: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := New(attack.Options{}).runOne(t.Context(), "https://agent.example", planEntry{
				rule: &rules.Rule{ID: "test-rule"}, executor: tt.executor,
			}, attack.NewBlackboard())
			if len(result.TargetObjects) != 1 || result.TargetObjects[0].ID != "client-1" {
				t.Fatalf("target state was lost: %+v", result)
			}
			if !result.Skipped && result.Err == nil {
				t.Fatalf("incomplete result was clean: %+v", result)
			}
		})
	}
}
