package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/rules"
)

type lifecycleExecutor func(context.Context, attack.Options) ([]attack.Finding, error)

var cacheLifetimeSink func(*attack.DiscoveryCache)
var budgetExecutor lifecycleExecutor

func init() {
	attack.Register("test-engine-cache-lifetime", func(attack.RuleContext) attack.Executor {
		return lifecycleExecutor(func(_ context.Context, opts attack.Options) ([]attack.Finding, error) {
			cacheLifetimeSink(opts.Discovery)
			return nil, nil
		})
	})
	attack.Register("test-engine-budget", func(attack.RuleContext) attack.Executor {
		return budgetExecutor
	})
}

func TestRunWithBudgetPreservesPartialCoverage(t *testing.T) {
	called := 0
	budgetExecutor = func(ctx context.Context, opts attack.Options) ([]attack.Finding, error) {
		called++
		if called == 1 {
			return []attack.Finding{{RuleID: "first", Evidence: "confirmed"}}, nil
		}
		if called == 2 {
			opts.TargetState.Record(attack.TargetObject{Kind: "test_object", ID: "created", Cleanup: attack.CleanupNotAttempted})
			<-ctx.Done()
			return []attack.Finding{{RuleID: "second", Evidence: "earlier subcheck"}}, ctx.Err()
		}
		t.Fatal("rule started after budget expired")
		return nil, nil
	}
	defer func() { budgetExecutor = nil }()
	ruleset := []*rules.Rule{
		{ID: "first", Attack: rules.AttackBlock{Type: "test-engine-budget"}},
		{ID: "second", Attack: rules.AttackBlock{Type: "test-engine-budget"}},
		{ID: "third", Attack: rules.AttackBlock{Type: "test-engine-budget"}},
	}
	start := time.Now()
	results := New(attack.Options{}).RunWithBudget(t.Context(), "https://agent.example", ruleset, 30*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("budget did not stop rule execution: %v", elapsed)
	}
	if called != 2 || len(results) != 3 || results[0].Skipped || len(results[0].Findings) != 1 {
		t.Fatalf("completed rule lost: calls=%d results=%+v", called, results)
	}
	if !results[1].BudgetExceeded || !results[1].Skipped || len(results[1].Findings) != 1 || len(results[1].TargetObjects) != 1 ||
		!strings.Contains(results[1].SkipMsg, "during rule") {
		t.Fatalf("partial rule lost: %+v", results[1])
	}
	if !results[2].BudgetExceeded || !results[2].Skipped || len(results[2].Findings) != 0 ||
		!strings.Contains(results[2].SkipMsg, "before rule started") {
		t.Fatalf("unstarted rule not reported: %+v", results[2])
	}
}

func TestRunWithBudgetDoesNotMislabelParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	budgetExecutor = func(ctx context.Context, _ attack.Options) ([]attack.Finding, error) {
		cancel()
		return nil, ctx.Err()
	}
	defer func() { budgetExecutor = nil }()
	rule := &rules.Rule{ID: "cancelled", Attack: rules.AttackBlock{Type: "test-engine-budget"}}
	results := New(attack.Options{}).RunWithBudget(ctx, "https://agent.example", []*rules.Rule{rule, rule}, time.Minute)
	if len(results) != 2 || results[0].BudgetExceeded || results[1].BudgetExceeded || !results[1].Skipped {
		t.Fatalf("parent cancellation marked as budget: %+v", results)
	}
}

func (f lifecycleExecutor) Execute(ctx context.Context, _ string, opts attack.Options) ([]attack.Finding, error) {
	return f(ctx, opts)
}

func TestRunOneKeepsPartialFindings(t *testing.T) {
	executor := lifecycleExecutor(func(context.Context, attack.Options) ([]attack.Finding, error) {
		return []attack.Finding{{RuleID: "r", Severity: "high", Confidence: attack.ConfirmedExploit, Evidence: "access observed"}},
			fmt.Errorf("%w: later comparison unavailable", attack.ErrInconclusive)
	})
	result := New(attack.Options{}).runOne(t.Context(), "https://agent.example", planEntry{
		rule: &rules.Rule{ID: "r"}, executor: executor,
	}, attack.NewBlackboard())
	if !result.Skipped || result.Err != nil || !strings.Contains(result.SkipMsg, "later comparison unavailable") {
		t.Fatalf("incomplete outcome lost: %+v", result)
	}
	if len(result.Findings) != 1 || result.Findings[0].Confidence != attack.ConfirmedExploit {
		t.Fatalf("completed subcheck finding lost: %+v", result.Findings)
	}
}

func TestRunOneNotCleanWhenCancelledDuringExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	executor := lifecycleExecutor(func(context.Context, attack.Options) ([]attack.Finding, error) {
		cancel()
		return []attack.Finding{{RuleID: "r", Evidence: "earlier check succeeded"}}, nil
	})
	result := New(attack.Options{}).runOne(ctx, "https://agent.example", planEntry{
		rule: &rules.Rule{ID: "r"}, executor: executor,
	}, attack.NewBlackboard())
	if !result.Skipped || result.Err != nil || !strings.Contains(result.SkipMsg, "context canceled") || len(result.Findings) != 1 {
		t.Fatalf("cancelled rule looked clean: %+v", result)
	}
}

func TestEngineCopiesMutableOptions(t *testing.T) {
	opts := attack.Options{
		OAuthOrigins:   []string{"https://auth.example"},
		MCPScopeTools:  []string{"lookup"},
		MCPInvokeTools: []string{"research"},
		Principals:     []attack.Principal{{Name: "owner", Headers: map[string]string{"X-Tenant": "A"}}},
	}
	engine := New(opts)
	opts.OAuthOrigins[0] = "https://changed.example"
	opts.MCPScopeTools[0] = "changed"
	opts.MCPInvokeTools[0] = "changed"
	opts.Principals[0].Headers["X-Tenant"] = "B"

	check := func(_ context.Context, got attack.Options) ([]attack.Finding, error) {
		if got.OAuthOrigins[0] != "https://auth.example" || got.MCPScopeTools[0] != "lookup" ||
			got.MCPInvokeTools[0] != "research" || got.Principals[0].Headers["X-Tenant"] != "A" {
			return nil, errors.New("options changed across rules")
		}
		got.OAuthOrigins[0] = "https://mutated.example"
		got.MCPScopeTools[0] = "mutated"
		got.MCPInvokeTools[0] = "mutated"
		got.Principals[0].Headers["X-Tenant"] = "C"
		return nil, nil
	}
	entry := planEntry{rule: &rules.Rule{ID: "r"}, executor: lifecycleExecutor(check)}
	for i := 0; i < 2; i++ {
		if result := engine.runOne(t.Context(), "https://agent.example", entry, attack.NewBlackboard()); result.Err != nil {
			t.Fatalf("run %d: %v", i, result.Err)
		}
	}
}

func TestEngineDiscoveryCacheLifetime(t *testing.T) {
	var seen []*attack.DiscoveryCache
	cacheLifetimeSink = func(cache *attack.DiscoveryCache) { seen = append(seen, cache) }
	defer func() { cacheLifetimeSink = nil }()
	rule := &rules.Rule{ID: "r", Attack: rules.AttackBlock{Type: "test-engine-cache-lifetime"}}
	engine := New(attack.Options{})
	engine.Run(t.Context(), "https://agent.example", []*rules.Rule{rule, rule})
	engine.Run(t.Context(), "https://agent.example", []*rules.Rule{rule})
	if len(seen) != 3 || seen[0] == nil || seen[0] != seen[1] || seen[0] == seen[2] {
		t.Fatalf("default discovery cache must be shared within one run, not across runs: %v", seen)
	}

	shared := attack.NewDiscoveryCache()
	engine = New(attack.Options{Discovery: shared})
	engine.Run(t.Context(), "https://agent.example", []*rules.Rule{rule})
	engine.Run(t.Context(), "https://agent.example", []*rules.Rule{rule})
	if len(seen) != 5 || seen[3] != shared || seen[4] != shared {
		t.Fatalf("caller-supplied discovery cache was replaced: %v", seen)
	}
}
