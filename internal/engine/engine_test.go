package engine_test

import (
	"testing"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// TestAllBundledRulesResolve loads every YAML rule shipped with the binary and
// asserts that each attack.type maps to a registered executor.  This prevents
// a rule from being added to the rules/ directory without a matching entry in
// engine.resolveExecutor.
func TestAllBundledRulesResolve(t *testing.T) {
	loaded, warns, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	for _, w := range warns {
		t.Logf("warning: skipped malformed rule %s: %v", w.Path, w.Err)
	}
	if len(loaded) == 0 {
		t.Fatal("no rules loaded from embedded FS; embed directive may be broken")
	}

	eng := engine.New(attack.Options{TimeoutSeconds: 1})
	for _, r := range loaded {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			// Run against an unreachable target; we only care that the executor
			// resolves, not that it finds anything.
			results := eng.Run(t.Context(), "http://127.0.0.1:1", []*rules.Rule{r})
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			res := results[0]
			if res.Skipped {
				t.Errorf("rule %q was skipped (%s) — add its attack.type to engine.resolveExecutor", r.ID, res.SkipMsg)
			}
		})
	}
}
