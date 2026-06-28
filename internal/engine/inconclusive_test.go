package engine_test

import (
	"strings"
	"testing"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// TestRun_UnreachableA2ARuleIsInconclusive verifies that an A2A rule run against
// an unreachable target is recorded as a skipped/inconclusive result (the
// executor returned attack.ErrInconclusive), not as a clean pass or an error.
func TestRun_UnreachableA2ARuleIsInconclusive(t *testing.T) {
	loaded, _, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	var r *rules.Rule
	for _, x := range loaded {
		if x.ID == "a2a-peer-impersonation-001" {
			r = x
			break
		}
	}
	if r == nil {
		t.Skip("a2a-peer-impersonation-001 not present")
	}

	res := engine.New(attack.Options{TimeoutSeconds: 1}).Run(t.Context(), "http://127.0.0.1:1", []*rules.Rule{r})[0]
	if !res.Skipped || !strings.Contains(res.SkipMsg, "could not reach") {
		t.Errorf("expected inconclusive skip, got skipped=%v msg=%q err=%v findings=%d",
			res.Skipped, res.SkipMsg, res.Err, len(res.Findings))
	}
}
