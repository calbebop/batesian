package a2a_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func TestPushLifecycle(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantFindings int
		inconclusive bool
	}{
		{mode: "lifecycle-bound"},
		{mode: "lifecycle-list-open", wantFindings: 1},
		{mode: "lifecycle-paged-open", wantFindings: 1},
		{mode: "lifecycle-delete-open", wantFindings: 1},
		{mode: "lifecycle-open", wantFindings: 2},
		{mode: "lifecycle-legacy-open", wantFindings: 2},
		{mode: "lifecycle-shared", inconclusive: true},
		{mode: "lifecycle-list-wrong-id", inconclusive: true},
		{mode: "lifecycle-list-malformed", inconclusive: true},
		{mode: "lifecycle-list-loop", inconclusive: true},
		{mode: "lifecycle-delete-noop", inconclusive: true},
		{mode: "lifecycle-delete-wrong-id", inconclusive: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ts := pushServer(tc.mode)
			defer ts.Close()
			state := &attack.TargetState{}
			findings, err := a2a.NewPushLifecycleExecutor(testRuleCtx()).Execute(t.Context(), ts.URL,
				attack.Options{TimeoutSeconds: 5, Principals: pushPrincipals(), TargetState: state})
			if len(findings) != tc.wantFindings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(err != nil && !tc.inconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			objects := pushConfigObjects(state.Snapshot())
			if len(objects) != 1 || objects[0].Cleanup != attack.CleanupCompleted ||
				!strings.HasPrefix(objects[0].ID, "lifecycle-") {
				t.Fatalf("cleanup=%+v", objects)
			}
			for _, finding := range findings {
				if finding.Severity != "high" || finding.Confidence != attack.ConfirmedExploit ||
					!strings.Contains(finding.Evidence, "GetTask control: denied") ||
					!strings.Contains(finding.Evidence, "deleted") {
					t.Fatalf("finding=%+v", finding)
				}
			}
		})
	}
}

func TestPushLifecycleNeedsDistinctPrincipals(t *testing.T) {
	exec := a2a.NewPushLifecycleExecutor(testRuleCtx())
	findings, err := exec.Execute(t.Context(), "https://example.com", attack.Options{
		Principals: []attack.Principal{{Name: "owner", Token: "same"}, {Name: "other", Token: "same"}},
	})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}
