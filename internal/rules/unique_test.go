package rules

import (
	"strings"
	"testing"
)

func TestValidateUniqueIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want string
	}{
		{name: "empty"},
		{name: "distinct", ids: []string{"a2a-test-001", "mcp-test-001"}},
		{name: "exact", ids: []string{"a2a-test-001", "a2a-test-001"}, want: "duplicate rule ID"},
		{name: "case only", ids: []string{"a2a-test-001", "A2A-TEST-001"}, want: "duplicate rule ID"},
		{name: "selector whitespace", ids: []string{"a2a-test-001", " a2a-test-001 "}, want: "duplicate rule ID"},
		{name: "Unicode case fold", ids: []string{"Σ", "ς"}, want: "duplicate rule ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := make([]*Rule, 0, len(tc.ids))
			for _, id := range tc.ids {
				catalog = append(catalog, &Rule{ID: id})
			}
			err := ValidateUniqueIDs(catalog)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("ValidateUniqueIDs(%v) = %v, want %q", tc.ids, err, tc.want)
			}
		})
	}
}

func TestValidateUniqueIDsRejectsNilRule(t *testing.T) {
	if err := ValidateUniqueIDs([]*Rule{nil}); err == nil {
		t.Fatal("nil rule was accepted")
	}
}
