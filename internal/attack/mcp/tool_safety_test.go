package mcp

import "testing"

func boolPtr(v bool) *bool { return &v }

func TestDeclaresReadOnlyTool(t *testing.T) {
	tests := []struct {
		name        string
		readOnly    *bool
		destructive *bool
		want        bool
	}{
		{"no annotations", nil, nil, false},
		{"read-only absent and non-destructive", nil, boolPtr(false), false},
		{"non-read-only and non-destructive", boolPtr(false), boolPtr(false), false},
		{"explicitly read-only", boolPtr(true), nil, true},
		{"read-only and non-destructive", boolPtr(true), boolPtr(false), true},
		{"contradictory read-only and destructive", boolPtr(true), boolPtr(true), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := declaresReadOnlyTool(tc.readOnly, tc.destructive); got != tc.want {
				t.Fatalf("declaresReadOnlyTool() = %v, want %v", got, tc.want)
			}
		})
	}
}
