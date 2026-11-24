package attack

import "testing"

func TestNewVarsPreservesExplicitPath(t *testing.T) {
	vars := NewVars("https://example.test/mcp/", "")
	if vars.BaseURL != "https://example.test/mcp/" {
		t.Fatalf("target path = %q, want trailing slash", vars.BaseURL)
	}
	if got := vars.Expand("{{BaseURL}}/register"); got != "https://example.test/mcp/register" {
		t.Fatalf("expanded URL = %q, want one separator", got)
	}
}
