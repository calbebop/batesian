package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func vvRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-vulnerable-version-001",
		Name:        "MCP Known-Vulnerable Component",
		Severity:    "high",
		Remediation: "Upgrade the component past the patched version.",
	}
}

// vvServer serves an initialize whose serverInfo carries the given name and
// version, verbatim.
func vvServer(name, version string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "initialize" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]interface{}{"name": name, "version": version},
			},
		})
	}))
}

func runVV(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewVulnerableVersionExecutor(vvRC()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
}

// TestVV_VulnerableGitFires: the reference git server one patch behind. MUST
// fire a high indicator naming the advisory set.
func TestVV_VulnerableGitFires(t *testing.T) {
	ts := vvServer("mcp-server-git", "2025.12.17")
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.RiskIndicator {
		t.Errorf("want high/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "CVE-2025-68143") {
		t.Errorf("evidence should cite the advisories, got: %q", f.Evidence)
	}
}

// TestVV_PatchedSilent: same product at the patched version. MUST stay
// silent.
func TestVV_PatchedSilent(t *testing.T) {
	ts := vvServer("mcp-server-git", "2025.12.18")
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings at the patched version, got %d: %+v", len(findings), findings)
	}
}

// TestVV_UnknownProductSilent: an unrelated identity matches nothing in the
// closed table.
func TestVV_UnknownProductSilent(t *testing.T) {
	ts := vvServer("my-custom-mcp-server", "1.0.0")
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for an unknown product, got %d: %+v", len(findings), findings)
	}
}

// TestVV_UnparseableVersionLow: name matches a table entry but the version is
// not parseable, so neither clean nor vulnerable can be claimed - low
// indicator instead of silence.
func TestVV_UnparseableVersionLow(t *testing.T) {
	ts := vvServer("mcp-remote", "not-a-version")
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "low" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want low/RiskIndicator for unverifiable version, got %q/%q",
			findings[0].Severity, findings[0].Confidence)
	}
}

// TestVV_Boundaries: the range edges behave - equal-to-bound is not affected
// under "<", but is under "<=".
func TestVV_Boundaries(t *testing.T) {
	cases := []struct {
		label   string
		product string
		version string
		want    int
	}{
		{"inspector at bound excluded", "mcp-inspector-proxy", "0.14.1", 0},
		{"inspector just below fires", "mcp-inspector-proxy", "0.14.0", 1},
		{"mcpjam inclusive bound fires", "mcpjam-inspector", "1.4.2", 1},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			ts := vvServer(tc.product, tc.version)
			defer ts.Close()

			findings, err := runVV(t, ts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tc.want {
				t.Fatalf("version %q: want %d findings, got %d: %+v",
					tc.version, tc.want, len(findings), findings)
			}
		})
	}
}

// TestVV_ModernWireMeta: on the modern wire the identity travels under
// result._meta rather than result.serverInfo; the extractor reads both.
func TestVV_ModernWireMeta(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "initialize" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				// A modern discover result must advertise the revision to be
				// taken as a modern wire at all.
				"supportedVersions": []string{"2026-07-28"},
				"_meta": map[string]interface{}{
					"io.modelcontextprotocol/serverInfo": map[string]interface{}{
						"name": "serena", "version": "1.5.1",
					},
				},
			},
		})
	}))
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding from _meta identity, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "CVE-2026-49471") {
		t.Errorf("evidence should cite the Serena advisory, got: %q", findings[0].Evidence)
	}
}
