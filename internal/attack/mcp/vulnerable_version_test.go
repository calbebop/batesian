package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
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

// TestVV_VulnerableGitFires: the reference git server reports an affected package release.
func TestVV_VulnerableGitFires(t *testing.T) {
	ts := vvServer("mcp-git", "2026.10.19")
	defer ts.Close()

	findings, err := runVV(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
		t.Errorf("want medium/RiskIndicator, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "GHSA-w766-5x43-whvw") {
		t.Errorf("evidence should cite the advisories, got: %q", f.Evidence)
	}
}

// TestVV_PatchedSilent: same product at the patched version.
func TestVV_PatchedSilent(t *testing.T) {
	ts := vvServer("mcp-git", "2026.10.28")
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
	ts := vvServer("serena", "not-a-version")
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
		{"serena at bound excluded", "serena", "1.5.2", 0},
		{"serena just below fires", "serena", "1.5.1", 1},
		{"git at lower bound fires", "mcp-git", "2026.10.10", 1},
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

func TestVV_ExcludedAndPartialIdentities(t *testing.T) {
	for _, tc := range []struct{ name, version string }{
		{"mcp-server-git", "2025.12.17"},
		{"mcp-remote", "0.1.15"},
		{"mcp-atlassian", "0.16.9"},
		{"inspector", "0.14.0"},
		{"mcpjam", "1.4.2"},
		{"custom-mcp-git", "2026.10.19"},
		{"mcp-git-proxy", "2026.10.19"},
		{"custom-serena", "1.5.1"},
		{"mcp-inspector-proxy", "0.14.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := vvServer(tc.name, tc.version)
			defer ts.Close()
			findings, err := runVV(t, ts)
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestVV_OmitsReportedVersionSuffix(t *testing.T) {
	const private = "private-canary"
	for _, tc := range []struct {
		name, product, version, want string
	}{
		{"build suffix", "mcp-git", "2026.10.19+" + private, "2026.10.19"},
		{"prerelease suffix", "serena", "1.5.2-rc." + private, "1.5.2 (prerelease)"},
		{"unparseable", "serena", private, "unparseable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := vvServer(tc.product, tc.version)
			defer ts.Close()
			findings, err := runVV(t, ts)
			if err != nil || len(findings) != 1 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			report, err := json.Marshal(findings)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(report), private) || !strings.Contains(findings[0].Evidence, tc.want) {
				t.Fatalf("reported version leaked or normalized value missing: %s", report)
			}
		})
	}
}

func TestVV_ReferenceServerAdvisoryRanges(t *testing.T) {
	cases := []struct {
		name, version string
		refs          []string
	}{
		{"secure-filesystem-server", "2025.8.20", nil},
		{"secure-filesystem-server", "2025.8.21", nil},
		{"secure-filesystem-server", "2026.8.31", nil},
		{"secure-filesystem-server", "2026.9.1", nil},
		{"secure-filesystem-server", "0.2.0", nil},
		{"secure-filesystem-server", "0.9.0", nil},
		{"secure-filesystem-server", "1.0.0", []string{"GHSA-7rgq-gccq-qphx", "GHSA-hhwq-wxfx-cj7g", "GHSA-4gxg-m5jx-9j57", "GHSA-53mr-w429-c597"}},
		{"secure-filesystem-server", "2.0.0", []string{"GHSA-7rgq-gccq-qphx", "GHSA-hhwq-wxfx-cj7g", "GHSA-4gxg-m5jx-9j57", "GHSA-53mr-w429-c597"}},
		{"secure-filesystem-server", "2.0.1-rc.1", []string{"GHSA-7rgq-gccq-qphx", "GHSA-hhwq-wxfx-cj7g", "GHSA-4gxg-m5jx-9j57", "GHSA-53mr-w429-c597"}},
		{"secure-filesystem-server", "2.0.1", nil},
		{"proxy-secure-filesystem-server", "2.0.0", nil},
		{"mcp-git", "2026.10.9", nil},
		{"mcp-git", "2026.10.10", []string{"GHSA-w766-5x43-whvw"}},
		{"mcp-git", "2026.10.19", []string{"GHSA-w766-5x43-whvw"}},
		{"MCP-GIT", "2026.10.19", []string{"GHSA-w766-5x43-whvw"}},
		{"mcp-git", "2026.10.28-rc.1", []string{"GHSA-w766-5x43-whvw"}},
		{"mcp-git", "2026.10.28", nil},
		{"custom-mcp-git", "2026.10.19", nil},
		{"mcp-fetch", "0.6.0", nil},
		{"mcp-fetch", "0.6.1", nil},
		{"mcp-fetch", "2026.10.9", nil},
		{"mcp-fetch", "2026.10.10", []string{"GHSA-v38p-wf49-hx2j", "GHSA-3jqg-r5pp-rmp2", "GHSA-66qx-2266-pmj6"}},
		{"mcp-fetch", "2026.10.19", []string{"GHSA-v38p-wf49-hx2j", "GHSA-3jqg-r5pp-rmp2", "GHSA-66qx-2266-pmj6"}},
		{"mcp-fetch", "2026.10.20", nil},
		{"mcp-fetch", "2026.10.24", nil},
		{"custom-mcp-fetch", "2026.10.19", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.version, func(t *testing.T) {
			ts := vvServer(tc.name, tc.version)
			defer ts.Close()
			findings, err := runVV(t, ts)
			if err != nil || len(findings) != len(tc.refs) {
				t.Fatalf("findings=%+v err=%v, want %v", findings, err, tc.refs)
			}
			for i, ref := range tc.refs {
				if !strings.Contains(findings[i].Evidence, ref) || findings[i].Confidence != attack.RiskIndicator {
					t.Fatalf("finding[%d]=%+v, want %s indicator", i, findings[i], ref)
				}
				if strings.HasPrefix(ref, "GHSA-") {
					severity := "medium"
					fixed := "2026.10.24"
					if tc.name == "secure-filesystem-server" {
						fixed = "2.0.1"
					}
					if strings.EqualFold(tc.name, "mcp-git") {
						fixed = "2026.10.28"
					}
					if ref == "GHSA-3jqg-r5pp-rmp2" || ref == "GHSA-66qx-2266-pmj6" ||
						ref == "GHSA-hhwq-wxfx-cj7g" || ref == "GHSA-53mr-w429-c597" {
						severity = "low"
					}
					if findings[i].Severity != severity || !strings.Contains(findings[i].Remediation, fixed) {
						t.Fatalf("finding[%d]=%+v, want %s severity and %s fix", i, findings[i], severity, fixed)
					}
				}
			}
		})
	}
}

func TestVV_UnrecognizedVersionSuffixIsUnverifiable(t *testing.T) {
	ts := vvServer("secure-filesystem-server", "2.0.1rc1")
	defer ts.Close()
	findings, err := runVV(t, ts)
	if err != nil || len(findings) != 4 || findings[0].Severity != "low" ||
		!strings.Contains(findings[0].Evidence, "GHSA-7rgq-gccq-qphx") ||
		!strings.Contains(findings[1].Evidence, "GHSA-hhwq-wxfx-cj7g") ||
		!strings.Contains(findings[2].Evidence, "GHSA-4gxg-m5jx-9j57") ||
		!strings.Contains(findings[3].Evidence, "GHSA-53mr-w429-c597") {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}

// TestVV_ModernWireMeta: on the modern wire the identity travels under
// result._meta rather than result.serverInfo; the extractor reads both.
func TestVV_ModernWireMeta(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     interface{} `json:"id"`
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

func TestVV_UsesSuppliedTokenForReadOnlyInventory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modern bool
	}{
		{name: "legacy"},
		{name: "modern", modern: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer inventory-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				var req struct {
					Method string      `json:"method"`
					ID     interface{} `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req.Method {
				case "initialize":
					if tc.modern {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID,
						"result": map[string]interface{}{
							"protocolVersion": "2025-06-18",
							"serverInfo":      map[string]interface{}{"name": "mcp-git", "version": "2026.10.19"},
							"capabilities":    map[string]interface{}{},
						},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "server/discover":
					if !tc.modern {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID,
						"result": map[string]interface{}{
							"supportedVersions": []string{"2026-07-28"},
							"_meta": map[string]interface{}{
								"io.modelcontextprotocol/serverInfo": map[string]interface{}{
									"name": "mcp-git", "version": "2026.10.19",
								},
							},
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()
			exec := mcp.NewVulnerableVersionExecutor(vvRC())
			findings, err := exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, Token: "inventory-token"})
			if err != nil || len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator {
				t.Fatalf("authenticated inventory: findings=%+v err=%v", findings, err)
			}
			findings, err = exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("anonymous inventory should be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}
