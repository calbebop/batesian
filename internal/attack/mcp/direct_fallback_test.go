package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func directFallbackServer(method, mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var req struct {
			ID     interface{} `json:"id"`
			Method string      `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			w.WriteHeader(http.StatusBadRequest)
			return
		case "server/discover":
			w.WriteHeader(http.StatusUnauthorized)
			return
		case method:
			if mode == "protected401" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mode == "protected403" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		default:
			if req.Method != "resources/read" || method != "resources/list" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		result := map[string]interface{}{}
		if req.Method == "resources/read" {
			result["contents"] = []map[string]string{{"uri": "public://guide", "text": "Public guide"}}
		} else if method == "tools/list" {
			result["tools"] = []map[string]string{{"name": "public_search"}}
		} else {
			result["resources"] = []map[string]string{{"uri": "public://guide", "name": "Guide"}}
		}
		if mode == "modern" {
			result["resultType"] = "complete"
			result["ttlMs"] = 0
			result["cacheScope"] = "public"
		} else if mode == "malformed" {
			result["resultType"] = "complete"
			result["ttlMs"] = "not-an-integer"
			result["cacheScope"] = "public"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		})
	}))
}

func TestDirectModernFallback_Tools(t *testing.T) {
	for _, mode := range []string{"modern", "generic", "malformed", "protected401", "protected403"} {
		t.Run(mode, func(t *testing.T) {
			ts := directFallbackServer("tools/list", mode)
			defer ts.Close()
			exec := mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"})
			opts := testOpts()
			opts.Token = "operator-token"
			findings, err := exec.Execute(context.Background(), ts.URL, opts)
			if mode == "modern" {
				if err != nil || len(findings) != 1 || findings[0].Severity != "info" ||
					findings[0].Confidence != attack.RiskIndicator ||
					!strings.Contains(findings[0].Evidence, "2026-07-28") {
					t.Fatalf("direct modern tools: findings=%+v err=%v", findings, err)
				}
			} else if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unverified direct tools should be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestDirectModernFallback_Resources(t *testing.T) {
	for _, mode := range []string{"modern", "generic", "malformed", "protected401", "protected403"} {
		t.Run(mode, func(t *testing.T) {
			ts := directFallbackServer("resources/list", mode)
			defer ts.Close()
			exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
			opts := testOpts()
			opts.Token = "operator-token"
			findings, err := exec.Execute(context.Background(), ts.URL, opts)
			if mode == "modern" {
				if err != nil || len(findings) != 2 {
					t.Fatalf("direct modern resources: findings=%+v err=%v", findings, err)
				}
				for _, finding := range findings {
					if finding.Severity != "info" || finding.Confidence != attack.RiskIndicator ||
						!strings.Contains(finding.Evidence, "2026-07-28") {
						t.Errorf("public resource overstated: %+v", finding)
					}
				}
			} else if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unverified direct resources should be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestDirectModernFallback_ExplicitEndpointStaysNarrow(t *testing.T) {
	var childModernCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     interface{} `json:"id"`
			Method string      `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.HasPrefix(r.URL.Path, "/mcp/") &&
			(req.Method == "tools/list" || (req.Method == "server/discover" && req.ID == "batesian-discover")) {
			childModernCalls.Add(1)
		}
		switch req.Method {
		case "initialize":
			w.WriteHeader(http.StatusBadRequest)
		case "server/discover":
			w.WriteHeader(http.StatusUnauthorized)
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"resultType": "complete", "ttlMs": 0, "cacheScope": "public",
					"tools": []map[string]string{{"name": "public_search"}},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	findings, err := mcpattack.NewToolsUnauthExecutor(attack.RuleContext{ID: "mcp-tools-unauth-001"}).
		Execute(t.Context(), ts.URL+"/mcp", testOpts())
	if err != nil || len(findings) != 1 || childModernCalls.Load() != 0 || findings[0].TargetURL != ts.URL+"/mcp" {
		t.Fatalf("explicit endpoint: findings=%+v err=%v child modern calls=%d", findings, err, childModernCalls.Load())
	}
}

func TestPublicCatalogFindingOutputs(t *testing.T) {
	ts := directFallbackServer("tools/list", "modern")
	defer ts.Close()
	rc := attack.RuleContext{ID: "mcp-tools-unauth-001", Name: "Public tool catalog",
		Remediation: "Protect the catalog if it is intended to be private."}
	findings, err := mcpattack.NewToolsUnauthExecutor(rc).Execute(t.Context(), ts.URL, testOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("catalog probe: findings=%+v err=%v", findings, err)
	}
	rule := &rules.Rule{ID: rc.ID}
	rule.Info.Name = rc.Name
	rule.Info.Severity = "info"
	results := []engine.RunResult{{Rule: rule, Findings: findings}}

	var jsonOut bytes.Buffer
	if err := report.New(&jsonOut, false).PrintJSON(map[string]interface{}{"findings": findings}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonOut.String(), `"Severity": "info"`) ||
		!strings.Contains(jsonOut.String(), `"Confidence": "indicator"`) ||
		!strings.Contains(jsonOut.String(), rc.Remediation) {
		t.Fatalf("JSON lost the finding grade or remediation: %s", jsonOut.String())
	}

	var sarif bytes.Buffer
	if err := report.WriteSARIF(&sarif, results, "test", ts.URL); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]interface{} `json:"properties"`
				Message    struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 ||
		doc.Runs[0].Results[0].Properties["severity"] != "info" ||
		doc.Runs[0].Results[0].Properties["confidence"] != "indicator" ||
		!strings.Contains(doc.Runs[0].Results[0].Message.Text, rc.Remediation) {
		t.Fatalf("SARIF lost the finding grade or remediation: %s", sarif.String())
	}

	var table bytes.Buffer
	if err := report.New(&table, true).PrintScanSummary(results); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[indicator]", "evidence:", "2026-07-28", "remediation:", rc.Remediation} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table lacks %q: %s", want, table.String())
		}
	}
}
