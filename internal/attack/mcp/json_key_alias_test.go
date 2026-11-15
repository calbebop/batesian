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
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func keyAliasRule() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-json-key-alias-001", Name: "MCP JSON-RPC Method Key Alias",
		Severity: "low", Remediation: "Require exact JSON-RPC method keys.",
	}
}

func keyAliasServer(t *testing.T, modern bool, acceptedKey, variantReply string) (*httptest.Server, *[]string) {
	t.Helper()
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		method, _ := body["method"].(string)
		key := "method"
		if method == "" {
			for _, alias := range []string{"Method", "method\x00"} {
				if value, ok := body[alias].(string); ok {
					method, key = value, alias
					break
				}
			}
		}
		methods = append(methods, key+":"+method)
		w.Header().Set("Content-Type", "application/json")
		answer := func(result map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"], "result": result,
			})
		}
		switch method {
		case "initialize":
			if modern {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			answer(map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]interface{}{"name": "key-alias-fixture", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "server/discover":
			if !modern {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			answer(map[string]interface{}{
				"supportedVersions": []string{"2026-07-28"},
				"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
				"cacheScope":        "private", "resultType": "complete", "ttlMs": 0,
			})
		case "tools/list":
			if key == "method" && variantReply == "canonical-error" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": body["id"],
					"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
				})
				return
			}
			if key != "method" && key != acceptedKey && variantReply == "other-ambiguous" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": 999,
					"result": map[string]interface{}{"tools": []interface{}{}},
				})
				return
			}
			if key != "method" && (key != acceptedKey || variantReply == "discard") {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			if key != "method" {
				switch variantReply {
				case "unrelated":
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 999,
						"result": map[string]interface{}{"tools": []interface{}{}},
					})
					return
				case "error":
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 999,
						"error": map[string]interface{}{"code": -32600, "message": "Invalid Request"},
					})
					return
				case "matched-error", "param-error":
					code := -32600
					if variantReply == "param-error" {
						code = -32602
					}
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": body["id"],
						"error": map[string]interface{}{"code": code, "message": "Rejected"},
					})
					return
				}
			}
			answer(map[string]interface{}{
				"tools":      []interface{}{map[string]interface{}{"name": "fixture-secret"}},
				"cacheScope": "private", "resultType": "complete", "ttlMs": 0,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, &methods
}

func TestJSONKeyAliasFindingsOnBothWires(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, alias := range []string{"Method", "method\x00"} {
			t.Run(alias, func(t *testing.T) {
				srv, methods := keyAliasServer(t, modern, alias, "list")
				defer srv.Close()
				findings, err := mcpattack.NewJSONKeyAliasExecutor(keyAliasRule()).Execute(context.Background(), srv.URL, testOpts())
				if err != nil || len(findings) != 1 {
					t.Fatalf("modern=%v alias=%q: findings=%+v err=%v", modern, alias, findings, err)
				}
				if findings[0].Confidence != attack.RiskIndicator || findings[0].Severity != "low" ||
					strings.Contains(findings[0].Evidence, "fixture-secret") || strings.Contains(findings[0].Description, "fixture-secret") {
					t.Fatalf("unsafe or misrated finding: %+v", findings[0])
				}
				if modern && !strings.Contains(findings[0].Title, "2026-07-28 wire") {
					t.Fatalf("modern wire not labeled: %+v", findings[0])
				}
				if len(*methods) < 3 || (*methods)[len(*methods)-3] != "method:tools/list" {
					t.Fatalf("missing canonical baseline: %v", *methods)
				}
				for _, called := range *methods {
					if strings.Contains(called, "tools/call") {
						t.Fatalf("rule invoked a tool: %v", *methods)
					}
				}
			})
		}
	}
}

func TestJSONKeyAliasRejectedAndAmbiguousResponses(t *testing.T) {
	for _, tc := range []struct {
		reply        string
		inconclusive bool
	}{
		{"discard", false},
		{"matched-error", false},
		{"unrelated", true},
		{"error", true},
		{"param-error", true},
		{"canonical-error", true},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			srv, _ := keyAliasServer(t, false, "Method", tc.reply)
			defer srv.Close()
			findings, err := mcpattack.NewJSONKeyAliasExecutor(keyAliasRule()).Execute(t.Context(), srv.URL, testOpts())
			if len(findings) != 0 || (errors.Is(err, attack.ErrInconclusive) != tc.inconclusive) {
				t.Fatalf("reply=%q: findings=%+v err=%v", tc.reply, findings, err)
			}
		})
	}
}

func TestJSONKeyAliasFindingSurvivesAmbiguousOtherVariant(t *testing.T) {
	srv, _ := keyAliasServer(t, false, "Method", "other-ambiguous")
	defer srv.Close()
	findings, err := mcpattack.NewJSONKeyAliasExecutor(keyAliasRule()).Execute(t.Context(), srv.URL, testOpts())
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("partial verdict: findings=%+v err=%v", findings, err)
	}
}
