package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func filesystemSuffixRule() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-filesystem-suffix-001", Name: "MCP Filesystem Trailing-Character Boundary",
		Severity: "medium", Remediation: "Use the same canonical path for validation and access.",
	}
}

func TestFilesystemSuffixModernWire(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage        `json:"id"`
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		write := func(result interface{}, message string) {
			body := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
			if message == "" {
				body["result"] = result
			} else {
				body["error"] = map[string]interface{}{"code": -32602, "message": message}
			}
			_ = json.NewEncoder(w).Encode(body)
		}
		switch req.Method {
		case "initialize":
			write(nil, "Method not found")
		case "server/discover":
			write(map[string]interface{}{"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
				"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":   map[string]string{"name": "fixture", "version": "1"}}, "")
		case "tools/list":
			write(map[string]interface{}{"resultType": "complete", "tools": []interface{}{readOnlySchemaTool("get_file_info")}}, "")
		case "tools/call":
			calls.Add(1)
			args, _ := req.Params["arguments"].(map[string]interface{})
			p, _ := args["path"].(string)
			meta, _ := req.Params["_meta"].(map[string]interface{})
			if r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != "get_file_info" ||
				r.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
				write(nil, "invalid modern request")
				return
			}
			if strings.HasPrefix(p, "/srv/disposable/batesian-") || p == "/srv/disposable'" {
				write(nil, "ENOENT: no such file or directory, stat '"+p+"'")
				return
			}
			write(nil, "Access denied")
		default:
			write(nil, "Method not found")
		}
	}))
	defer ts.Close()
	findings, err := mcp.NewFilesystemSuffixExecutor(filesystemSuffixRule()).Execute(context.Background(), ts.URL,
		attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"get_file_info"},
			MCPFilesystemSuffixProbe: &attack.MCPFilesystemSuffixProbe{AllowedDirectory: "/srv/disposable"}})
	if err != nil || len(findings) != 1 || calls.Load() != 3 {
		t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
	}
}

func TestFilesystemSuffixBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, posture string
		finding       bool
		inconclusive  bool
	}{
		{"vulnerable", "vulnerable", true, false},
		{"tool result error", "tool-error", true, false},
		{"protected", "protected", false, false},
		{"outside control missing", "outside-missing", false, true},
		{"outside control success", "outside-success", false, true},
		{"success-shaped error", "success-shaped", false, true},
		{"ambiguous suffix", "ambiguous", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{readOnlySchemaTool("get_file_info")},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					calls.Add(1)
					if name != "get_file_info" || len(args) != 1 {
						t.Errorf("unexpected call: %s %v", name, args)
					}
					p, _ := args["path"].(string)
					if strings.HasPrefix(p, "/srv/disposable/batesian-") {
						if tc.posture == "tool-error" {
							return fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p), true, ""
						}
						return "", false, fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p)
					}
					if strings.HasPrefix(p, "/srv/disposable-batesian-") {
						if tc.posture == "outside-missing" {
							return "", false, fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p)
						}
						if tc.posture == "outside-success" {
							return "Access denied", false, ""
						}
						if tc.posture == "tool-error" {
							return "Access denied", true, ""
						}
						return "", false, "Access denied"
					}
					if p == "/srv/disposable'" && tc.posture == "tool-error" {
						return fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p), true, ""
					}
					if p == "/srv/disposable'" && tc.posture == "vulnerable" {
						return "", false, fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p)
					}
					if tc.posture == "success-shaped" || tc.posture == "ambiguous" {
						return fmt.Sprintf("ENOENT: no such file or directory, stat '%s'", p), false, ""
					}
					return "", false, "Access denied"
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()
			findings, err := mcp.NewFilesystemSuffixExecutor(filesystemSuffixRule()).Execute(
				context.Background(), ts.URL, attack.Options{
					TimeoutSeconds: 5, MCPInvokeTools: []string{"get_file_info"},
					MCPFilesystemSuffixProbe: &attack.MCPFilesystemSuffixProbe{AllowedDirectory: "/srv/disposable"},
				})
			if (len(findings) == 1) != tc.finding || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if calls.Load() < 2 || calls.Load() > 5 {
				t.Fatalf("tool calls=%d, want 2..5", calls.Load())
			}
			if tc.finding {
				f := findings[0]
				if f.Confidence != attack.RiskIndicator || f.Severity != "medium" ||
					strings.Contains(f.Evidence, "/srv/disposable") || strings.Contains(f.Description, "/srv/disposable") {
					t.Fatalf("finding=%+v", f)
				}
			}
		})
	}
}

func TestFilesystemSuffixRequiresApprovalAndSafeTool(t *testing.T) {
	for _, tc := range []struct {
		name     string
		approved bool
		tool     map[string]interface{}
	}{
		{"no approval", false, readOnlySchemaTool("get_file_info")},
		{"unannotated", true, map[string]interface{}{
			"name": "get_file_info", "inputSchema": readOnlySchemaTool("get_file_info")["inputSchema"],
		}},
		{"extra required argument", true, map[string]interface{}{
			"name": "get_file_info", "annotations": map[string]interface{}{"readOnlyHint": true},
			"inputSchema": map[string]interface{}{
				"type": "object", "properties": map[string]interface{}{
					"path": map[string]interface{}{"type": "string"}, "mode": map[string]interface{}{"type": "string"},
				}, "required": []interface{}{"path", "mode"},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{tc.tool},
				call: func(string, map[string]interface{}) (string, bool, string) {
					calls.Add(1)
					return "", false, "Access denied"
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()
			opts := attack.Options{TimeoutSeconds: 5,
				MCPFilesystemSuffixProbe: &attack.MCPFilesystemSuffixProbe{AllowedDirectory: "/srv/disposable"}}
			if tc.approved {
				opts.MCPInvokeTools = []string{"get_file_info"}
			}
			findings, err := mcp.NewFilesystemSuffixExecutor(filesystemSuffixRule()).Execute(context.Background(), ts.URL, opts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
				t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
			}
		})
	}
}
