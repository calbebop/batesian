package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func traversalRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-tool-param-traversal-001",
		Name:        "MCP Tool Path Traversal",
		Severity:    "high",
		Remediation: "Resolve the joined path and verify containment before opening.",
	}
}

// traversalServer answers the MCP handshake and serves one tool set. The
// readTool behaviour decides what a tools/call for it reports back.
type traversalServer struct {
	caps  map[string]interface{}
	tools []map[string]interface{}
	list  func(http.ResponseWriter, json.Number, map[string]interface{})
	call  func(name string, args map[string]interface{}) (resultText string, isError bool, errMessage string)
	reply func(http.ResponseWriter, json.Number, map[string]interface{})
}

func (s *traversalServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Method string                 `json:"method"`
			ID     json.Number            `json:"id"`
			Params map[string]interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-traversal")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    s.caps,
					"serverInfo":      map[string]interface{}{"name": "traversal-fixture", "version": "1"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if s.list != nil {
				s.list(w, body.ID, body.Params)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]interface{}{"tools": s.tools},
			})
		case "tools/call":
			params := body.Params
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]interface{})
			if s.reply != nil {
				s.reply(w, body.ID, args)
				return
			}
			text, isErr, errMsg := s.call(name, args)
			if errMsg != "" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": body.ID,
					"error": map[string]interface{}{"code": -32000, "message": errMsg},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]interface{}{
					"content": []map[string]interface{}{{"type": "text", "text": text}},
					"isError": isErr,
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}
}

const (
	// sandboxRoot stands in for the tool's intended root directory.
	sandboxRoot = "/srv/notes"

	// leakTemplate is how a resolving server discloses its lookup: resolved
	// absolute path, dot-dot segments gone.
	leakTemplate = "ENOENT: no such file or directory, open '<PATH>'"
)

// joinLikeNaive mimics filepath.Join(root, p) followed by an OS resolution:
// an absolute caller path discards the root entirely, a relative one stays
// under whatever remains after the climb.
func joinLikeNaive(p string) string {
	if strings.HasPrefix(p, "/") {
		return collapseDotDot("/" + strings.TrimLeft(p, "/"))
	}
	return collapseDotDot(sandboxRoot + "/" + p)
}

// collapseDotDot resolves leading ../ segments against a POSIX tree.
func collapseDotDot(p string) string {
	parts := strings.Split(p, "/")
	var out []string
	for _, part := range parts {
		if part == ".." {
			if len(out) > 1 { // never climb above /
				out = out[:len(out)-1]
			}
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, "/")
}

func runTraversal(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	findings, err := mcp.NewToolParamTraversalExecutor(traversalRC()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"read_note", "echo_note_path"}})
	return findings, err
}

func readOnlySchemaTool(name string) map[string]interface{} {
	return map[string]interface{}{
		"name": name,
		"annotations": map[string]interface{}{
			"readOnlyHint": true,
		},
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string"},
			},
			"required": []interface{}{"path"},
		},
	}
}

// TestTraversal_VulnerableFires: a naive join that resolves outside the root
// and leaks where it looked. MUST fire confirmed/high from the resolution
// evidence alone - no file content was ever returned.
func TestTraversal_VulnerableFires(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			p, _ := args["path"].(string)
			resolved := joinLikeNaive(p)
			return strings.ReplaceAll(leakTemplate, "<PATH>", resolved), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, sandboxRoot) {
		t.Errorf("evidence should name the baseline root, got: %q", f.Evidence)
	}
}

func TestTraversal_ProbesEachPathParameter(t *testing.T) {
	tool := readOnlySchemaTool("read_note")
	schema := tool["inputSchema"].(map[string]interface{})
	schema["properties"] = map[string]interface{}{
		"a_path": map[string]interface{}{"type": "string"},
		"z_path": map[string]interface{}{"type": "string"},
	}
	schema["required"] = []interface{}{"a_path", "z_path"}
	var mu sync.Mutex
	var probed []string
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{tool},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			param := "a_path"
			path, _ := args[param].(string)
			if path == "" {
				param = "z_path"
				path, _ = args[param].(string)
			}
			mu.Lock()
			probed = append(probed, param)
			mu.Unlock()
			if param == "a_path" {
				if strings.Contains(path, "..") {
					return "rejected", true, ""
				}
				return strings.ReplaceAll(leakTemplate, "<PATH>", sandboxRoot+"/"+path), true, ""
			}
			return strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path)), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Evidence, "parameter: z_path") {
		t.Fatalf("second path parameter was missed: findings=%+v err=%v", findings, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(probed) != 9 {
		t.Fatalf("unexpected probe count: %v", probed)
	}
	for i, param := range probed {
		if (i < 7 && param != "a_path") || (i >= 7 && param != "z_path") {
			t.Fatalf("path parameters were not probed in name order: %v", probed)
		}
	}
}

func TestTraversal_MultiplePathsRespectCap(t *testing.T) {
	tool := readOnlySchemaTool("read_note")
	schema := tool["inputSchema"].(map[string]interface{})
	props := map[string]interface{}{}
	for i := range 9 {
		props[fmt.Sprintf("path_%d", i)] = map[string]interface{}{"type": "string"}
	}
	schema["properties"] = props
	schema["required"] = []interface{}{}
	var calls atomic.Int32
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{tool},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			calls.Add(1)
			for _, value := range args {
				path, _ := value.(string)
				return strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path)), true, ""
			}
			return "", true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil || len(findings) != 8 || calls.Load() != 16 {
		t.Fatalf("parameter cap changed: findings=%d calls=%d err=%v", len(findings), calls.Load(), err)
	}
}

func TestTraversal_PaginatedToolDiscovery(t *testing.T) {
	noPath := readOnlySchemaTool("noop")
	noPath["inputSchema"].(map[string]interface{})["properties"] = map[string]interface{}{
		"message": map[string]interface{}{"type": "string"},
	}
	noPath["inputSchema"].(map[string]interface{})["required"] = []interface{}{"message"}
	tests := []struct {
		name      string
		mode      string
		wantCalls bool
	}{
		{"later-page tool", "", true},
		{"empty cursor", "empty-cursor", true},
		{"repeated cursor", "loop", false},
		{"failed page", "fail", false},
		{"uncorrelated page", "bad-id", false},
		{"later-page approval", "unapproved", false},
		{"duplicate name", "duplicate", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var listCalls, toolCalls atomic.Int32
			srv := &traversalServer{
				caps: map[string]interface{}{"tools": map[string]interface{}{}},
				list: func(w http.ResponseWriter, id json.Number, params map[string]interface{}) {
					listCalls.Add(1)
					cursor, paged := params["cursor"]
					wantCursor := "next"
					if tc.mode == "empty-cursor" {
						wantCursor = ""
					}
					if paged && cursor != wantCursor {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if paged && tc.mode == "fail" {
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					result := map[string]interface{}{}
					if !paged {
						first := noPath
						if tc.mode == "loop" || tc.mode == "fail" || tc.mode == "duplicate" {
							first = readOnlySchemaTool("read_note")
						}
						result["tools"] = []interface{}{first}
						result["nextCursor"] = wantCursor
					} else {
						tool := readOnlySchemaTool("read_note")
						if tc.mode == "unapproved" {
							tool = readOnlySchemaTool("delete_note")
						}
						if tc.mode == "duplicate" {
							tool["annotations"] = map[string]interface{}{"readOnlyHint": false}
						}
						result["tools"] = []interface{}{tool}
						if tc.mode == "loop" {
							result["nextCursor"] = wantCursor
						}
						if tc.mode == "bad-id" {
							id = "999"
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
				},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					toolCalls.Add(1)
					path, _ := args["path"].(string)
					return strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path)), true, ""
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			findings, err := runTraversal(t, ts)
			if listCalls.Load() != 2 {
				t.Fatalf("tools/list calls: got %d, want 2", listCalls.Load())
			}
			if tc.wantCalls {
				if err != nil || len(findings) != 1 || toolCalls.Load() < 2 {
					t.Fatalf("later-page tool was missed: findings=%+v calls=%d err=%v", findings, toolCalls.Load(), err)
				}
			} else if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || toolCalls.Load() != 0 {
				t.Fatalf("incomplete or ambiguous listing invoked a tool: findings=%+v calls=%d err=%v", findings, toolCalls.Load(), err)
			}
			if tc.mode == "unapproved" && !strings.Contains(err.Error(), "delete_note") {
				t.Fatalf("later-page tool did not require exact approval: %v", err)
			}
		})
	}
}

func TestTraversal_PaginationKeepsToolCap(t *testing.T) {
	var toolCalls atomic.Int32
	tools := make([]map[string]interface{}, 9)
	approved := make([]string, len(tools))
	for i := range tools {
		approved[i] = fmt.Sprintf("read_note_%d", i)
		tools[i] = readOnlySchemaTool(approved[i])
	}
	srv := &traversalServer{
		caps: map[string]interface{}{"tools": map[string]interface{}{}},
		list: func(w http.ResponseWriter, id json.Number, params map[string]interface{}) {
			result := map[string]interface{}{"tools": tools[:4], "nextCursor": "next"}
			if params["cursor"] == "next" {
				result = map[string]interface{}{"tools": tools[4:]}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
		},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			toolCalls.Add(1)
			path, _ := args["path"].(string)
			return strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path)), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := mcp.NewToolParamTraversalExecutor(traversalRC()).Execute(
		t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: approved})
	if err != nil || len(findings) != 8 || toolCalls.Load() != 16 {
		t.Fatalf("tool cap changed: findings=%d calls=%d err=%v", len(findings), toolCalls.Load(), err)
	}
}

func TestTraversal_JSONRPCErrorCanDiscloseResolvedPath(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			path, _ := args["path"].(string)
			return "", false, strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path))
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil || len(findings) != 1 {
		t.Fatalf("resolved path in JSON-RPC error was missed: findings=%+v err=%v", findings, err)
	}
}

func modernTraversalCase(t *testing.T, mismatchStatus int, mismatchAt int32, firstResultType string, paged bool) ([]attack.Finding, int32, error) {
	t.Helper()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params struct {
				Arguments map[string]interface{} `json:"arguments"`
				Cursor    *string                `json:"cursor"`
			} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var result map[string]interface{}
		switch req.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		case "server/discover":
			result = map[string]interface{}{
				"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
				"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
			}
		case "tools/list":
			if paged && req.Params.Cursor == nil {
				noop := readOnlySchemaTool("noop")
				schema := noop["inputSchema"].(map[string]interface{})
				schema["properties"] = map[string]interface{}{"message": map[string]interface{}{"type": "string"}}
				schema["required"] = []interface{}{"message"}
				result = map[string]interface{}{"resultType": "complete", "tools": []interface{}{noop}, "nextCursor": "next"}
				break
			}
			if paged && *req.Params.Cursor != "next" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			tool := readOnlySchemaTool("read_note")
			schema := tool["inputSchema"].(map[string]interface{})
			props := schema["properties"].(map[string]interface{})
			props["path"].(map[string]interface{})["x-mcp-header"] = "Path"
			result = map[string]interface{}{"resultType": "complete", "tools": []interface{}{tool}}
		case "tools/call":
			callNumber := calls.Add(1)
			if mismatchStatus != 0 && callNumber == mismatchAt {
				w.WriteHeader(mismatchStatus)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
				})
				return
			}
			path, _ := req.Params.Arguments["path"].(string)
			if path == "" || r.Header.Get("Mcp-Param-Path") != path {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
				})
				return
			}
			text := strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path))
			result = map[string]interface{}{"resultType": "complete", "content": []interface{}{
				map[string]interface{}{"type": "text", "text": text},
			}}
			if callNumber == 1 && firstResultType != "" {
				result["resultType"] = firstResultType
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	return findings, calls.Load(), err
}

func TestTraversal_ModernMirrorsAnnotatedPath(t *testing.T) {
	findings, calls, err := modernTraversalCase(t, 0, 0, "", false)
	if err != nil || len(findings) != 1 || calls < 2 {
		t.Fatalf("annotated path tool was not assessed: findings=%+v calls=%d err=%v", findings, calls, err)
	}
}

func TestTraversal_ModernDiscoversLaterPage(t *testing.T) {
	findings, calls, err := modernTraversalCase(t, 0, 0, "", true)
	if err != nil || len(findings) != 1 || calls < 2 {
		t.Fatalf("later-page annotated path tool was missed: findings=%+v calls=%d err=%v", findings, calls, err)
	}
}

func TestTraversal_HeaderMismatchIsInconclusive(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		for _, rejectAt := range []int32{1, 2} {
			t.Run(fmt.Sprintf("%d/call-%d", status, rejectAt), func(t *testing.T) {
				findings, calls, err := modernTraversalCase(t, status, rejectAt, "", false)
				if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
					!strings.Contains(err.Error(), "HeaderMismatch") || calls != rejectAt {
					t.Fatalf("mismatch must stop without retry: findings=%+v calls=%d err=%v", findings, calls, err)
				}
			})
		}
	}
}

func TestTraversal_ModernIncompleteResultIsInconclusive(t *testing.T) {
	findings, calls, err := modernTraversalCase(t, 0, 0, "input_required", false)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls != 1 {
		t.Fatalf("incomplete result must stop the probe: findings=%+v calls=%d err=%v", findings, calls, err)
	}
}

func TestTraversal_UnusableToolRepliesAreInconclusive(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   func(json.Number, string) interface{}
		raw    string
	}{
		{"HTTP error", http.StatusInternalServerError, func(id json.Number, path string) interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "text", "text": strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path))}},
			}}
		}, ""},
		{"wrong ID", http.StatusOK, func(id json.Number, path string) interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": 999, "result": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "text", "text": strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path))}},
			}}
		}, ""},
		{"missing envelope", http.StatusOK, func(id json.Number, path string) interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id}
		}, ""},
		{"missing version", http.StatusOK, func(id json.Number, path string) interface{} {
			return map[string]interface{}{"id": id, "result": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "text", "text": "refused"}},
			}}
		}, ""},
		{"no text", http.StatusOK, func(id json.Number, path string) interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{"type": "image", "data": "AAAA"}},
			}}
		}, ""},
		{"malformed JSON", http.StatusOK, nil, "{"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
				reply: func(w http.ResponseWriter, id json.Number, args map[string]interface{}) {
					path, _ := args["path"].(string)
					if calls.Add(1) == 1 {
						_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
							"content": []interface{}{map[string]interface{}{"type": "text", "text": strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(path))}},
						}})
						return
					}
					w.WriteHeader(tc.status)
					if tc.raw != "" {
						_, _ = w.Write([]byte(tc.raw))
						return
					}
					_ = json.NewEncoder(w).Encode(tc.body(id, path))
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			findings, err := runTraversal(t, ts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 2 {
				t.Fatalf("unusable reply must stop the probe: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
			}
		})
	}
}

func TestTraversal_UnresolvedBaselineIsInconclusive(t *testing.T) {
	tests := []struct {
		name string
		text func(string) string
	}{
		{"generic refusal", func(string) string { return "rejected: path escapes the notes directory" }},
		{"echo", func(path string) string { return "no note found at " + path }},
		{"relative lookup", func(path string) string { return "../" + path }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					calls.Add(1)
					path, _ := args["path"].(string)
					return tc.text(path), true, ""
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			findings, err := runTraversal(t, ts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "baseline") || calls.Load() != 1 {
				t.Fatalf("unresolved baseline must stop the probe: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
			}
		})
	}
}

// TestTraversal_UnannotatedSkipped: the vulnerable tool exists but carries no
// annotations, so the safety gate refuses to dispatch it even though the bug
// is real. The rule reports clean rather than executing an unknown tool; the
// trade-off is documented in the rule catalog rather than hidden.
func TestTraversal_UnannotatedSkipped(t *testing.T) {
	vulnerable := readOnlySchemaTool("read_note")
	delete(vulnerable, "annotations")
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{vulnerable},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			p, _ := args["path"].(string)
			return strings.ReplaceAll(leakTemplate, "<PATH>", joinLikeNaive(p)), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings: unannotated tools must not be dispatched, got %d: %+v", len(findings), findings)
	}
}

func TestTraversal_NonDestructiveWriteToolIsNotCalled(t *testing.T) {
	tool := readOnlySchemaTool("create_note")
	tool["annotations"] = map[string]interface{}{
		"readOnlyHint":    false,
		"destructiveHint": false,
	}
	var calls atomic.Int32
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{tool},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			calls.Add(1)
			return "created", false, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := mcp.NewToolParamTraversalExecutor(traversalRC()).Execute(
		t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"create_note"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when no explicitly read-only tool exists, got %d", len(findings))
	}
	if calls.Load() != 0 {
		t.Fatalf("non-read-only tool was called %d times", calls.Load())
	}
}

func TestTraversal_RequiresExactToolApproval(t *testing.T) {
	var calls atomic.Int32
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("delete_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			calls.Add(1)
			return "deleted", false, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	exec := mcp.NewToolParamTraversalExecutor(traversalRC())
	for _, approved := range [][]string{nil, {"other_tool"}} {
		findings, err := exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: approved})
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "delete_note") {
			t.Fatalf("approval %v: findings=%+v err=%v", approved, findings, err)
		}
		if calls.Load() != 0 {
			t.Fatalf("tool was called without exact approval: %d", calls.Load())
		}
	}
	_, err := exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"delete_note"}})
	if !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 1 {
		t.Fatalf("exact approval did not enable the probe: calls=%d err=%v", calls.Load(), err)
	}
}

// TestTraversal_NoToolsCapability: the server does not advertise tools at all.
// Nothing to probe, determined clean.
func TestTraversal_NoToolsCapability(t *testing.T) {
	srv := &traversalServer{caps: map[string]interface{}{}}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on a server without tools, got %d", len(findings))
	}
}

// TestTraversal_ContainedClimbStaysSilent: the server clamps the climb so both
// lookups land under the same root. Containment held; MUST stay silent.
func TestTraversal_ContainedClimbStaysSilent(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			p, _ := args["path"].(string)
			// Clamp at the root regardless of how far the input climbs.
			resolved := sandboxRoot + "/" + strings.TrimLeft(p, "/.")
			return strings.ReplaceAll(leakTemplate, "<PATH>", resolved), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when the sandbox contains the climb, got %d: %+v", len(findings), findings)
	}
}

// TestTraversal_EncodedOnlyFires: a server that rejects literal traversal
// up front but decodes the input before joining escapes only through the
// percent-encoded payloads. The pre-expansion probe set read this server
// clean; the expansion exists to catch exactly it.
func TestTraversal_EncodedOnlyFires(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			p, _ := args["path"].(string)
			if !strings.Contains(p, "%") && strings.Contains(p, "..") {
				// Literal dot-dot is rejected before anything else happens.
				return "rejected: path contains traversal segments", true, ""
			}
			decoded, err := url.PathUnescape(p)
			if err == nil {
				p = decoded
			}
			resolved := joinLikeNaive(p)
			return strings.ReplaceAll(leakTemplate, "<PATH>", resolved), true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "URL-encoded") {
		t.Errorf("expected the URL-encoded payload to be the one that escaped, got: %q", findings[0].Evidence)
	}
}
