package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	call  func(name string, args map[string]interface{}) (resultText string, isError bool, errMessage string)
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
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body.ID,
				"result": map[string]interface{}{"tools": s.tools},
			})
		case "tools/call":
			params := body.Params
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]interface{})
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
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
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

// TestTraversal_PatchedStaysSilent: the server validates containment and
// refuses without echoing any path. MUST stay silent.
func TestTraversal_PatchedStaysSilent(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("read_note")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			return "rejected: path escapes the notes directory", true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against containment validation, got %d: %+v", len(findings), findings)
	}
}

// TestTraversal_EchoOnlyStaysSilent: a chatty tool echoes the caller's input,
// dot-dot segments intact, without resolving anything. An echo is not
// resolution evidence; reporting it would accuse any tool that repeats what it
// was sent. MUST stay silent.
func TestTraversal_EchoOnlyStaysSilent(t *testing.T) {
	srv := &traversalServer{
		caps:  map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{readOnlySchemaTool("echo_note_path")},
		call: func(name string, args map[string]interface{}) (string, bool, string) {
			p, _ := args["path"].(string)
			return "no note found at " + p, true, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runTraversal(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against an echoing (non-resolving) tool, got %d: %+v", len(findings), findings)
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
