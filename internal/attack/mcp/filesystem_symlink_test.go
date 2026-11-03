package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func filesystemSymlinkRule() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-filesystem-symlink-001", Name: "MCP Filesystem Symlink Metadata Exposure",
		Severity: "low", Remediation: "Validate child paths before following symlinks.",
	}
}

func filesystemSymlinkOptions() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		MCPInvokeTools: []string{"get_file_info", "list_directory_with_sizes"},
		MCPFilesystemSymlinkProbe: &attack.MCPFilesystemSymlinkProbe{
			AllowedDirectory: "/srv/disposable", LinkName: "outside-link",
			OutsidePath: "/srv/outside/fixture.bin", OutsideSizeBytes: 1536,
		},
	}
}

func filesystemSizeSchemaTool() map[string]interface{} {
	tool := readOnlySchemaTool("list_directory_with_sizes")
	schema := tool["inputSchema"].(map[string]interface{})
	props := schema["properties"].(map[string]interface{})
	props["sortBy"] = map[string]interface{}{"type": "string", "enum": []interface{}{"name", "size"}}
	return tool
}

func TestFilesystemSymlinkMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, listing, outsideReply, linkReply string
		finding, inconclusive                  bool
		calls                                  int32
	}{
		{"vulnerable", "[FILE] outside-link                    1.50 KB\n\n Total: 1 files", "Access denied", "Access denied", true, false, 4},
		{"protected", "[FILE] outside-link                         0 B", "Access denied", "Access denied", false, false, 4},
		{"other size", "[FILE] outside-link                    2.00 KB", "Access denied", "Access denied", false, false, 4},
		{"no link entry", "Total size: 1.50 KB", "Access denied", "Access denied", false, true, 4},
		{"duplicate entry", "[FILE] outside-link 1.50 KB\n[FILE] outside-link 1.50 KB", "Access denied", "Access denied", false, true, 4},
		{"malformed size", "[FILE] outside-link 1.50 unknown", "Access denied", "Access denied", false, true, 4},
		{"listing error", "[FILE] outside-link 1.50 KB", "Access denied", "Access denied", false, true, 4},
		{"inside denied", "[FILE] outside-link 1.50 KB", "Access denied", "Access denied", false, true, 1},
		{"outside not denied", "[FILE] outside-link 1.50 KB", "size: 1536", "Access denied", false, true, 2},
		{"link not denied", "[FILE] outside-link 1.50 KB", "Access denied", "size: 1536", false, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps: map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{
					readOnlySchemaTool("get_file_info"), filesystemSizeSchemaTool(),
				},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					calls.Add(1)
					p, _ := args["path"].(string)
					switch {
					case name == "get_file_info" && p == "/srv/disposable":
						if tc.name == "inside denied" {
							return "Access denied", true, ""
						}
						return "size: 0", false, ""
					case name == "get_file_info" && p == "/srv/outside/fixture.bin":
						return tc.outsideReply, true, ""
					case name == "get_file_info" && p == "/srv/disposable/outside-link":
						return tc.linkReply, true, ""
					case name == "list_directory_with_sizes" && p == "/srv/disposable":
						return tc.listing, tc.name == "listing error", ""
					default:
						t.Errorf("unexpected call: %s %v", name, args)
						return "", true, ""
					}
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()
			findings, err := mcp.NewFilesystemSymlinkExecutor(filesystemSymlinkRule()).Execute(
				context.Background(), ts.URL, filesystemSymlinkOptions())
			if (len(findings) == 1) != tc.finding || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				calls.Load() != tc.calls {
				t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
			}
			if tc.finding {
				f := findings[0]
				if f.Confidence != attack.RiskIndicator || f.Severity != "low" ||
					strings.Contains(f.Evidence, "/srv/") || strings.Contains(f.Evidence, "1536") ||
					strings.Contains(f.Description, "/srv/") {
					t.Fatalf("finding=%+v", f)
				}
			}
		})
	}
}

func TestFilesystemSymlinkNeedsApprovalAndSafeFixture(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*attack.Options)
	}{
		{"missing approval", func(o *attack.Options) { o.MCPInvokeTools = []string{"get_file_info"} }},
		{"outside inside root", func(o *attack.Options) { o.MCPFilesystemSymlinkProbe.OutsidePath = "/srv/disposable/fixture.bin" }},
		{"unsupported size", func(o *attack.Options) { o.MCPFilesystemSymlinkProbe.OutsideSizeBytes = 1537 }},
		{"path-shaped name", func(o *attack.Options) { o.MCPFilesystemSymlinkProbe.LinkName = "../outside" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := &traversalServer{
				caps: map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{
					readOnlySchemaTool("get_file_info"), filesystemSizeSchemaTool(),
				},
				call: func(string, map[string]interface{}) (string, bool, string) {
					calls.Add(1)
					return "", false, ""
				},
			}
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()
			opts := filesystemSymlinkOptions()
			tc.edit(&opts)
			findings, err := mcp.NewFilesystemSymlinkExecutor(filesystemSymlinkRule()).Execute(context.Background(), ts.URL, opts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
				t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
			}
		})
	}
}

func TestFilesystemSymlinkRejectsUnannotatedTool(t *testing.T) {
	var calls atomic.Int32
	unsafe := filesystemSizeSchemaTool()
	delete(unsafe, "annotations")
	srv := &traversalServer{
		caps: map[string]interface{}{"tools": map[string]interface{}{}},
		tools: []map[string]interface{}{
			readOnlySchemaTool("get_file_info"), unsafe,
		},
		call: func(string, map[string]interface{}) (string, bool, string) {
			calls.Add(1)
			return "", false, ""
		},
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	findings, err := mcp.NewFilesystemSymlinkExecutor(filesystemSymlinkRule()).Execute(context.Background(), ts.URL, filesystemSymlinkOptions())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
		t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
	}
}

func TestFilesystemSymlinkModernWire(t *testing.T) {
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
			write(map[string]interface{}{"resultType": "complete", "tools": []interface{}{
				readOnlySchemaTool("get_file_info"), filesystemSizeSchemaTool(),
			}}, "")
		case "tools/call":
			calls.Add(1)
			meta, _ := req.Params["_meta"].(map[string]interface{})
			name, _ := req.Params["name"].(string)
			if r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != name ||
				r.Header.Get("Mcp-Protocol-Version") != "2026-07-28" ||
				meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
				write(nil, "invalid modern request")
				return
			}
			if name == "get_file_info" {
				args, _ := req.Params["arguments"].(map[string]interface{})
				if args["path"] == "/srv/disposable" {
					write(map[string]interface{}{"resultType": "complete", "content": []interface{}{
						map[string]string{"type": "text", "text": "size: 0"},
					}}, "")
					return
				}
				write(nil, "Access denied")
				return
			}
			if name == "list_directory_with_sizes" {
				write(map[string]interface{}{"resultType": "complete", "content": []interface{}{
					map[string]string{"type": "text", "text": "[FILE] outside-link                    1.50 KB"},
				}}, "")
				return
			}
			write(nil, "unknown tool")
		default:
			write(nil, "Method not found")
		}
	}))
	defer ts.Close()
	findings, err := mcp.NewFilesystemSymlinkExecutor(filesystemSymlinkRule()).Execute(context.Background(), ts.URL, filesystemSymlinkOptions())
	if err != nil || len(findings) != 1 || calls.Load() != 4 {
		t.Fatalf("findings=%+v err=%v calls=%d", findings, err, calls.Load())
	}
}
