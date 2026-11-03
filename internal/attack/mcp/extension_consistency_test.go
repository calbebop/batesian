package mcp_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

type extensionFixture struct {
	mu      sync.Mutex
	mode    string
	methods []string
	appsCap bool
}

func (f *extensionFixture) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	meta, _ := req.Params["_meta"].(map[string]interface{})
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" || r.Header.Get("Mcp-Method") != req.Method ||
		meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		http.Error(w, "bad MCP headers", http.StatusBadRequest)
		return
	}
	if (req.Method == "resources/read" || req.Method == "skills/get") && r.Header.Get("Mcp-Name") != req.Params["uri"] {
		http.Error(w, "bad MCP name", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	f.mu.Unlock()
	if req.Method == "tools/list" || req.Method == "resources/read" {
		caps, _ := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]interface{})
		extensions, _ := caps["extensions"].(map[string]interface{})
		ui, _ := extensions["io.modelcontextprotocol/ui"].(map[string]interface{})
		mimeTypes, _ := ui["mimeTypes"].([]interface{})
		f.appsCap = len(mimeTypes) == 1 && mimeTypes[0] == "text/html;profile=mcp-app"
	}
	respond := func(value interface{}, code int) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if code == 0 {
			body["result"] = value
		} else {
			body["error"] = map[string]interface{}{"code": code, "message": "unknown resource"}
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	skillURI := "skill://demo/SKILL.md"
	uiURI := "ui://demo/view"
	if f.mode == "app-scheme" {
		uiURI = "https://example.test/view"
	}
	skillText := "---\nname: demo\ndescription: Example\n---\n"
	digest := sha256.Sum256([]byte(skillText))
	declaredDigest := "sha256:" + hex.EncodeToString(digest[:])
	if f.mode == "skill-mismatch" || f.mode == "skill-changing" || f.mode == "skill-stale-after-read" {
		declaredDigest = "sha256:" + strings.Repeat("0", 64)
	}
	if f.mode == "skill-changing" && req.Method == "skills/get" {
		declaredDigest = "sha256:" + hex.EncodeToString(digest[:])
	}
	if f.mode == "skill-stale-after-read" && req.Method == "skills/get" {
		f.mu.Lock()
		gets := 0
		for _, method := range f.methods {
			if method == "skills/get" {
				gets++
			}
		}
		f.mu.Unlock()
		if gets > 1 {
			declaredDigest = "sha256:" + hex.EncodeToString(digest[:])
		}
	}
	skill := map[string]interface{}{
		"uri":         skillURI,
		"frontmatter": map[string]string{"name": "demo", "description": "Example"},
		"resources":   []map[string]interface{}{{"uri": skillURI, "digest": declaredDigest, "size": len(skillText)}},
	}
	switch req.Method {
	case "server/discover":
		caps := map[string]interface{}{"tools": map[string]interface{}{}, "resources": map[string]interface{}{}}
		if strings.HasPrefix(f.mode, "skill-") {
			caps["extensions"] = map[string]interface{}{"io.modelcontextprotocol/skills": map[string]interface{}{}}
		}
		if f.mode == "skill-no-resources" {
			delete(caps, "resources")
		}
		respond(map[string]interface{}{"resultType": "complete", "supportedVersions": []string{"2026-07-28"}, "capabilities": caps}, 0)
	case "skills/list":
		if f.mode == "skill-app-empty" {
			respond(map[string]interface{}{"resultType": "complete", "skills": []interface{}{}}, 0)
			return
		}
		respond(map[string]interface{}{"resultType": "complete", "skills": []interface{}{skill}}, 0)
	case "skills/get":
		if f.mode == "skill-get-missing" {
			respond(nil, -32601)
			return
		}
		respond(map[string]interface{}{"resultType": "complete", "skill": skill}, 0)
	case "tools/list":
		tools := []interface{}{}
		if (strings.HasPrefix(f.mode, "app-") || f.mode == "skill-app-empty") && f.appsCap {
			tools = append(tools, map[string]interface{}{"name": "show", "_meta": map[string]interface{}{"ui": map[string]string{"resourceUri": uiURI}}})
		}
		respond(map[string]interface{}{"resultType": "complete", "tools": tools}, 0)
	case "resources/read":
		uri, _ := req.Params["uri"].(string)
		if uri == skillURI {
			respond(map[string]interface{}{"resultType": "complete", "contents": []map[string]string{{"uri": skillURI, "text": skillText}}}, 0)
			return
		}
		if uri != uiURI || f.mode == "app-missing" {
			respond(nil, -32602)
			return
		}
		mime := "text/html;profile=mcp-app"
		if f.mode == "app-mime" {
			mime = "text/html"
		}
		if f.mode == "app-uri" {
			uiURI = "ui://demo/other"
		}
		if f.mode == "app-flaky" {
			f.mu.Lock()
			reads := 0
			for _, method := range f.methods {
				if method == "resources/read" {
					reads++
				}
			}
			f.mu.Unlock()
			if reads == 1 {
				mime = "text/html"
			}
		}
		respond(map[string]interface{}{"resultType": "complete", "contents": []map[string]string{{"uri": uiURI, "mimeType": mime, "text": "<main>ok</main>"}}}, 0)
	default:
		respond(nil, -32601)
	}
}

func TestExtensionConsistency(t *testing.T) {
	for _, tc := range []struct {
		mode           string
		wantFinding    bool
		wantIncomplete bool
	}{
		{"skill-protected", false, false},
		{"skill-mismatch", true, false},
		{"skill-no-resources", true, false},
		{"skill-changing", false, false},
		{"skill-stale-after-read", false, true},
		{"skill-get-missing", false, true},
		{"skill-app-empty", false, true},
		{"app-protected", false, false},
		{"app-mime", true, false},
		{"app-missing", true, false},
		{"app-scheme", true, false},
		{"app-uri", true, false},
		{"app-flaky", false, false},
		{"empty", false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			fixture := &extensionFixture{mode: tc.mode}
			server := httptest.NewServer(http.HandlerFunc(fixture.serve))
			defer server.Close()
			executor := mcpattack.NewExtensionConsistencyExecutor(attack.RuleContext{
				ID: "mcp-extension-consistency-001", Name: "MCP extension resource consistency", Remediation: "Fix the resource.",
			})
			findings, err := executor.Execute(context.Background(), server.URL, attack.Options{})
			if (len(findings) > 0) != tc.wantFinding {
				t.Fatalf("findings = %+v, want finding %v; err = %v", findings, tc.wantFinding, err)
			}
			if errors.Is(err, attack.ErrInconclusive) != tc.wantIncomplete {
				t.Fatalf("inconclusive = %v, want %v; err = %v", errors.Is(err, attack.ErrInconclusive), tc.wantIncomplete, err)
			}
			if strings.HasPrefix(tc.mode, "app-") && !fixture.appsCap {
				t.Fatal("Apps client capability was not advertised")
			}
			for _, method := range fixture.methods {
				if method == "tools/call" || method == "resources/list" {
					t.Fatalf("unexpected method %q", method)
				}
			}
			for _, finding := range findings {
				if strings.Contains(finding.Evidence, "skill://") || strings.Contains(finding.Evidence, "ui://") || strings.Contains(finding.Evidence, "<main>") {
					t.Fatalf("resource content or URI leaked in evidence: %q", finding.Evidence)
				}
			}
		})
	}
}
