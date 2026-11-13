package mcp_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

type skillResourcesFixture struct {
	mu    sync.Mutex
	mode  string
	reads []string
	gets  int
}

func skillRecord(uri, content string) map[string]interface{} {
	digest := sha256.Sum256([]byte(content))
	return map[string]interface{}{
		"uri": uri, "size": len(content), "digest": "sha256:" + hex.EncodeToString(digest[:]),
	}
}

func (f *skillResourcesFixture) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" || r.Header.Get("Mcp-Method") != req.Method {
		http.Error(w, "invalid MCP headers", http.StatusBadRequest)
		return
	}
	if req.Method == "resources/read" || req.Method == "skills/get" {
		if r.Header.Get("Mcp-Name") != req.Params["uri"] {
			http.Error(w, "invalid MCP name", http.StatusBadRequest)
			return
		}
	}
	respond := func(result interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	const root = "skill://demo/"
	const skillURI = root + "SKILL.md"
	const supportURI = root + "references/guide.md"
	const skillText = "---\nname: demo\ndescription: Example\n---\n"
	const supportText = "Reference material"
	manifest := []map[string]interface{}{skillRecord(skillURI, skillText), skillRecord(supportURI, supportText)}
	if f.mode == "entry-cap" {
		manifest = manifest[:1]
		for i := range 8 {
			manifest = append(manifest, skillRecord(fmt.Sprintf("%sreferences/%d.md", root, i), supportText))
		}
	}
	if f.mode == "declared-cap" {
		manifest[1]["size"] = (1 << 20) + 1
	}
	if f.mode == "manifest-cap" {
		manifest[1]["size"] = (16 << 20) + 1
	}
	if f.mode == "duplicate" {
		manifest = append(manifest, skillRecord(supportURI, supportText))
	}
	gets := 0
	if req.Method == "skills/get" {
		f.mu.Lock()
		f.gets++
		gets = f.gets
		f.mu.Unlock()
		if f.mode == "changed" && gets > 1 {
			manifest[1] = skillRecord(supportURI, "changed")
		}
	}
	frontmatter := map[string]string{"name": "demo", "description": "Example"}
	if f.mode == "frontmatter-changed" && gets > 1 {
		frontmatter["description"] = "Updated example"
	}
	skill := map[string]interface{}{
		"uri": skillURI, "frontmatter": frontmatter,
		"resources": manifest,
	}
	switch req.Method {
	case "server/discover":
		respond(map[string]interface{}{
			"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": map[string]interface{}{
				"resources":  map[string]interface{}{},
				"extensions": map[string]interface{}{"io.modelcontextprotocol/skills": map[string]interface{}{}},
			},
		})
	case "skills/list":
		result := map[string]interface{}{"resultType": "complete", "skills": []interface{}{skill}}
		if f.mode == "paged" {
			result["nextCursor"] = "next"
		}
		respond(result)
	case "skills/get":
		respond(map[string]interface{}{"resultType": "complete", "skill": skill})
	case "resources/read":
		uri, _ := req.Params["uri"].(string)
		f.mu.Lock()
		f.reads = append(f.reads, uri)
		reads := len(f.reads)
		f.mu.Unlock()
		content := supportText
		if uri == skillURI {
			content = skillText
		} else if f.mode == "mismatch" || f.mode == "changed" || f.mode == "frontmatter-changed" || f.mode == "transient" && reads == 2 {
			content = "changed"
		} else if f.mode == "actual-cap" {
			content = strings.Repeat("x", (1<<20)+1)
		} else if f.mode == "wire-cap" {
			content = strings.Repeat("x", 2<<20)
		}
		item := map[string]interface{}{"uri": uri, "text": content}
		if uri == supportURI && f.mode == "blob" {
			item = map[string]interface{}{"uri": uri, "blob": base64.StdEncoding.EncodeToString([]byte(content))}
		}
		respond(map[string]interface{}{"resultType": "complete", "contents": []interface{}{item}})
	default:
		http.Error(w, "unknown method", http.StatusBadRequest)
	}
}

func TestExtensionConsistencySkillResources(t *testing.T) {
	for _, tc := range []struct {
		mode           string
		wantFinding    bool
		wantIncomplete bool
		wantReads      int
	}{
		{"valid", false, false, 2},
		{"blob", false, false, 2},
		{"mismatch", true, false, 3},
		{"transient", false, false, 3},
		{"changed", false, true, 2},
		{"frontmatter-changed", false, true, 2},
		{"entry-cap", false, true, 8},
		{"declared-cap", false, true, 1},
		{"manifest-cap", false, true, 0},
		{"actual-cap", false, true, 2},
		{"wire-cap", false, true, 2},
		{"duplicate", false, true, 0},
		{"paged", false, true, 2},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			fixture := &skillResourcesFixture{mode: tc.mode}
			server := httptest.NewServer(http.HandlerFunc(fixture.serve))
			defer server.Close()
			executor := mcpattack.NewExtensionConsistencyExecutor(attack.RuleContext{
				ID: "mcp-extension-consistency-001", Name: "MCP extension resource consistency",
			})
			findings, err := executor.Execute(context.Background(), server.URL, attack.Options{})
			if (len(findings) > 0) != tc.wantFinding {
				t.Fatalf("findings = %+v, want finding %v; err = %v", findings, tc.wantFinding, err)
			}
			if errors.Is(err, attack.ErrInconclusive) != tc.wantIncomplete {
				t.Fatalf("inconclusive = %v, want %v; err = %v", errors.Is(err, attack.ErrInconclusive), tc.wantIncomplete, err)
			}
			if len(fixture.reads) != tc.wantReads {
				t.Fatalf("resources/read calls = %d, want %d", len(fixture.reads), tc.wantReads)
			}
			for _, finding := range findings {
				if strings.Contains(finding.Evidence, "skill://") || strings.Contains(finding.Evidence, "changed") {
					t.Fatalf("resource URI or content leaked in evidence: %q", finding.Evidence)
				}
			}
		})
	}
}
