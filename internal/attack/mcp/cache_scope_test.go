package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

type cacheScopeFixture struct {
	mu    sync.Mutex
	mode  string
	calls map[string]int
}

func (f *cacheScopeFixture) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	respond := func(result interface{}, code int) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if code != 0 {
			body["error"] = map[string]interface{}{"code": code, "message": "rejected"}
		} else {
			body["result"] = result
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	meta, _ := req.Params["_meta"].(map[string]interface{})
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
		r.Header.Get("Mcp-Method") != req.Method ||
		meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		respond(nil, -32020)
		return
	}
	if req.Method == "resources/read" && r.Header.Get("Mcp-Name") != req.Params["uri"] {
		respond(nil, -32020)
		return
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if principal != "tok-a" && principal != "tok-b" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.mode == "denied" && principal == "tok-b" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	key := principal + ":" + req.Method
	f.calls[key]++
	call := f.calls[key]
	f.mu.Unlock()

	switch req.Method {
	case "server/discover":
		capabilities := map[string]interface{}{"tools": map[string]interface{}{}}
		if f.mode == "all" || strings.HasPrefix(f.mode, "resource-") {
			capabilities["prompts"] = map[string]interface{}{}
			capabilities["resources"] = map[string]interface{}{}
		}
		if f.mode == "discover" && principal == "tok-b" {
			capabilities["prompts"] = map[string]interface{}{}
		}
		respond(map[string]interface{}{
			"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": capabilities, "cacheScope": "public", "ttlMs": 60000,
		}, 0)
	case "tools/list":
		name := "private-" + principal
		if f.mode == "same" || strings.HasPrefix(f.mode, "resource-") {
			name = "shared"
		}
		if f.mode == "unstable" && principal == "tok-a" {
			name += string(rune('0' + call))
		}
		scope, ttl := "public", 60000
		if f.mode == "private" || f.mode == "mixed" && principal == "tok-b" {
			scope = "private"
		}
		if f.mode == "zero-ttl" {
			ttl = 0
		}
		if f.mode == "expired" {
			ttl = 1
			if principal == "tok-b" {
				time.Sleep(5 * time.Millisecond)
			}
		}
		tools := []map[string]string{{"name": name}}
		if f.mode == "order" {
			tools = []map[string]string{{"name": "first"}, {"name": "second"}}
			if principal == "tok-b" {
				tools[0], tools[1] = tools[1], tools[0]
			}
		}
		respond(map[string]interface{}{
			"resultType": "complete", "tools": tools,
			"cacheScope": scope, "ttlMs": ttl,
		}, 0)
	case "prompts/list", "resources/list", "resources/templates/list":
		if f.mode != "all" && !strings.HasPrefix(f.mode, "resource-") {
			respond(nil, -32601)
			return
		}
		field := map[string]string{
			"prompts/list":             "prompts",
			"resources/list":           "resources",
			"resources/templates/list": "resourceTemplates",
		}[req.Method]
		name := "private-" + principal
		if strings.HasPrefix(f.mode, "resource-") {
			name = "shared"
		}
		item := map[string]string{"name": name}
		if req.Method == "resources/list" {
			item["uri"] = "resource://" + principal
			if strings.HasPrefix(f.mode, "resource-") {
				item["uri"] = "resource://shared?token=private"
			}
		}
		if req.Method == "resources/templates/list" {
			item["uriTemplate"] = "resource://" + principal + "/{id}"
			if strings.HasPrefix(f.mode, "resource-") {
				item["uriTemplate"] = "resource://shared/{id}"
			}
		}
		items := []map[string]string{item}
		if f.mode == "resource-many" && req.Method == "resources/list" {
			items = nil
			for i := range 7 {
				items = append(items, map[string]string{"uri": "resource://shared/" + strconv.Itoa(i)})
			}
		}
		respond(map[string]interface{}{
			"resultType": "complete", field: items,
			"cacheScope": "public", "ttlMs": 60000,
		}, 0)
	case "resources/read":
		uri, _ := req.Params["uri"].(string)
		if !strings.HasPrefix(f.mode, "resource-") ||
			(f.mode != "resource-many" && uri != "resource://shared?token=private") ||
			(f.mode == "resource-many" && !strings.HasPrefix(uri, "resource://shared/")) {
			respond(nil, -32602)
			return
		}
		if f.mode == "resource-denied" && principal == "tok-b" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.mode == "resource-input" && principal == "tok-b" {
			respond(map[string]interface{}{"resultType": "input_required", "requestState": "opaque"}, 0)
			return
		}
		content := "secret-" + principal
		if f.mode == "resource-same" {
			content = "shared"
		}
		if f.mode == "resource-unstable" && principal == "tok-a" {
			content += string(rune('0' + call))
		}
		scope := "public"
		if f.mode == "resource-private" {
			scope = "private"
		}
		respond(map[string]interface{}{
			"resultType": "complete", "contents": []map[string]string{{
				"uri": uri, "text": content,
			}}, "cacheScope": scope, "ttlMs": 60000,
		}, 0)
	default:
		respond(nil, -32601)
	}
}

func runCacheScopeFixture(t *testing.T, mode string) ([]attack.Finding, *cacheScopeFixture, error) {
	t.Helper()
	fixture := &cacheScopeFixture{mode: mode}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	opts := testOpts()
	opts.Principals = []attack.Principal{
		{Name: "tenant-a", Token: "tok-a"},
		{Name: "tenant-b", Token: "tok-b"},
	}
	findings, err := mcpattack.NewCacheScopeExecutor(attack.RuleContext{
		ID: "mcp-cache-scope-001", Name: "MCP public cache scope", Remediation: "Use private scope.",
	}).Execute(context.Background(), server.URL, opts)
	return findings, fixture, err
}

func TestCacheScope_DifferingPublicResults(t *testing.T) {
	findings, fixture, err := runCacheScopeFixture(t, "public")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Confidence != attack.RiskIndicator || finding.Severity != "medium" ||
		!strings.Contains(finding.Evidence, "tools/list") ||
		strings.Contains(finding.Evidence, "private-tok") || strings.Contains(finding.Evidence, "tok-a") {
		t.Fatalf("incorrect or secret-bearing finding: %+v", finding)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls["tok-a:tools/list"] != 2 || fixture.calls["tok-b:tools/list"] != 2 {
		t.Fatalf("expected repeat controls, calls=%v", fixture.calls)
	}
}

func TestCacheScope_ProtectedControls(t *testing.T) {
	for _, mode := range []string{"private", "mixed", "same", "order", "zero-ttl", "expired"} {
		t.Run(mode, func(t *testing.T) {
			findings, _, err := runCacheScopeFixture(t, mode)
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestCacheScope_AllAdvertisedListings(t *testing.T) {
	findings, fixture, err := runCacheScopeFixture(t, "all")
	if err != nil || len(findings) != 4 {
		t.Fatalf("expected all four list methods, findings=%+v err=%v", findings, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls["tok-a:resources/read"] != 0 || fixture.calls["tok-b:resources/read"] != 0 {
		t.Fatalf("resources without a shared URI must not be read: %v", fixture.calls)
	}
}

func TestCacheScope_DiscoveryAndIncompleteControls(t *testing.T) {
	findings, _, err := runCacheScopeFixture(t, "discover")
	if err != nil || len(findings) != 2 {
		t.Fatalf("discovery and list findings=%+v err=%v", findings, err)
	}
	for _, mode := range []string{"unstable", "denied"} {
		t.Run(mode, func(t *testing.T) {
			findings, _, err := runCacheScopeFixture(t, mode)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestCacheScope_RequiresDistinctPrincipals(t *testing.T) {
	exec := mcpattack.NewCacheScopeExecutor(attack.RuleContext{ID: "mcp-cache-scope-001"})
	for _, principals := range [][]attack.Principal{
		nil,
		{{Name: "a", Token: "same"}, {Name: "b", Token: "same"}},
	} {
		findings, err := exec.Execute(t.Context(), "http://127.0.0.1:1", attack.Options{Principals: principals})
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("principals=%+v findings=%+v err=%v", principals, findings, err)
		}
	}
}

func TestCacheScope_ResourceRead(t *testing.T) {
	findings, fixture, err := runCacheScopeFixture(t, "resource-public")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "resources/read") ||
		!strings.Contains(findings[0].Evidence, "shared resource: 1 of 1") ||
		strings.Contains(findings[0].Evidence, "resource://") ||
		strings.Contains(findings[0].Evidence, "secret-") {
		t.Fatalf("incorrect or secret-bearing evidence: %+v", findings[0])
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls["tok-a:resources/read"] != 2 || fixture.calls["tok-b:resources/read"] != 2 {
		t.Fatalf("expected repeated reads, calls=%v", fixture.calls)
	}
}

func TestCacheScope_ResourceReadControls(t *testing.T) {
	for _, mode := range []string{"resource-private", "resource-same", "resource-unstable", "resource-denied", "resource-input"} {
		t.Run(mode, func(t *testing.T) {
			findings, _, err := runCacheScopeFixture(t, mode)
			wantIncomplete := mode == "resource-unstable" || mode == "resource-denied" || mode == "resource-input"
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != wantIncomplete {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestCacheScope_ResourceReadBound(t *testing.T) {
	findings, fixture, err := runCacheScopeFixture(t, "resource-many")
	if err != nil || len(findings) != 5 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.calls["tok-a:resources/read"] != 10 || fixture.calls["tok-b:resources/read"] != 10 {
		t.Fatalf("expected five repeated reads per principal, calls=%v", fixture.calls)
	}
}
