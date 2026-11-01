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

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

type mrtrFixture struct {
	mode  string
	mu    sync.Mutex
	reads int
	lists int
}

func (f *mrtrFixture) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	respond := func(result interface{}, code int) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if code != 0 {
			body["error"] = map[string]interface{}{"code": code, "message": "denied"}
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
	switch req.Method {
	case "server/discover":
		capabilities := map[string]interface{}{"resources": map[string]interface{}{}}
		if f.mode == "no-resources" {
			capabilities = map[string]interface{}{}
		}
		respond(map[string]interface{}{"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": capabilities}, 0)
	case "resources/list":
		f.mu.Lock()
		f.lists++
		listNumber := f.lists
		f.mu.Unlock()
		if strings.HasPrefix(f.mode, "paged-") {
			cursor, _ := req.Params["cursor"].(string)
			result := map[string]interface{}{"resultType": "complete", "resources": []map[string]string{}}
			switch f.mode {
			case "paged-vulnerable":
				switch cursor {
				case "":
					resources := make([]map[string]string, 7)
					for i := range resources {
						resources[i] = map[string]string{"uri": "resource://public/" + strconv.Itoa(i), "name": "public"}
					}
					result["resources"] = resources
					result["nextCursor"] = "next"
				case "next":
					result["resources"] = []map[string]string{{"uri": "resource://owner?token=private", "name": "owner"}}
				}
			case "paged-loop":
				result["nextCursor"] = "next"
			case "paged-limit":
				result["nextCursor"] = strconv.Itoa(listNumber)
			case "paged-invalid":
				result["nextCursor"] = 7
			}
			respond(result, 0)
			return
		}
		resources := []map[string]string{{"uri": "resource://owner?token=private", "name": "owner"}}
		if f.mode == "many" {
			resources = nil
			for i := range 7 {
				resources = append(resources, map[string]string{"uri": "resource://owner/" + strconv.Itoa(i)})
			}
		}
		respond(map[string]interface{}{"resultType": "complete", "resources": resources}, 0)
	case "resources/read":
		f.mu.Lock()
		f.reads++
		f.mu.Unlock()
		uri, _ := req.Params["uri"].(string)
		state, _ := req.Params["requestState"].(string)
		if f.mode == "many" {
			respond(map[string]interface{}{"resultType": "complete", "contents": []interface{}{}}, 0)
			return
		}
		if uri != "resource://owner?token=private" {
			respond(nil, -32602)
			return
		}
		if principal == "tok-b" && state == "" {
			switch f.mode {
			case "shared":
				respond(mrtrComplete(uri, "owner-secret"), 0)
			case "rpc-denied":
				respond(nil, -32001)
			case "invalid-baseline":
				respond(nil, -32602)
			default:
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		if state == "" {
			result := map[string]interface{}{"resultType": "input_required", "requestState": "state-a"}
			if f.mode == "needs-input" {
				result["inputRequests"] = map[string]interface{}{"ask": map[string]interface{}{"method": "elicitation/create"}}
			}
			if f.mode == "missing-state" {
				delete(result, "requestState")
			}
			if f.mode == "long-state" {
				result["requestState"] = strings.Repeat("x", 4097)
			}
			respond(result, 0)
			return
		}
		if state != "state-a" || f.mode == "protected" && principal == "tok-b" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.mode == "renewed-state" && principal == "tok-b" {
			respond(map[string]interface{}{"resultType": "input_required", "requestState": "state-b"}, 0)
			return
		}
		if f.mode == "wrong-id" && principal == "tok-b" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 999, "result": mrtrComplete(uri, "owner-secret"),
			})
			return
		}
		if f.mode == "owner-fails" && principal == "tok-a" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if f.mode == "empty-content" {
			respond(map[string]interface{}{"resultType": "complete", "contents": []interface{}{}}, 0)
			return
		}
		content := "owner-secret"
		if f.mode == "different" && principal == "tok-b" {
			content = "guest-content"
		}
		respond(mrtrComplete(uri, content), 0)
	default:
		respond(nil, -32601)
	}
}

func mrtrComplete(uri, content string) map[string]interface{} {
	return map[string]interface{}{"resultType": "complete", "contents": []map[string]string{{"uri": uri, "text": content}}}
}

func runMRTRFixture(t *testing.T, mode string) ([]attack.Finding, *mrtrFixture, error) {
	t.Helper()
	fixture := &mrtrFixture{mode: mode}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	opts := testOpts()
	opts.Principals = []attack.Principal{
		{Name: "tenant-a", Tenant: "A", Token: "tok-a"},
		{Name: "tenant-b", Tenant: "B", Token: "tok-b"},
	}
	findings, err := mcpattack.NewMRTRStateExecutor(attack.RuleContext{
		ID: "mcp-mrtr-state-001", Name: "MCP request state replay", Remediation: "Bind state to the principal.",
	}).Execute(context.Background(), server.URL, opts)
	return findings, fixture, err
}

func TestMRTRState_CrossPrincipalReplay(t *testing.T) {
	findings, _, err := runMRTRFixture(t, "vulnerable")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Confidence != attack.RiskIndicator || finding.Access == nil ||
		finding.Access.Operation != attack.MCPResourcesRead ||
		finding.Access.Caller != "tenant-b" || finding.Access.Owner != "tenant-a" {
		t.Fatalf("incorrect access observation: %+v", finding)
	}
	encoded, _ := json.Marshal(finding)
	if strings.Contains(string(encoded), "owner-secret") || strings.Contains(string(encoded), "state-a") ||
		strings.Contains(string(encoded), "resource://owner") {
		t.Fatalf("finding disclosed resource or state: %s", encoded)
	}
	if !attack.ApplyExpectedDenial(&finding, []attack.ExpectedDenial{{
		Operation: attack.MCPResourcesRead, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A",
	}}) || finding.Confidence != attack.ConfirmedExploit {
		t.Fatalf("expected policy confirmation: %+v", finding)
	}
}

func TestMRTRState_JSONRPCAuthDenial(t *testing.T) {
	findings, _, err := runMRTRFixture(t, "rpc-denied")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}

func TestMRTRState_PaginatedOwnerResource(t *testing.T) {
	findings, fixture, err := runMRTRFixture(t, "paged-vulnerable")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.lists != 2 || fixture.reads > 10 {
		t.Fatalf("list calls=%d resource reads=%d", fixture.lists, fixture.reads)
	}
}

func TestMRTRState_BoundsResourcePages(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		lists int
	}{
		{"paged-loop", 2},
		{"paged-limit", 3},
		{"paged-invalid", 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			findings, fixture, err := runMRTRFixture(t, tc.mode)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.lists != tc.lists || fixture.reads != 0 {
				t.Fatalf("list calls=%d resource reads=%d", fixture.lists, fixture.reads)
			}
		})
	}
}

func TestMRTRState_ProtectedAndIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		incomplete bool
	}{
		{"protected", false},
		{"shared", true},
		{"different", true},
		{"owner-fails", true},
		{"empty-content", true},
		{"needs-input", true},
		{"missing-state", true},
		{"long-state", true},
		{"renewed-state", true},
		{"wrong-id", true},
		{"invalid-baseline", true},
		{"no-resources", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			findings, _, err := runMRTRFixture(t, tc.mode)
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.incomplete {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestMRTRState_BoundsReads(t *testing.T) {
	findings, fixture, err := runMRTRFixture(t, "many")
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.reads != 5 {
		t.Fatalf("expected five bounded reads, got %d", fixture.reads)
	}
}

func TestMRTRState_RequiresDistinctPrincipals(t *testing.T) {
	exec := mcpattack.NewMRTRStateExecutor(attack.RuleContext{ID: "mcp-mrtr-state-001"})
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
