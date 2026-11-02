package mcp_test

import (
	"context"
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

const subscriptionURI = "resource://owner/disposable?key=private"

type subscriptionFixture struct {
	mu       sync.Mutex
	mode     string
	content  string
	triggers int
	streams  []subscriptionSink
}

type subscriptionSink struct {
	principal string
	id        int
	events    chan string
}

func (f *subscriptionFixture) serve(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID     int                    `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	meta, _ := request.Params["_meta"].(map[string]interface{})
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
		r.Header.Get("Mcp-Method") != request.Method ||
		meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		http.Error(w, "wrong wire", http.StatusBadRequest)
		return
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if principal != "owner-token" && principal != "caller-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	respond := func(result interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": request.ID, "result": result,
		})
	}
	switch request.Method {
	case "server/discover":
		resources := map[string]interface{}{"subscribe": true}
		if f.mode == "no-capability" {
			resources["subscribe"] = false
		}
		respond(map[string]interface{}{"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": map[string]interface{}{"resources": resources, "tools": map[string]interface{}{}}})
	case "resources/read":
		if r.Header.Get("Mcp-Name") != subscriptionURI || request.Params["uri"] != subscriptionURI {
			http.Error(w, "wrong resource", http.StatusBadRequest)
			return
		}
		if principal == "caller-token" && f.mode != "no-denial" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		content := f.content
		f.mu.Unlock()
		contentURI := subscriptionURI
		if f.mode == "wrong-content-uri" {
			contentURI = "resource://other"
		}
		respond(map[string]interface{}{"resultType": "complete", "contents": []map[string]string{{
			"uri": contentURI, "text": content,
		}}})
	case "tools/list":
		if f.mode == "tool-paged" && request.Params["cursor"] == nil {
			respond(map[string]interface{}{"resultType": "complete", "tools": []interface{}{}, "nextCursor": "page-two"})
			return
		}
		toolName := "update_disposable"
		if f.mode == "tool-missing" {
			toolName = "another_tool"
		}
		respond(map[string]interface{}{"resultType": "complete", "tools": []map[string]interface{}{{
			"name": toolName, "inputSchema": map[string]interface{}{
				"type": "object", "properties": map[string]interface{}{
					"value": map[string]interface{}{"type": "string", "x-mcp-header": "value"},
				},
			},
		}}})
	case "tools/call":
		args, _ := request.Params["arguments"].(map[string]interface{})
		if principal != "owner-token" || r.Header.Get("Mcp-Name") != "update_disposable" ||
			r.Header.Get("Mcp-Param-Value") != "updated-secret" || args["value"] != "updated-secret" {
			http.Error(w, "unapproved update", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.triggers++
		if f.mode != "no-change" && f.mode != "tool-error" {
			f.content = "changed-content"
		}
		streams := append([]subscriptionSink(nil), f.streams...)
		f.mu.Unlock()
		if f.mode == "tool-error" {
			respond(map[string]interface{}{"resultType": "complete", "isError": true, "content": []interface{}{}})
			return
		}
		for _, stream := range streams {
			if f.mode == "no-owner-event" && stream.principal == "owner-token" {
				continue
			}
			if f.mode == "protected" && stream.principal == "caller-token" {
				continue
			}
			id := stream.id
			uri := subscriptionURI
			if stream.principal == "caller-token" && f.mode == "wrong-id" {
				id++
			}
			if stream.principal == "caller-token" && f.mode == "wrong-uri" {
				uri = "resource://other"
			}
			frame, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "method": "notifications/resources/updated",
				"params": map[string]interface{}{
					"_meta": map[string]interface{}{"io.modelcontextprotocol/subscriptionId": id}, "uri": uri,
				},
			})
			stream.events <- string(frame)
		}
		respond(map[string]interface{}{"resultType": "complete", "isError": false, "content": []interface{}{}})
	case "subscriptions/listen":
		if principal == "caller-token" && f.mode == "caller-denied" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if principal == "caller-token" &&
			(f.mode == "caller-rpc-denied" || f.mode == "caller-sse-denied" || f.mode == "caller-generic-error") {
			code, message := -32001, "Forbidden"
			if f.mode == "caller-generic-error" {
				code, message = -32603, "Internal error"
			}
			frame, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "id": request.ID,
				"error": map[string]interface{}{"code": code, "message": message},
			})
			if f.mode == "caller-sse-denied" {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, "data: %s\n\n", frame)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Write(frame)
			}
			return
		}
		if r.Header.Get("Accept") != "text/event-stream" {
			http.Error(w, "wrong accept", http.StatusBadRequest)
			return
		}
		requested, _ := request.Params["notifications"].(map[string]interface{})
		uris, _ := requested["resourceSubscriptions"].([]interface{})
		if len(uris) != 1 || uris[0] != subscriptionURI {
			http.Error(w, "wrong subscription", http.StatusBadRequest)
			return
		}
		ackURIs := []string{subscriptionURI}
		if principal == "caller-token" && f.mode == "ack-omitted" {
			ackURIs = []string{}
		}
		ackID := request.ID
		if principal == "caller-token" && f.mode == "wrong-ack-id" {
			ackID++
		}
		ack, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
			"params": map[string]interface{}{
				"_meta":         map[string]interface{}{"io.modelcontextprotocol/subscriptionId": ackID},
				"notifications": map[string]interface{}{"resourceSubscriptions": ackURIs},
			},
		})
		events := make(chan string, 2)
		f.mu.Lock()
		f.streams = append(f.streams, subscriptionSink{principal: principal, id: request.ID, events: events})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: %s\n\n", ack)
		w.(http.Flusher).Flush()
		for {
			select {
			case event := <-events:
				fmt.Fprintf(w, "data: %s\n\n", event)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func runSubscriptionFixture(t *testing.T, mode string) ([]attack.Finding, *subscriptionFixture, error) {
	t.Helper()
	fixture := &subscriptionFixture{mode: mode, content: "original-content"}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	opts := testOpts()
	opts.TimeoutSeconds = 1
	opts.Principals = []attack.Principal{
		{Name: "owner", Token: "owner-token"},
		{Name: "caller", Token: "caller-token"},
	}
	opts.MCPSubscriptionProbe = &attack.MCPSubscriptionProbe{
		Owner: "owner", Caller: "caller", ResourceURI: subscriptionURI,
		TriggerTool: "update_disposable", TriggerArguments: map[string]interface{}{"value": "updated-secret"},
	}
	findings, err := mcpattack.NewSubscriptionScopeExecutor(attack.RuleContext{
		ID: "mcp-subscription-scope-001", Name: "MCP subscription scope", Remediation: "Authorize updates.",
	}).Execute(context.Background(), server.URL, opts)
	return findings, fixture, err
}

func TestSubscriptionScope_Observed(t *testing.T) {
	for _, mode := range []string{"vulnerable", "ack-omitted", "tool-paged"} {
		t.Run(mode, func(t *testing.T) {
			findings, fixture, err := runSubscriptionFixture(t, mode)
			if err != nil || len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			encoded, _ := json.Marshal(findings)
			for _, secret := range []string{subscriptionURI, "updated-secret", "owner-token", "caller-token", "changed-content"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("finding disclosed resource or credential: %s", encoded)
				}
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.triggers != 1 {
				t.Fatalf("update tool called %d times", fixture.triggers)
			}
		})
	}
}

func TestSubscriptionScope_ProtectedAndIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		incomplete bool
		triggers   int
	}{
		{"caller-denied", true, 0},
		{"caller-rpc-denied", true, 0},
		{"caller-sse-denied", true, 0},
		{"caller-generic-error", true, 0},
		{"protected", true, 1},
		{"no-capability", true, 0},
		{"no-denial", true, 0},
		{"wrong-content-uri", true, 0},
		{"tool-missing", true, 0},
		{"no-owner-event", true, 1},
		{"no-change", true, 1},
		{"tool-error", true, 1},
		{"wrong-id", true, 1},
		{"wrong-uri", true, 1},
		{"wrong-ack-id", true, 0},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			findings, fixture, err := runSubscriptionFixture(t, tc.mode)
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.incomplete {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.triggers != tc.triggers {
				t.Fatalf("update tool called %d times", fixture.triggers)
			}
		})
	}
}

func TestSubscriptionScope_RequiresOptInAndDistinctPrincipals(t *testing.T) {
	exec := mcpattack.NewSubscriptionScopeExecutor(attack.RuleContext{})
	for _, opts := range []attack.Options{
		{},
		{MCPSubscriptionProbe: &attack.MCPSubscriptionProbe{Owner: "a", Caller: "b"}},
		{Principals: []attack.Principal{{Name: "a", Token: "same"}, {Name: "b", Token: "same"}},
			MCPSubscriptionProbe: &attack.MCPSubscriptionProbe{Owner: "a", Caller: "b"}},
	} {
		findings, err := exec.Execute(t.Context(), "http://127.0.0.1:1", opts)
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("findings=%+v err=%v", findings, err)
		}
	}
}
