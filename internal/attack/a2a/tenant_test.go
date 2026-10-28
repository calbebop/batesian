package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestJSONRPCInterfaceTenant(t *testing.T) {
	for _, tc := range []struct {
		name, cardTenant, wantTenant string
		offOrigin                    bool
	}{
		{"advertised", `,"tenant":"team-a"`, "team-a", false},
		{"off-origin URL pinned", `,"tenant":"team-a"`, "team-a", true},
		{"omitted", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/agent-card.json" {
					cardURL := server.URL + "/rpc"
					if tc.offOrigin {
						cardURL = "https://other.example/rpc"
					}
					_, _ = fmt.Fprintf(w, `{"supportedInterfaces":[{"url":%q,"protocolBinding":"JSONRPC","protocolVersion":"1.0"%s}]}`,
						cardURL, tc.cardTenant)
					return
				}
				if r.URL.Path != "/rpc" {
					http.NotFound(w, r)
					return
				}
				var request struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
					Params map[string]any  `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					t.Error("invalid JSON-RPC request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				value, hasTenant := request.Params["tenant"]
				if (tc.cardTenant == "" || request.Method == "tasks/get") && hasTenant ||
					request.Method != "tasks/get" && tc.cardTenant != "" && value != tc.wantTenant {
					t.Errorf("%s tenant = %v (present %t)", request.Method, value, hasTenant)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if request.Method == "GetTask" {
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID,
						"error": map[string]any{"code": -32001, "message": "Task not found"}})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID,
					"result": map[string]any{"task": map[string]any{"id": "task-1"}}})
			}))
			defer server.Close()

			ctx := withTenantRouting(context.Background())
			client := newClient(server.URL)
			endpoint, ok := resolveA2AEndpoint(ctx, client, server.URL)
			if !ok || endpoint != server.URL+"/rpc" {
				t.Fatalf("selected endpoint = %q (ok %t)", endpoint, ok)
			}
			response, err := client.POST(ctx, endpoint, map[string]string{"A2A-Version": "1.0"},
				map[string]any{"jsonrpc": "2.0", "id": "send", "method": "SendMessage", "params": map[string]any{"message": map[string]any{}}})
			if err != nil || !response.IsAccepted() {
				t.Fatalf("send response = %v, error = %v", response, err)
			}
		})
	}
}

func TestRESTInterfaceTenant(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = fmt.Fprintf(w, `{"supportedInterfaces":[{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"team-b"}]}`,
				server.URL+"/api")
			return
		}
		switch r.URL.Path {
		case "/api/message:send":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["tenant"] != "team-b" {
				t.Errorf("REST send tenant = %v", body["tenant"])
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		case "/api/tasks":
			if r.URL.Query().Get("tenant") != "team-b" || r.URL.Query().Get("pageToken") != "next" {
				t.Errorf("REST list query = %q", r.URL.RawQuery)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		case "/api/tasks/task-1/pushNotificationConfigs/config-1":
			if r.Method != http.MethodDelete || r.URL.Query().Get("tenant") != "team-b" {
				t.Errorf("REST delete = %s %q", r.Method, r.URL.RawQuery)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx := withTenantRouting(context.Background())
	client := newClient(server.URL)
	interfaces := resolveHTTPJSONInterfaces(ctx, client, server.URL)
	if len(interfaces) != 1 || interfaces[0].base != server.URL+"/api" {
		t.Fatalf("REST interfaces = %+v", interfaces)
	}
	ctx = withHTTPJSONInterface(ctx, interfaces[0])
	headers := map[string]string{"A2A-Version": "1.0"}
	if response, err := client.POST(ctx, interfaces[0].base+"/message:send", headers, map[string]any{"message": map[string]any{}}); err != nil || !response.IsSuccess() {
		t.Fatalf("REST send response = %v, error = %v", response, err)
	}
	if response, err := client.GET(ctx, interfaces[0].base+"/tasks?pageToken=next", headers); err != nil || !response.IsSuccess() {
		t.Fatalf("REST list response = %v, error = %v", response, err)
	}
	if response, err := client.DELETE(ctx, interfaces[0].base+"/tasks/task-1/pushNotificationConfigs/config-1", headers); err != nil || !response.IsSuccess() {
		t.Fatalf("REST delete response = %v, error = %v", response, err)
	}
}

func TestRESTSharedURLKeepsDistinctTenants(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = fmt.Fprintf(w, `{"supportedInterfaces":[`+
				`{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"alpha"},`+
				`{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"beta"},`+
				`{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}]}`,
				server.URL+"/api", server.URL+"/api", server.URL+"/api")
			return
		}
		var request map[string]any
		if r.URL.Path != "/api/message:send" || json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(request)
	}))
	defer server.Close()

	ctx := withTenantRouting(t.Context())
	client := newClient(server.URL)
	interfaces := resolveHTTPJSONInterfaces(ctx, client, server.URL)
	if len(interfaces) != 3 || !sharedHTTPJSONTenants(interfaces, server.URL+"/api") {
		t.Fatalf("interfaces = %+v", interfaces)
	}
	for i, want := range []string{"alpha", "beta", ""} {
		response, err := client.POST(withHTTPJSONInterface(ctx, interfaces[i]), server.URL+"/api/message:send",
			map[string]string{"A2A-Version": "1.0"}, map[string]any{"message": map[string]any{}})
		if err != nil || !response.IsSuccess() {
			t.Fatalf("route %d response = %v, error = %v", i, response, err)
		}
		var request map[string]any
		if json.Unmarshal(response.Body, &request) != nil {
			t.Fatalf("route %d returned invalid JSON", i)
		}
		value, present := request["tenant"]
		if present != (i < 2) || present && value != want {
			t.Errorf("route %d tenant = %v (present %t)", i, value, present)
		}
	}
}

func TestAnonymousRESTListSkipsSharedTenantURL(t *testing.T) {
	var server *httptest.Server
	listReads := 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = fmt.Fprintf(w, `{"supportedInterfaces":[`+
				`{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"A"},`+
				`{"url":%q,"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"B"}]}`,
				server.URL+"/api", server.URL+"/api")
			return
		}
		if r.URL.Path == "/api/tasks" {
			listReads++
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{map[string]string{"id": "owner-task"}}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	vars := attack.NewVars(server.URL, "")
	ctx := withTenantRouting(t.Context())
	client := newClient(server.URL)
	probe := NewTaskIDORExecutor(attack.RuleContext{}).probeTaskList(ctx, client, client, vars, "owner-task", "", true)
	if len(probe.findings) != 0 || !probe.unverified || probe.reason == "" || listReads != 0 {
		t.Fatalf("probe = %+v, shared-route list reads = %d", probe, listReads)
	}
}

func TestTenantRoutingKeepsLegacyAndProbeBodiesUnchanged(t *testing.T) {
	routes := &tenantRoutes{}
	tenant := "team-c"
	ctx := context.WithValue(context.Background(), tenantRoutesKey{}, routes)
	registerTenantRoute(ctx, "https://agent.example/rpc", "JSONRPC", &tenant)
	v1 := map[string]any{"jsonrpc": "2.0", "method": "GetTask", "params": map[string]any{"id": "task-1"}}
	_, routed := routes.augment(http.MethodPost, "https://agent.example/rpc", map[string]string{"A2A-Version": "1.0"}, v1)
	params := routed.(map[string]any)["params"].(map[string]any)
	if params["tenant"] != tenant || v1["params"].(map[string]any)["tenant"] != nil {
		t.Fatalf("routed request = %v; original request = %v", routed, v1)
	}
	legacy := map[string]any{"jsonrpc": "2.0", "method": "tasks/get", "params": map[string]any{"id": "task-1"}}
	_, routed = routes.augment(http.MethodPost, "https://agent.example/rpc", map[string]string{"A2A-Version": "1.0"}, legacy)
	if _, ok := routed.(map[string]any)["params"].(map[string]any)["tenant"]; ok {
		t.Fatalf("legacy request gained tenant: %v", routed)
	}
	batch := []interface{}{v1}
	_, routed = routes.augment(http.MethodPost, "https://agent.example/rpc", map[string]string{"A2A-Version": "1.0"}, batch)
	if routed.([]interface{})[0].(map[string]any)["params"].(map[string]any)["tenant"] != tenant {
		t.Fatalf("batch request = %v", routed)
	}
}

func TestTenantRoutingStaysOnSelectedInterface(t *testing.T) {
	routes := &tenantRoutes{}
	tenant := ""
	ctx := context.WithValue(context.Background(), tenantRoutesKey{}, routes)
	registerTenantRoute(ctx, "https://agent.example/api", "HTTP+JSON", &tenant)
	headers := map[string]string{"A2A-Version": "1.0"}
	query, body := routes.augment(http.MethodGet, "https://agent.example/api/tasks", headers, nil)
	if value, ok := query["tenant"]; !ok || value != "" || body != nil {
		t.Fatalf("explicit empty tenant was lost: %v, %v", query, body)
	}
	for _, requestURL := range []string{
		"https://agent.example/api2/tasks",
		"https://other.example/api/tasks",
	} {
		query, _ := routes.augment(http.MethodGet, requestURL, headers, nil)
		if len(query) != 0 {
			t.Errorf("tenant leaked to %s: %v", requestURL, query)
		}
	}
	registerTenantRoute(ctx, "https://agent.example/api/open", "HTTP+JSON", nil)
	query, _ = routes.augment(http.MethodGet, "https://agent.example/api/open/tasks", headers, nil)
	if len(query) != 0 {
		t.Fatalf("parent tenant leaked into an unscoped interface: %v", query)
	}
	registerTenantRoute(ctx, "https://agent.example/api", "HTTP+JSON", nil)
	query, _ = routes.augment(http.MethodGet, "https://agent.example/api/tasks", headers, nil)
	if len(query) != 0 {
		t.Fatalf("tenant was not omitted: %v", query)
	}
}
