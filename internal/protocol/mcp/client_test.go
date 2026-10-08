package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestWithSkipTLSVerify_TakesEffect confirms the security-relevant skip-TLS
// option actually enables InsecureSkipVerify on a normally-constructed client.
func TestWithSkipTLSVerify_TakesEffect(t *testing.T) {
	c, err := NewClient("https://example.com", WithSkipTLSVerify())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("WithSkipTLSVerify did not enable InsecureSkipVerify")
	}
}

// TestWithSkipTLSVerify_NilConfig exercises a transport with no TLS config. The
// option must create one and enable InsecureSkipVerify; before the fix this
// nil-dereferenced.
func TestWithSkipTLSVerify_NilConfig(t *testing.T) {
	c := &Client{http: &http.Client{Transport: &http.Transport{}}} // nil TLSClientConfig
	WithSkipTLSVerify()(c)
	tr := c.http.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("WithSkipTLSVerify should create a TLS config and enable InsecureSkipVerify")
	}
}

func TestTryDiscover_RejectsUnrelatedOrIncompleteReplies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		version string
		kind    string
	}{
		{name: "wrong id", id: "unrelated", version: modernVersion, kind: "complete"},
		{name: "wrong version", id: "batesian-probe-discover", version: "2025-11-25", kind: "complete"},
		{name: "incomplete", id: "batesian-probe-discover", version: modernVersion, kind: "input_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": tc.id,
					"result": map[string]interface{}{
						"resultType": tc.kind, "supportedVersions": []string{tc.version},
						"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
			}))
			defer srv.Close()
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.tryDiscover(context.Background(), srv.URL); err == nil {
				t.Fatal("untrusted discovery reply was accepted")
			}
		})
	}
}

func TestListResult_RejectsModernProtocolErrors(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":10,"error":{"code":-32601,"message":"not found"}}`,
		`{"jsonrpc":"2.0","id":11,"result":{"resultType":"complete","resources":[]}}`,
		`{"jsonrpc":"2.0","id":10,"result":{"resultType":"input_required","tools":[]}}`,
	} {
		if _, err := listResult([]byte(body), 10, true); err == nil {
			t.Fatalf("invalid modern list result was accepted: %s", body)
		}
	}
}

func TestLegacyRequestsCarryNegotiatedVersion(t *testing.T) {
	for _, tc := range []struct {
		name      string
		version   string
		sessionID string
	}{
		{name: "stateful older revision", version: "2025-06-18", sessionID: "session-1"},
		{name: "stateless latest revision", version: "2025-11-25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type request struct {
				method  string
				version string
				session string
			}
			var requests []request
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Method string `json:"method"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests = append(requests, request{
					method: body.Method, version: r.Header.Get("MCP-Protocol-Version"),
					session: r.Header.Get("Mcp-Session-Id"),
				})
				switch body.Method {
				case "initialize":
					if tc.sessionID != "" {
						w.Header().Set("Mcp-Session-Id", tc.sessionID)
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 1,
						"result": map[string]interface{}{
							"protocolVersion": tc.version,
							"serverInfo":      map[string]string{"name": "fixture", "version": "1"},
							"capabilities": map[string]interface{}{
								"tools": map[string]interface{}{}, "resources": map[string]interface{}{},
								"prompts": map[string]interface{}{},
							},
						},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "tools/list", "resources/list", "prompts/list":
					id := map[string]int{"tools/list": 10, "resources/list": 11, "prompts/list": 12}[body.Method]
					key := map[string]string{"tools/list": "tools", "resources/list": "resources", "prompts/list": "prompts"}[body.Method]
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{key: []interface{}{}},
					})
				default:
					t.Errorf("unexpected method %q", body.Method)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer srv.Close()

			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.Initialize(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListTools(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListResources(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListPrompts(context.Background(), session); err != nil {
				t.Fatal(err)
			}

			if len(requests) != 5 {
				t.Fatalf("got %d requests, want 5: %+v", len(requests), requests)
			}
			if requests[0].method != "initialize" || requests[0].version != "" || requests[0].session != "" {
				t.Errorf("initialize carried session headers: %+v", requests[0])
			}
			for _, got := range requests[1:] {
				if got.version != tc.version || got.session != tc.sessionID {
					t.Errorf("%s headers = version %q, session %q; want %q, %q",
						got.method, got.version, got.session, tc.version, tc.sessionID)
				}
			}
		})
	}
}

func TestConnectSelectsModernWhenAvailable(t *testing.T) {
	for _, tc := range []struct {
		name         string
		legacy       bool
		modern       bool
		noDiscovery  bool
		rpcErrorCode int
		rpcStatus    int
		wantMethods  []string
		wantVersion  string
		wantTool     string
	}{
		{
			name: "dual era", legacy: true, modern: true,
			wantMethods: []string{"server/discover", "tools/list"},
			wantVersion: modernVersion, wantTool: "modern-tool",
		},
		{
			name: "modern only", modern: true,
			wantMethods: []string{"server/discover", "tools/list"},
			wantVersion: modernVersion, wantTool: "modern-tool",
		},
		{
			name: "legacy advertised", legacy: true,
			wantMethods: []string{"server/discover", "initialize", "notifications/initialized", "tools/list"},
			wantVersion: "2025-11-25", wantTool: "legacy-tool",
		},
		{
			name: "legacy without discovery", legacy: true, noDiscovery: true,
			wantMethods: []string{"server/discover", "initialize", "notifications/initialized", "tools/list"},
			wantVersion: "2025-11-25", wantTool: "legacy-tool",
		},
		{
			name: "legacy method not found", legacy: true, rpcErrorCode: -32601,
			wantMethods: []string{"server/discover", "initialize", "notifications/initialized", "tools/list"},
			wantVersion: "2025-11-25", wantTool: "legacy-tool",
		},
		{
			name: "legacy version rejected", legacy: true, rpcErrorCode: -32022, rpcStatus: http.StatusBadRequest,
			wantMethods: []string{"server/discover", "initialize", "notifications/initialized", "tools/list"},
			wantVersion: "2025-11-25", wantTool: "legacy-tool",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Method string                 `json:"method"`
					Params map[string]interface{} `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				methods = append(methods, body.Method)
				isModern := body.Method == "server/discover" ||
					(body.Method == "tools/list" && r.Header.Get("MCP-Protocol-Version") == modernVersion)
				if isModern {
					if got := r.Header.Get("MCP-Protocol-Version"); got != modernVersion {
						t.Errorf("%s version = %q, want %q", body.Method, got, modernVersion)
					}
					if got := r.Header.Get("Mcp-Method"); got != body.Method {
						t.Errorf("%s method header = %q", body.Method, got)
					}
					meta, _ := body.Params["_meta"].(map[string]interface{})
					if meta["io.modelcontextprotocol/protocolVersion"] != modernVersion {
						t.Errorf("%s has wrong modern metadata: %+v", body.Method, meta)
					}
				}
				switch body.Method {
				case "server/discover":
					if tc.noDiscovery {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if tc.rpcErrorCode != 0 {
						if tc.rpcStatus != 0 {
							w.WriteHeader(tc.rpcStatus)
						}
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": "batesian-probe-discover",
							"error": map[string]interface{}{"code": tc.rpcErrorCode, "message": "Rejected"},
						})
						return
					}
					versions := []string{"2025-11-25"}
					if tc.modern {
						versions = append(versions, modernVersion)
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": "batesian-probe-discover",
						"result": map[string]interface{}{
							"resultType": "complete", "supportedVersions": versions,
							"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
						},
					})
				case "initialize":
					if !tc.legacy {
						t.Error("modern-only server received initialize")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 1,
						"result": map[string]interface{}{
							"protocolVersion": "2025-11-25",
							"serverInfo":      map[string]string{"name": "fixture", "version": "1"},
							"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
						},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "tools/list":
					if !isModern && !tc.legacy {
						t.Error("modern-only server received legacy tools/list")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					tool := "legacy-tool"
					result := map[string]interface{}{"tools": []map[string]string{{"name": tool}}}
					if isModern {
						tool = "modern-tool"
						result = map[string]interface{}{
							"resultType": "complete", "tools": []map[string]string{{"name": tool}},
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 10, "result": result,
					})
				default:
					t.Errorf("unexpected method %q", body.Method)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer srv.Close()

			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.Connect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if session.Modern != tc.modern || session.ProtocolVersion != tc.wantVersion {
				t.Errorf("selected modern=%t, version=%q; want modern=%t, version=%q",
					session.Modern, session.ProtocolVersion, tc.modern, tc.wantVersion)
			}
			tools, err := client.ListTools(context.Background(), session)
			if err != nil {
				t.Fatal(err)
			}
			if len(tools) != 1 || tools[0].Name != tc.wantTool {
				t.Errorf("tools = %+v, want %q", tools, tc.wantTool)
			}
			if !slices.Equal(methods, tc.wantMethods) {
				t.Errorf("methods = %v, want %v", methods, tc.wantMethods)
			}
		})
	}
}

func TestConnectDoesNotDowngradeAfterDiscoveryFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "forbidden", status: http.StatusForbidden},
		{name: "server error", status: http.StatusInternalServerError},
		{name: "malformed success", status: http.StatusOK, body: "not JSON"},
		{
			name: "header mismatch", status: http.StatusBadRequest,
			body: `{"jsonrpc":"2.0","id":"batesian-probe-discover","error":{"code":-32020,"message":"Header mismatch"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Method string `json:"method"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				methods = append(methods, body.Method)
				if body.Method == "server/discover" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				if body.Method == "initialize" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": 1,
						"result": map[string]interface{}{
							"protocolVersion": "2025-11-25",
							"capabilities":    map[string]interface{}{},
						},
					})
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()
			client, err := NewClient(srv.URL + "?token=probe-secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Connect(context.Background()); err == nil {
				t.Fatal("failed modern discovery fell back to legacy")
			} else if strings.Contains(err.Error(), "probe-secret") {
				t.Errorf("discovery error leaked target query: %v", err)
			}
			if !slices.Equal(methods, []string{"server/discover"}) {
				t.Errorf("methods = %v, want only modern discovery", methods)
			}
		})
	}
}
