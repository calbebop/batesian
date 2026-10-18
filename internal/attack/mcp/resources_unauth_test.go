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
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func resourcesRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-resources-unauth-001",
		Name:        "MCP Resources Unauthenticated Read",
		Severity:    "critical",
		Remediation: "Require authentication on all MCP endpoints.",
	}
}

// mcpResourcesServer builds a test server that serves resources/list and
// resources/read without any authentication.
func mcpResourcesServer(t *testing.T, resources []map[string]interface{}, readContent string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "resources/list":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{"resources": resources},
			})
		case "resources/read":
			params, _ := req["params"].(map[string]interface{})
			uri, _ := params["uri"].(string)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"contents": []interface{}{
						map[string]interface{}{
							"uri":      uri,
							"mimeType": "text/plain",
							"text":     readContent,
						},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
}

// mcpResourcesRequireAuthServer returns 401 for all resource requests.
func mcpResourcesRequireAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "secure", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "server/discover":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"supportedVersions": []string{"2025-03-26"}},
			})
		default:
			// Reject with JSON-RPC auth error
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32000, "message": "Authentication required"},
			})
		}
	}))
}

func TestResourcesUnauth_Vulnerable(t *testing.T) {
	resources := []map[string]interface{}{
		{"uri": "config://database", "name": "DB Config", "mimeType": "text/plain"},
		{"uri": "config://app", "name": "App Config", "mimeType": "text/plain"},
	}
	// Benign content with no detectable secret: the read is still a finding but
	// graded "high", not escalated to critical.
	content := "Welcome to the public configuration overview page."

	ts := mcpResourcesServer(t, resources, content)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (list + read), got %d", len(findings))
	}
	// Without a detected secret, no finding should be critical.
	for _, f := range findings {
		if f.Severity != "high" {
			t.Errorf("finding %q: want high severity for non-secret content, got %q", f.Title, f.Severity)
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q: want ConfirmedExploit, got %q", f.Title, f.Confidence)
		}
		if strings.Contains(f.Evidence+f.Description, content) {
			t.Errorf("finding exposed resource content: %+v", f)
		}
	}
	if !strings.Contains(findings[len(findings)-1].Evidence, "content: ") {
		t.Errorf("read finding should retain content length: %+v", findings[len(findings)-1])
	}
}

func TestResourcesUnauth_CredentialInContent(t *testing.T) {
	resources := []map[string]interface{}{
		{"uri": "secrets://api", "name": "API Keys", "mimeType": "text/plain"},
	}
	// Contains an AWS access key - should trigger credential detection
	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"

	ts := mcpResourcesServer(t, resources, content)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Credential detection should escalate the read finding to critical.
	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
			if !strings.Contains(f.Evidence, "AKIA") && !strings.Contains(f.Description, "Credential pattern") {
				t.Errorf("critical finding should cite the matched credential pattern: %q", f.Title)
			}
		}
	}
	if !hasCritical {
		t.Errorf("expected a critical finding when content contains an AWS key, got: %v", findings)
	}
}

func TestResourcesUnauth_ReadRequiresContents(t *testing.T) {
	cases := []struct {
		name        string
		result      map[string]interface{}
		wrongID     bool
		status      int
		rpcError    bool
		badJSON     bool
		findings    int
		wantOutcome string
	}{
		{name: "missing result", findings: 1, wantOutcome: "incomplete (missing result)"},
		{name: "missing contents", result: map[string]interface{}{}, findings: 1, wantOutcome: "incomplete (missing resource contents)"},
		{name: "empty contents", result: map[string]interface{}{"contents": []interface{}{}}, findings: 1, wantOutcome: "no non-empty content returned"},
		{name: "input required", result: map[string]interface{}{"resultType": "input_required", "inputRequests": map[string]interface{}{}}, findings: 1, wantOutcome: "incomplete (input required)"},
		{name: "unexpected result type", result: map[string]interface{}{"resultType": "unknown"}, findings: 1, wantOutcome: "incomplete (unexpected result type)"},
		{name: "empty text", result: map[string]interface{}{"contents": []map[string]string{{"uri": "config://one", "text": ""}}}, findings: 1, wantOutcome: "no non-empty content returned"},
		{name: "invalid blob", result: map[string]interface{}{"contents": []map[string]string{{"uri": "config://one", "blob": "not base64"}}}, findings: 1, wantOutcome: "incomplete (invalid resource content)"},
		{name: "wrong response ID", result: map[string]interface{}{"contents": []map[string]string{{"uri": "config://one", "text": "data"}}}, wrongID: true, findings: 1, wantOutcome: "incomplete (invalid JSON-RPC response)"},
		{name: "HTTP unauthorized", status: http.StatusUnauthorized, findings: 1, wantOutcome: "denied (HTTP 401)"},
		{name: "HTTP forbidden", status: http.StatusForbidden, findings: 1, wantOutcome: "denied (HTTP 403)"},
		{name: "HTTP unavailable", status: http.StatusServiceUnavailable, findings: 1, wantOutcome: "incomplete (HTTP 503)"},
		{name: "JSON-RPC error", rpcError: true, findings: 1, wantOutcome: "incomplete (JSON-RPC error)"},
		{name: "malformed response", badJSON: true, findings: 1, wantOutcome: "incomplete (invalid JSON-RPC response)"},
		{name: "text content", result: map[string]interface{}{"contents": []map[string]string{{"uri": "config://one", "text": "data"}}}, findings: 2, wantOutcome: "content returned"},
		{name: "complete result", result: map[string]interface{}{"resultType": "complete", "contents": []map[string]string{{"uri": "config://one", "text": "data"}}}, findings: 2, wantOutcome: "content returned"},
		{name: "blob content", result: map[string]interface{}{"contents": []map[string]string{{"uri": "config://one", "blob": "ZGF0YQ=="}}}, findings: 2, wantOutcome: "content returned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string          `json:"method"`
					ID     json.RawMessage `json:"id"`
				}
				if json.NewDecoder(r.Body).Decode(&req) != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				id := req.ID
				if req.Method == "resources/read" && tc.wrongID {
					id = json.RawMessage("99")
				}
				reply := func(result interface{}) {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": id, "result": result,
					})
				}
				switch req.Method {
				case "initialize":
					reply(map[string]interface{}{
						"protocolVersion": "2025-03-26",
						"serverInfo":      map[string]string{"name": "read-shape", "version": "1"},
						"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "resources/list":
					reply(map[string]interface{}{"resources": []map[string]string{{"uri": "config://one", "name": "one"}}})
				case "resources/read":
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					if tc.rpcError {
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": id,
							"error": map[string]interface{}{"code": -32000, "message": "read failed"},
						})
						return
					}
					if tc.badJSON {
						_, _ = w.Write([]byte("not json"))
						return
					}
					reply(tc.result)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			findings, err := mcpattack.NewResourcesUnauthExecutor(resourcesRC()).Execute(context.Background(), ts.URL, testOpts())
			if err != nil || len(findings) != tc.findings {
				t.Fatalf("expected %d finding(s), got findings=%+v err=%v", tc.findings, findings, err)
			}
			if !strings.Contains(findings[0].Evidence, "1: "+tc.wantOutcome) {
				t.Errorf("missing read outcome %q in listing evidence: %s", tc.wantOutcome, findings[0].Evidence)
			}
			if strings.Contains(findings[0].Description, "read their contents") {
				t.Errorf("listing description claims unverified content access: %s", findings[0].Description)
			}
			if tc.findings == 1 && !strings.Contains(findings[0].Evidence, "resource content access not confirmed") {
				t.Errorf("missing unconfirmed read status: %s", findings[0].Evidence)
			}
		})
	}
}

func TestResourcesUnauth_AuthRequired(t *testing.T) {
	ts := mcpResourcesRequireAuthServer(t)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when auth required, got %d", len(findings))
	}
}

func TestResourcesUnauth_NoResources(t *testing.T) {
	// Server returns empty resources list - nothing to read, no finding expected.
	ts := mcpResourcesServer(t, []map[string]interface{}{}, "")
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with empty resource list, got %d", len(findings))
	}
}

func TestResourcesUnauth_MalformedResource(t *testing.T) {
	ts := mcpResourcesServer(t, []map[string]interface{}{{"name": "missing URI"}}, "")
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewResourcesUnauthExecutor(resourcesRC()), ts.URL, testOpts())
}

func TestResourcesUnauth_FollowsEmptyCursor(t *testing.T) {
	var followed atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                     `json:"method"`
			ID     json.RawMessage            `json:"id"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := func(result interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID, "result": result,
			})
		}
		switch req.Method {
		case "initialize":
			reply(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"serverInfo":      map[string]string{"name": "paged-resources", "version": "1"},
				"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			if raw, ok := req.Params["cursor"]; ok {
				var cursor string
				if json.Unmarshal(raw, &cursor) != nil || cursor != "" {
					http.Error(w, "unexpected cursor", http.StatusBadRequest)
					return
				}
				followed.Store(true)
				reply(map[string]interface{}{"resources": []map[string]string{{"uri": "config://later", "name": "later"}}})
				return
			}
			reply(map[string]interface{}{"resources": []interface{}{}, "nextCursor": ""})
		case "resources/read":
			reply(map[string]interface{}{"contents": []map[string]string{{
				"uri": "config://later", "text": "public data",
			}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer ts.Close()

	findings, err := mcpattack.NewResourcesUnauthExecutor(resourcesRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil || len(findings) != 2 || !followed.Load() {
		t.Fatalf("expected the later resource to be listed and read, got findings=%+v err=%v followed=%t",
			findings, err, followed.Load())
	}
}

func interruptedResourcesServer(firstPageResource bool, followed, distinctRead *atomic.Bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                     `json:"method"`
			ID     json.RawMessage            `json:"id"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := func(result interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID, "result": result,
			})
		}
		switch req.Method {
		case "initialize":
			reply(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"serverInfo":      map[string]string{"name": "interrupted-resources", "version": "1"},
				"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			if _, ok := req.Params["cursor"]; ok {
				followed.Store(true)
				http.Error(w, "unavailable", http.StatusBadGateway)
				return
			}
			resources := []map[string]string{}
			if firstPageResource {
				resources = append(resources, map[string]string{"uri": "config://first", "name": "first"})
			}
			reply(map[string]interface{}{"resources": resources, "nextCursor": "later"})
		case "resources/read":
			var id int
			var uri string
			_ = json.Unmarshal(req.ID, &id)
			_ = json.Unmarshal(req.Params["uri"], &uri)
			if id == 5 && uri == "config://first" {
				distinctRead.Store(true)
			}
			reply(map[string]interface{}{"contents": []map[string]string{{
				"uri": uri, "text": "public data",
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestResourcesUnauth_IncompleteEmptyListing(t *testing.T) {
	var followed, distinctRead atomic.Bool
	ts := interruptedResourcesServer(false, &followed, &distinctRead)
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewResourcesUnauthExecutor(resourcesRC()), ts.URL, testOpts())
	if !followed.Load() || distinctRead.Load() {
		t.Fatalf("expected a failed next page without a read, got followed=%t read=%t", followed.Load(), distinctRead.Load())
	}
}

func TestResourcesUnauth_PartialListingRetainsFinding(t *testing.T) {
	var followed, distinctRead atomic.Bool
	ts := interruptedResourcesServer(true, &followed, &distinctRead)
	defer ts.Close()

	findings, err := mcpattack.NewResourcesUnauthExecutor(resourcesRC()).Execute(context.Background(), ts.URL, testOpts())
	if err != nil || len(findings) != 2 || !followed.Load() || !distinctRead.Load() {
		t.Fatalf("expected first-page findings and a distinct read ID, got findings=%+v err=%v followed=%t read=%t",
			findings, err, followed.Load(), distinctRead.Load())
	}
	if !strings.Contains(findings[0].Evidence, "listing incomplete") {
		t.Fatalf("expected partial-listing evidence, got %q", findings[0].Evidence)
	}
}

func TestResourcesUnauth_ListOutcomes(t *testing.T) {
	type reply struct {
		status int
		code   int
		result map[string]interface{}
	}
	resource := []interface{}{map[string]interface{}{"uri": "config://one", "name": "one"}}
	empty := []interface{}{}
	cases := []struct {
		name          string
		first, second reply
		noCapability  bool
		inconclusive  bool
		findings      int
		incomplete    bool
		pages         int32
	}{
		{"server error", reply{status: 503, code: -32603}, reply{}, false, true, 0, false, 1},
		{"RPC error", reply{code: -32603}, reply{}, false, true, 0, false, 1},
		{"advertised method missing", reply{code: -32601}, reply{}, false, true, 0, false, 1},
		{"unadvertised method missing", reply{code: -32601}, reply{}, true, false, 0, false, 1},
		{"HTTP auth denial", reply{status: 401}, reply{}, false, false, 0, false, 1},
		{"RPC auth denial", reply{code: -32001}, reply{}, false, false, 0, false, 1},
		{"unfinished result", reply{result: map[string]interface{}{"resultType": "input_required", "resources": empty}}, reply{}, false, true, 0, false, 1},
		{"null cursor", reply{result: map[string]interface{}{"resources": empty, "nextCursor": nil}}, reply{}, false, false, 0, false, 1},
		{"invalid first cursor", reply{result: map[string]interface{}{"resources": empty, "nextCursor": 7}}, reply{}, false, true, 0, false, 1},
		{"invalid later cursor", reply{result: map[string]interface{}{"resources": empty, "nextCursor": "more"}}, reply{result: map[string]interface{}{"resources": empty, "nextCursor": 7}}, false, true, 0, false, 2},
		{"unfinished later result", reply{result: map[string]interface{}{"resources": resource, "nextCursor": "more"}}, reply{result: map[string]interface{}{"resultType": "input_required", "resources": empty}}, false, false, 2, true, 2},
		{"partial list with invalid cursor", reply{result: map[string]interface{}{"resources": resource, "nextCursor": "more"}}, reply{result: map[string]interface{}{"resources": empty, "nextCursor": 7}}, false, false, 2, true, 2},
		{"mixed malformed entries", reply{result: map[string]interface{}{"resources": append(resource, map[string]interface{}{"name": "missing URI"})}}, reply{}, false, false, 2, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pages atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string                     `json:"method"`
					ID     json.RawMessage            `json:"id"`
					Params map[string]json.RawMessage `json:"params"`
				}
				if json.NewDecoder(r.Body).Decode(&req) != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				replyResult := func(result interface{}) {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID, "result": result,
					})
				}
				switch req.Method {
				case "initialize":
					caps := map[string]interface{}{}
					if !tc.noCapability {
						caps["resources"] = map[string]interface{}{}
					}
					replyResult(map[string]interface{}{
						"protocolVersion": "2025-03-26",
						"serverInfo":      map[string]string{"name": "resource-outcomes", "version": "1"},
						"capabilities":    caps,
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "resources/list":
					pages.Add(1)
					page := tc.first
					if _, ok := req.Params["cursor"]; ok {
						page = tc.second
					}
					if page.status != 0 {
						w.WriteHeader(page.status)
					}
					if page.code != 0 {
						message := "Internal error"
						switch page.code {
						case -32601:
							message = "Method not found"
						case -32001:
							message = "Unauthorized"
						}
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": req.ID,
							"error": map[string]interface{}{"code": page.code, "message": message},
						})
						return
					}
					if page.status != http.StatusUnauthorized {
						replyResult(page.result)
					}
				case "resources/read":
					replyResult(map[string]interface{}{"contents": []map[string]string{{
						"uri": "config://one", "text": "public data",
					}}})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			findings, err := mcpattack.NewResourcesUnauthExecutor(resourcesRC()).Execute(context.Background(), ts.URL, testOpts())
			if errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				(!tc.inconclusive && err != nil) || len(findings) != tc.findings || pages.Load() != tc.pages {
				t.Fatalf("findings=%+v err=%v pages=%d", findings, err, pages.Load())
			}
			if tc.findings > 0 && strings.Contains(findings[0].Evidence, "listing incomplete") != tc.incomplete {
				t.Fatalf("unexpected listing evidence: %s", findings[0].Evidence)
			}
		})
	}
}

func TestResourcesUnauth_NotMCPServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	assertInconclusive(t, exec, ts.URL, testOpts())
}
