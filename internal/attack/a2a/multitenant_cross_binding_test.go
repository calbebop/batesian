package a2a_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func crossBindingServer(mode string) *httptest.Server {
	type task struct{ owner, source, marker string }
	var server *httptest.Server
	var mu sync.Mutex
	tasks := map[string]task{}
	nextID := 0
	create := func(owner, source, marker string) string {
		mu.Lock()
		defer mu.Unlock()
		nextID++
		id := fmt.Sprintf("task-%s-%d", source, nextID)
		tasks[id] = task{owner, source, marker}
		return id
	}
	lookup := func(id string) (task, bool) {
		mu.Lock()
		defer mu.Unlock()
		value, ok := tasks[id]
		return value, ok
	}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			restInterface := map[string]string{"url": server.URL + "/rest", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
			rpcInterface := map[string]string{"url": server.URL + "/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
			interfaces := []any{rpcInterface, restInterface}
			if mode == "tenant-scoped-card" {
				restInterface["tenant"] = "A"
			}
			if mode == "mixed-rpc-tenants" {
				interfaces = append(interfaces, map[string]string{"url": server.URL + "/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0", "tenant": "A"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"supportedInterfaces": interfaces})
			return
		}
		if r.URL.Path == "/rpc" {
			request := readBody(r)
			method, _ := request["method"].(string)
			id := request["id"]
			who := tenantOf(r)
			switch method {
			case "SendMessage":
				if who == "" || mode == "rest-leak-reader-unusable" && who == "B" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				taskID := create(who, "rpc", rpcMessageText(request))
				taskResult(w, id, taskID, "ctx-"+who)
			case "GetTask":
				params, _ := request["params"].(map[string]any)
				taskID, _ := params["id"].(string)
				value, ok := lookup(taskID)
				if ok && who == "B" && who != value.owner && value.source == "rpc" && mode == "wrong-source-denial-id" {
					rpcErr(w, "other-request", -32001, "Task not found")
					return
				}
				if !ok || who == "" || who != value.owner && (value.source == "rpc" ||
					mode != "rpc-leak" && mode != "both-leak" && mode != "wrong-task-id" &&
						mode != "wrong-rpc-response-id") {
					rpcErr(w, id, -32001, "Task not found")
					return
				}
				text := value.marker + " server-private-canary"
				if mode == "rest-leak-redacted-owner" && who == value.owner && value.source == "rest" &&
					strings.Contains(text, "cross-binding") {
					text = "redacted"
				}
				if mode == "wrong-task-id" && who != value.owner && value.source == "rest" {
					taskID = "other-task"
				}
				if mode == "wrong-rpc-response-id" && who != value.owner && value.source == "rest" {
					id = "other-request"
				}
				taskWithHistory(w, id, taskID, "ctx-"+value.owner, text)
			default:
				rpcErr(w, id, -32601, "Method not found")
			}
			return
		}
		if mode == "unsupported-rest" || !strings.HasPrefix(r.URL.Path, "/rest/") {
			http.NotFound(w, r)
			return
		}
		who := tenantOf(r)
		if r.Method == http.MethodPost && r.URL.Path == "/rest/message:send" {
			if who == "" || mode == "rest-leak-reader-unusable" && who == "B" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var request struct {
				Message struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Message.Parts) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			taskID := create(who, "rest", request.Message.Parts[0].Text)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"task": map[string]any{
				"id": taskID, "contextId": "ctx-" + who,
				"status": map[string]string{"state": "TASK_STATE_WORKING"},
			}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/rest/tasks/") {
			taskID := strings.TrimPrefix(r.URL.Path, "/rest/tasks/")
			value, ok := lookup(taskID)
			if !ok || who == "" && mode != "public-rest" || who != "" && who != value.owner &&
				(value.source == "rest" || mode != "rest-leak" && mode != "both-leak" &&
					mode != "public-rest" && mode != "rest-leak-redacted-owner" &&
					mode != "rest-leak-reader-unusable" && mode != "wrong-task-id" &&
					mode != "wrong-source-denial-id") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if who == "" && value.source == "rest" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			text := value.marker + " server-private-canary"
			if mode == "rest-leak-redacted-owner" && who == value.owner && value.source == "rpc" &&
				strings.Contains(text, "cross-binding") {
				text = "redacted"
			}
			if mode == "wrong-task-id" && who != value.owner && value.source == "rpc" {
				taskID = "other-task"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": taskID, "contextId": "ctx-" + value.owner,
				"status":  map[string]string{"state": "TASK_STATE_WORKING"},
				"history": []any{map[string]any{"parts": []any{map[string]string{"text": text}}}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	return server
}

func TestMultiTenantCrossBindingTaskReads(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		findings     int
		inconclusive bool
	}{
		{"secure", 0, false},
		{"rest-leak", 1, false},
		{"rpc-leak", 1, false},
		{"both-leak", 2, false},
		{"public-rest", 0, false},
		{"rest-leak-redacted-owner", 0, true},
		{"rest-leak-reader-unusable", 0, true},
		{"wrong-task-id", 0, true},
		{"wrong-rpc-response-id", 0, true},
		{"wrong-source-denial-id", 0, true},
		{"tenant-scoped-card", 0, true},
		{"mixed-rpc-tenants", 0, true},
		{"unsupported-rest", 0, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			server := crossBindingServer(tc.mode)
			defer server.Close()
			findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: tenantPrincipals()})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				err != nil && !tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			for _, finding := range findings {
				if finding.Confidence != attack.ConfirmedExploit ||
					!strings.Contains(finding.Evidence, "source reader: denied") ||
					!strings.Contains(finding.Evidence, "destination anonymous: denied") ||
					!strings.Contains(finding.Evidence, "matched task content omitted") ||
					strings.Contains(finding.Description+finding.Evidence, "server-private-canary") {
					t.Fatalf("finding lacked cross-binding controls: %+v", finding)
				}
				assertOpaqueTaskFinding(t, finding, "task-rpc-", "task-rest-", "batesian cross-binding")
			}
		})
	}
}
