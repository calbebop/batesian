package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func restCancelAgent(t *testing.T, mode string, legacy, dual bool) (*httptest.Server, *[]string, *sync.Mutex) {
	t.Helper()
	sendPath, taskPath := "/agent/message:send", "/agent/tasks/"
	if legacy {
		sendPath, taskPath = "/agent/v1/message:send", "/agent/v1/tasks/"
	}
	taskID := "rest-owner-task"
	if mode == "escaped-id" {
		taskID = "task/a?b"
	}
	state := "submitted"
	if mode == "terminal" {
		state = "completed"
	}
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
			caller = ""
		}
		if strings.HasPrefix(r.URL.Path, "/.well-known/") {
			baseURL := "http://" + r.Host + "/agent"
			if mode == "off-origin" {
				baseURL = "http://untrusted.invalid/agent"
			}
			card := map[string]interface{}{"protocolVersion": "1.0", "supportedInterfaces": []interface{}{
				map[string]string{"protocolBinding": "HTTP+JSON", "url": baseURL},
			}}
			if dual {
				card["supportedInterfaces"] = []interface{}{
					map[string]string{"protocolBinding": "JSONRPC", "url": "http://" + r.Host + "/rpc"},
					map[string]string{"protocolBinding": "HTTP+JSON", "url": baseURL},
				}
			}
			if legacy {
				card = map[string]interface{}{"protocolVersion": "0.3.0", "preferredTransport": "HTTP+JSON", "url": baseURL}
			}
			writeJSON(w, card)
			return
		}
		if dual && r.Method == http.MethodPost && r.URL.Path == "/rpc" {
			method, id := decodeRPC(r)
			switch method {
			case "SendMessage", "message/send":
				if caller == "a" {
					taskResult(w, id, "rpc-owner-task", "rpc-context")
				} else {
					rpcErr(w, id, -32600, "authentication required")
				}
			case "GetTask", "tasks/get":
				writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": map[string]interface{}{
					"id": "rpc-owner-task", "status": map[string]string{"state": "submitted"},
				}})
			case "CancelTask", "tasks/cancel":
				w.WriteHeader(http.StatusForbidden)
			default:
				rpcErr(w, id, -32601, "Method not found")
			}
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == sendPath {
			if mode == "no-send" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if caller != "a" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct {
				Message struct {
					Role string `json:"role"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil ||
				(legacy && body.Message.Role != "user") || (!legacy && body.Message.Role != "ROLE_USER") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]interface{}{"task": map[string]string{"id": taskID}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), taskPath) {
			if mode == "escaped-id" && r.URL.EscapedPath() != taskPath+"task%2Fa%3Fb" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if caller != "a" || mode == "owner-blind" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			mu.Lock()
			current := state
			mu.Unlock()
			writeJSON(w, map[string]interface{}{"id": taskID, "status": map[string]string{"state": current}})
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.EscapedPath(), taskPath) &&
			strings.HasSuffix(r.URL.EscapedPath(), ":cancel") {
			mu.Lock()
			hits = append(hits, caller+" "+r.URL.EscapedPath())
			mu.Unlock()
			if mode == "escaped-id" && r.URL.EscapedPath() != taskPath+"task%2Fa%3Fb:cancel" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var body struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil ||
				(!legacy && body.ID != taskID) || (legacy && body.Name != "tasks/"+taskID) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if caller == "" {
				if mode != "anonymous-leak" && mode != "anon-mutate-403" && mode != "unpersisted" && mode != "anon-ambiguous" && mode != "no-cancel" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			} else if caller == "b" && mode != "cross-leak" && mode != "cross-mutate-403" && mode != "cross-unpersisted" && mode != "off-origin" && mode != "escaped-id" && mode != "no-cancel" {
				if mode == "cross-ambiguous" {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}
			if mode == "no-cancel" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if mode == "anon-ambiguous" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if mode != "unpersisted" && mode != "cross-unpersisted" {
				mu.Lock()
				state = "canceled"
				mu.Unlock()
			}
			if mode == "anon-mutate-403" || mode == "cross-mutate-403" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeJSON(w, map[string]interface{}{"id": taskID, "status": map[string]string{"state": "canceled"}})
			return
		}
		http.NotFound(w, r)
	}))
	return srv, &hits, &mu
}

func TestTaskCancelIDOR_REST(t *testing.T) {
	tests := []struct {
		name, mode   string
		legacy, dual bool
		title        string
		inconclusive bool
	}{
		{"REST-only anonymous cancel", "anonymous-leak", false, false, "without authentication", false},
		{"legacy REST anonymous cancel", "anonymous-leak", true, false, "without authentication", false},
		{"dual binding REST cancel", "cross-leak", false, true, "non-owning", false},
		{"REST-only cross-principal cancel", "cross-leak", false, false, "non-owning", false},
		{"off-origin card pinned", "off-origin", false, false, "non-owning", false},
		{"task ID escaped", "escaped-id", false, false, "non-owning", false},
		{"anonymous response denied after mutation", "anon-mutate-403", false, false, "without authentication", false},
		{"other response denied after mutation", "cross-mutate-403", false, false, "non-owning", false},
		{"owner-bound cancel", "secure", false, false, "", false},
		{"cancel surface absent", "no-cancel", false, false, "", false},
		{"unpersisted response", "unpersisted", false, false, "", true},
		{"non-owner response not persisted", "cross-unpersisted", false, false, "", true},
		{"anonymous error", "anon-ambiguous", false, false, "", true},
		{"cross-principal error", "cross-ambiguous", false, false, "", true},
		{"owner cannot read", "owner-blind", false, false, "", true},
		{"task already terminal", "terminal", false, false, "", true},
		{"task creation absent", "no-send", false, false, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits, mu := restCancelAgent(t, tc.mode, tc.legacy, tc.dual)
			defer srv.Close()
			findings, err := a2a.NewTaskCancelIDORExecutor(attack.RuleContext{
				ID: "a2a-task-cancel-idor-001", Name: "A2A Cross-Principal Task Cancellation",
			}).Execute(context.Background(), srv.URL, attack.Options{
				TimeoutSeconds: 5,
				Principals: []attack.Principal{
					{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
					{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
				},
			})
			if errors.Is(err, attack.ErrInconclusive) != tc.inconclusive {
				t.Fatalf("findings=%+v err=%v; want inconclusive=%t", findings, err, tc.inconclusive)
			}
			if !tc.inconclusive && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := 0
			if tc.title != "" {
				want = 1
			}
			if len(findings) != want {
				t.Fatalf("findings=%+v; want %d", findings, want)
			}
			if want != 0 && !strings.Contains(findings[0].Title, tc.title) {
				t.Fatalf("unexpected finding: %+v", findings[0])
			}
			mu.Lock()
			gotHits := append([]string(nil), (*hits)...)
			mu.Unlock()
			if want != 0 && len(gotHits) == 0 {
				t.Fatal("finding without a REST cancel request")
			}
		})
	}
}
