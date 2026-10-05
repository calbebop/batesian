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
)

const restEnumCursor = "next+page /?"

type restEnumHit struct {
	caller, token, path, history, size string
}

func restEnumAgent(t *testing.T, mode string, legacy, dual bool, requireImmediate ...bool) (*httptest.Server, *[]restEnumHit, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var hits []restEnumHit
	sendPath, listPath := "/agent/message:send", "/agent/tasks"
	if legacy {
		sendPath, listPath = "/agent/v1/message:send", "/agent/v1/tasks"
	}
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
			interfaces := []interface{}{map[string]string{
				"protocolBinding": "HTTP+JSON", "url": baseURL,
			}}
			if dual {
				interfaces = append([]interface{}{map[string]string{
					"protocolBinding": "JSONRPC", "url": "http://" + r.Host + "/",
				}}, interfaces...)
			}
			card := map[string]interface{}{"protocolVersion": "1.0", "supportedInterfaces": interfaces}
			if legacy {
				card = map[string]interface{}{"protocolVersion": "0.3.0", "preferredTransport": "HTTP+JSON",
					"url": "http://" + r.Host + "/agent"}
			}
			writeJSON(w, card)
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
				Configuration struct {
					ReturnImmediately bool `json:"returnImmediately"`
				} `json:"configuration"`
				Message struct {
					Role string `json:"role"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil ||
				(legacy && body.Message.Role != "user") || (!legacy && body.Message.Role != "ROLE_USER") ||
				(len(requireImmediate) != 0 && requireImmediate[0] && !body.Configuration.ReturnImmediately) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]interface{}{"task": map[string]string{"id": "rest-owner-task"}})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == listPath {
			token := r.URL.Query().Get("pageToken")
			mu.Lock()
			hits = append(hits, restEnumHit{caller, token, r.URL.Path, r.URL.Query().Get("historyLength"), r.URL.Query().Get("pageSize")})
			mu.Unlock()
			if mode == "no-list" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if caller == "" && mode != "open" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if token == "" {
				writeJSON(w, map[string]interface{}{"tasks": []interface{}{map[string]string{"id": "older-task"}}, "nextPageToken": restEnumCursor})
				return
			}
			if token != restEnumCursor && !strings.HasPrefix(token, "page-") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if mode == "failed-page" && caller == "b" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if mode == "invalid-page" && caller == "b" {
				writeJSON(w, map[string]interface{}{"tasks": []interface{}{}, "nextPageToken": 12})
				return
			}
			if mode == "loop" && caller == "b" {
				writeJSON(w, map[string]interface{}{"tasks": []interface{}{}, "nextPageToken": restEnumCursor})
				return
			}
			if mode == "cap" && caller == "b" {
				mu.Lock()
				count := len(hits)
				mu.Unlock()
				writeJSON(w, map[string]interface{}{"tasks": []interface{}{}, "nextPageToken": fmt.Sprintf("page-%d", count)})
				return
			}
			tasks := []interface{}{}
			if caller == "a" && mode != "owner-blind" || mode == "open" ||
				caller == "b" && (mode == "unscoped" || mode == "off-origin") {
				tasks = append(tasks, map[string]string{"id": "rest-owner-task"})
			}
			writeJSON(w, map[string]interface{}{"tasks": tasks, "nextPageToken": ""})
			return
		}
		if dual && r.Method == http.MethodPost && r.URL.Path == "/" {
			method, id := decodeRPC(r)
			switch method {
			case "SendMessage", "message/send":
				if caller != "a" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{"task": map[string]string{"id": "rpc-owner-task"}}})
			case "ListTasks", "tasks/list":
				if caller == "" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				tasks := []interface{}{}
				if caller == "a" {
					tasks = append(tasks, map[string]string{"id": "rpc-owner-task"})
				}
				writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{"tasks": tasks, "nextPageToken": ""}})
			case "GetTask", "tasks/get":
				rpcErr(w, id, -32001, "Task not found")
			default:
				rpcErr(w, id, -32601, "Method not found")
			}
			return
		}
		http.NotFound(w, r)
	}))
	return srv, &hits, &mu
}

func TestTaskEnumeration_RESTLongRunningTaskReturnsImmediately(t *testing.T) {
	srv, _, _ := restEnumAgent(t, "unscoped", false, false, true)
	defer srv.Close()

	findings, err := runEnum(t, srv, enumOpts())
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected an unscoped listing finding, got %d findings and error %v", len(findings), err)
	}
}

func TestTaskEnumeration_RESTBinding(t *testing.T) {
	tests := []struct {
		name, mode   string
		legacy, dual bool
		finding      bool
		inconclusive bool
	}{
		{"REST-only unscoped", "unscoped", false, false, true, false},
		{"legacy REST unscoped", "unscoped", true, false, true, false},
		{"dual binding REST leak", "unscoped", false, true, true, false},
		{"off-origin card is pinned", "off-origin", false, false, true, false},
		{"scoped", "scoped", false, false, false, false},
		{"anonymous list open", "open", false, false, false, false},
		{"list absent", "no-list", false, false, false, false},
		{"task creation absent", "no-send", false, false, false, true},
		{"owner cannot list own task", "owner-blind", false, false, false, true},
		{"repeated cursor", "loop", false, false, false, true},
		{"page cap", "cap", false, false, false, true},
		{"failed continuation", "failed-page", false, false, false, true},
		{"invalid continuation", "invalid-page", false, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits, mu := restEnumAgent(t, tc.mode, tc.legacy, tc.dual)
			defer srv.Close()
			findings, err := runEnum(t, srv, enumOpts())
			if errors.Is(err, attack.ErrInconclusive) != tc.inconclusive {
				t.Fatalf("findings=%+v err=%v; want inconclusive=%t", findings, err, tc.inconclusive)
			}
			if !tc.inconclusive && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantFindings := 0
			if tc.finding {
				wantFindings = 1
			}
			if len(findings) != wantFindings {
				t.Fatalf("findings=%+v; want %d", findings, wantFindings)
			}
			if tc.finding && !strings.Contains(findings[0].TargetURL, "/agent/") {
				t.Fatalf("finding targeted wrong binding: %s", findings[0].TargetURL)
			}
			mu.Lock()
			gotHits := append([]restEnumHit(nil), (*hits)...)
			mu.Unlock()
			if len(gotHits) == 0 && tc.mode != "no-send" {
				t.Fatal("REST listing was not probed")
			}
			for _, hit := range gotHits {
				if hit.history != "0" || hit.size != "100" {
					t.Fatalf("unexpected list query: %+v", hit)
				}
			}
			if tc.finding && !strings.Contains(findings[0].Evidence, "rest-owner-task") {
				t.Fatalf("finding omitted owner task: %s", findings[0].Evidence)
			}
		})
	}
}
