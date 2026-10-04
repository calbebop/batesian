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

func restReadAgent(t *testing.T, mode string, legacy, dual bool) (*httptest.Server, *[]string, *sync.Mutex) {
	t.Helper()
	sendPath, taskPath := "/agent/message:send", "/agent/tasks/"
	if legacy {
		sendPath, taskPath = "/agent/v1/message:send", "/agent/v1/tasks/"
	}
	taskID := "rest-owner-task"
	if mode == "escaped-id" {
		taskID = "task/a?b"
	}
	var mu sync.Mutex
	var marker string
	var reads []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
					map[string]string{"protocolBinding": "JSONRPC", "url": "http://" + r.Host + "/"},
					map[string]string{"protocolBinding": "HTTP+JSON", "url": baseURL},
				}
			}
			if legacy {
				card = map[string]interface{}{"protocolVersion": "0.3.0", "preferredTransport": "HTTP+JSON", "url": baseURL}
			}
			writeJSON(w, card)
			return
		}
		if dual && r.Method == http.MethodPost && r.URL.Path == "/" {
			method, id := decodeRPC(r)
			switch method {
			case "SendMessage", "message/send":
				if hasOwnerAuth(r) {
					taskResult(w, id, "rpc-owner-task", "rpc-context")
				} else {
					rpcErr(w, id, -32600, "authentication required")
				}
			case "GetTask", "tasks/get":
				rpcErr(w, id, -32001, "Task not found")
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
			var body struct {
				Message struct {
					Role  string `json:"role"`
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Message.Parts) == 0 ||
				(legacy && body.Message.Role != "user") || (!legacy && body.Message.Role != "ROLE_USER") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !hasOwnerAuth(r) {
				if mode != "open" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				writeJSON(w, map[string]interface{}{"task": map[string]string{"id": "anon-task"}})
				return
			}
			mu.Lock()
			marker = body.Message.Parts[0].Text
			mu.Unlock()
			if mode == "message-only" {
				writeJSON(w, map[string]interface{}{"message": map[string]string{"messageId": "reply"}})
				return
			}
			writeJSON(w, map[string]interface{}{"task": map[string]string{"id": taskID}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), taskPath) {
			mu.Lock()
			reads = append(reads, r.Header.Get("Authorization"))
			text := marker
			mu.Unlock()
			if mode == "escaped-id" && r.URL.EscapedPath() != taskPath+"task%2Fa%3Fb" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Query().Get("historyLength") != "10" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !hasOwnerAuth(r) {
				switch mode {
				case "scoped":
					w.WriteHeader(http.StatusUnauthorized)
					return
				case "redacted":
					writeJSON(w, map[string]interface{}{"id": taskID, "history": []interface{}{}})
					return
				case "unrelated":
					writeJSON(w, map[string]interface{}{"id": "other-task", "history": []interface{}{
						map[string]interface{}{"parts": []interface{}{map[string]string{"text": text}}},
					}})
					return
				case "failed-read":
					w.WriteHeader(http.StatusInternalServerError)
					return
				case "non-json":
					_, _ = w.Write([]byte("login"))
					return
				case "method-not-allowed":
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				case "error-body":
					writeJSON(w, map[string]interface{}{"error": map[string]string{"message": "Task unavailable"}})
					return
				}
			}
			if mode == "owner-blind" {
				writeJSON(w, map[string]interface{}{"id": taskID, "history": []interface{}{}})
				return
			}
			writeJSON(w, map[string]interface{}{"id": taskID, "history": []interface{}{
				map[string]interface{}{"parts": []interface{}{map[string]string{"text": text}}},
			}})
			return
		}
		http.NotFound(w, r)
	}))
	return srv, &reads, &mu
}

func TestTaskIDOR_RESTTaskRead(t *testing.T) {
	tests := []struct {
		name, mode   string
		legacy, dual bool
		finding      bool
		inconclusive bool
	}{
		{"REST-only leak", "leak", false, false, true, false},
		{"legacy REST-only leak", "leak", true, false, true, false},
		{"dual binding REST leak", "leak", false, true, true, false},
		{"off-origin card pinned", "off-origin", false, false, true, false},
		{"task ID escaped", "escaped-id", false, false, true, false},
		{"anonymous read denied", "scoped", false, false, false, false},
		{"open creation", "open", false, false, false, false},
		{"redacted task", "redacted", false, false, false, true},
		{"unrelated task", "unrelated", false, false, false, false},
		{"owner cannot see marker", "owner-blind", false, false, false, true},
		{"anonymous read failed", "failed-read", false, false, false, true},
		{"anonymous read is not JSON", "non-json", false, false, false, true},
		{"anonymous read returned method error", "method-not-allowed", false, false, false, true},
		{"anonymous read returned JSON error", "error-body", false, false, false, true},
		{"task creation absent", "no-send", false, false, false, true},
		{"creation returned message", "message-only", false, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, reads, mu := restReadAgent(t, tc.mode, tc.legacy, tc.dual)
			defer srv.Close()
			findings, err := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001"}).
				Execute(context.Background(), srv.URL, idorOpts())
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
			if tc.finding {
				if !strings.Contains(findings[0].TargetURL, "/agent/") ||
					!strings.Contains(findings[0].Evidence, "batesian idor probe") {
					t.Fatalf("finding lacks REST task evidence: %+v", findings[0])
				}
			}
			mu.Lock()
			gotReads := append([]string(nil), (*reads)...)
			mu.Unlock()
			if tc.finding && len(gotReads) < 2 {
				t.Fatalf("owner and anonymous reads were not both exercised: %v", gotReads)
			}
		})
	}
}
