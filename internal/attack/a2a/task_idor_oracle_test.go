package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// Two defects in a2a-task-idor-001, both of which the existing suite could not see.
//
// The read oracle was ContainsAny(`"history"`, `"contextId"`, taskID, contextID).
// ContainsAny is OR and the first two are key names present in virtually every A2A
// Task envelope, so it reduced to "the caller got some accepted result". taskref.go
// removed this exact expression from two sibling rules and documents it as a live
// false positive; this rule was the third instance.
//
// The tasks/list probe guessed vars.BaseURL+"/v1/tasks" and +"/tasks". endpoint.go
// states plainly that the REST prefix cannot be guessed, and resolveHTTPJSONBase
// exists for it and is used by push_ssrf.go.

// redactingAgent gates task creation, and answers an unauthenticated GetTask with a
// 200 carrying a Task stub that discloses NOTHING: no id, no contextId, empty
// history. That is a server refusing to expose the task while still speaking A2A.
//
// It must produce no finding. Under the old needles the literal `"contextId"` key
// matched and the rule reported high/confirmed, printing the owner's real taskId and
// contextId in the evidence as though the server had returned them.
func redactingAgent(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"protocolVersion": "0.3.0", "name": "redacting", "description": "d",
				"url": "http://" + r.Host + "/", "preferredTransport": "JSONRPC",
				"version": "1.0", "capabilities": map[string]interface{}{},
				"defaultInputModes": []string{"text"}, "defaultOutputModes": []string{"text"},
				"skills": []interface{}{},
			})
			return
		}
		method, id := decodeRPC(r)
		w.Header().Set("Content-Type", "application/json")
		enc := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": v,
			})
		}

		switch method {
		case "SendMessage", "message/send":
			if !hasOwnerAuth(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			enc(map[string]interface{}{"task": map[string]interface{}{
				"id": "task-owner-1", "contextId": "ctx-owner-1",
				"status": map[string]interface{}{"state": "working"},
			}})
		case "GetTask", "tasks/get":
			if hasOwnerAuth(r) {
				enc(map[string]interface{}{
					"id": "task-owner-1", "contextId": "ctx-owner-1",
					"status":  map[string]interface{}{"state": "working"},
					"history": []interface{}{map[string]interface{}{"role": "user"}},
				})
				return
			}
			// Anonymous: a Task-shaped envelope that discloses nothing at all.
			enc(map[string]interface{}{
				"id": "", "contextId": "",
				"status":  map[string]interface{}{"state": "unknown"},
				"history": []interface{}{},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
}

// A redacted stub is not a disclosure. The identifiers the rule would print are its
// own, so matching on key names manufactured the evidence.
func TestA2ATaskIDOR_RedactedStubIsNotADisclosure(t *testing.T) {
	ts := redactingAgent(t)
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001"}).
		Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("the agent answered every probe, so this is a tested clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("an envelope carrying neither the task id nor the context id disclosed "+
			"nothing; got %d finding(s): %+v", len(findings), findings)
	}
}

// The same agent, but the anonymous read really does return the owner's task. The
// oracle must still fire, or the fix above would have been bought by breaking the rule.
func TestA2ATaskIDOR_RealDisclosureStillFires(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"protocolVersion": "0.3.0", "name": "leaky", "description": "d",
				"url": "http://" + r.Host + "/", "preferredTransport": "JSONRPC",
				"version": "1.0", "capabilities": map[string]interface{}{},
				"defaultInputModes": []string{"text"}, "defaultOutputModes": []string{"text"},
				"skills": []interface{}{},
			})
			return
		}
		method, id := decodeRPC(r)
		w.Header().Set("Content-Type", "application/json")
		enc := func(v map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": v,
			})
		}
		switch method {
		case "SendMessage", "message/send":
			if !hasOwnerAuth(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			enc(map[string]interface{}{"task": map[string]interface{}{
				"id": "task-owner-1", "contextId": "ctx-owner-1",
				"status": map[string]interface{}{"state": "working"},
			}})
		case "GetTask", "tasks/get":
			// Hands the owner's task to anyone: the real defect.
			enc(map[string]interface{}{
				"id": "task-owner-1", "contextId": "ctx-owner-1",
				"status":  map[string]interface{}{"state": "working"},
				"history": []interface{}{map[string]interface{}{"role": "user"}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001"}).
		Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("an anonymous read that returned the owner's task IS the finding, got %d: %+v",
			len(findings), findings)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %s/%s", findings[0].Severity, findings[0].Confidence)
	}
}

// restMountedAgent serves its HTTP+JSON binding under a prefix the card declares, and
// leaks every task from GET {prefix}/v1/tasks to an anonymous caller. Nothing answers
// at the target root, so a rule that guesses vars.BaseURL+"/v1/tasks" finds nothing.
func restMountedAgent(t *testing.T, prefix string, hits *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits = append(*hits, r.URL.Path)
		mu.Unlock()

		if strings.Contains(r.URL.Path, "/.well-known/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"protocolVersion": "1.0", "name": "rest-mounted", "description": "d",
				"version": "1.0", "capabilities": map[string]interface{}{},
				"defaultInputModes": []string{"text"}, "defaultOutputModes": []string{"text"},
				"skills": []interface{}{},
				"supportedInterfaces": []interface{}{
					map[string]interface{}{
						"transport": "JSONRPC", "url": "http://" + r.Host + "/",
					},
					map[string]interface{}{
						"transport": "HTTP+JSON", "url": "http://" + r.Host + prefix,
					},
				},
			})
			return
		}

		// The leak, only under the advertised prefix.
		if r.Method == http.MethodGet && r.URL.Path == prefix+"/v1/tasks" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tasks": []interface{}{
					map[string]interface{}{"id": "task-1", "contextId": "ctx-1"},
					map[string]interface{}{"id": "task-2", "contextId": "ctx-2"},
				},
			})
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The JSON-RPC surface implements nothing, so only the REST probe can find
		// anything here.
		_, id := decodeRPC(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
		})
	}))
}

// The strongest finding this rule can emit must be reachable at the base the CARD
// declares, not only at two guessed paths off the target root.
func TestA2ATaskIDOR_RESTBaseComesFromTheCard(t *testing.T) {
	var hits []string
	const prefix = "/agents/finance"
	ts := restMountedAgent(t, prefix, &hits)
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001"}).
		Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("the REST listing answered, so the rule reached a testable surface: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("an anonymous REST listing returning 2 tasks is the critical finding; got %d: %+v\n"+
			"paths probed: %v", len(findings), findings, hits)
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("want critical, got %s", f.Severity)
	}
	if !strings.Contains(f.TargetURL, prefix) {
		t.Errorf("the finding should name the advertised REST base, got %q", f.TargetURL)
	}
	// The probe must actually have gone to the advertised prefix.
	var probedPrefix bool
	for _, p := range hits {
		if p == prefix+"/v1/tasks" {
			probedPrefix = true
		}
	}
	if !probedPrefix {
		t.Errorf("the advertised REST base was never probed; paths seen: %v", hits)
	}
}

// The guessed paths remain a fallback, so an agent that advertises no HTTP+JSON
// interface but serves one at the root is still found.
func TestA2ATaskIDOR_RootFallbackStillProbed(t *testing.T) {
	var hits []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if strings.Contains(r.URL.Path, "/.well-known/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/tasks" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tasks": []interface{}{map[string]interface{}{"id": "task-1", "contextId": "ctx-1"}},
			})
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, id := decodeRPC(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
		})
	}))
	defer ts.Close()

	findings, err := a2a.NewTaskIDORExecutor(attack.RuleContext{ID: "a2a-task-idor-001"}).
		Execute(context.Background(), ts.URL, idorOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("the root fallback must still be probed; got %d: %+v (paths: %v)",
			len(findings), findings, hits)
	}
}
