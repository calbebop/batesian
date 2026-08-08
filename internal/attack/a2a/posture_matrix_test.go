package a2a_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

// A negative control for the cross-principal A2A rules, in process.
//
// Three false negatives in this package were found by pointing the scanner at an
// agent that ENFORCES authorization and has one specific bug, and none of them was
// reachable from any fixture in testdata/, all of which enforce nothing. The
// scratchpad agent that found them is not in CI, so the same class could return.
//
// This runs both directions on every rule that depends on task ownership:
//
//	secured  authorization AND ownership enforced  -> every rule must be silent
//	idor     authorization enforced, ownership NOT -> the ownership rules must fire
//
// The silent half is what catches a false positive; the firing half is what catches
// a false negative, which is the half no fixture had. Reverting the v1.0 envelope fix
// in taskref.go fails the delegation case here, so this would have caught PR #176's
// defect on its own.
//
// WIRE SHAPES ARE REPRODUCED FROM CAPTURED a2a-sdk RESPONSES, not written from the
// specification and not from what these rules happen to send. The distinction
// matters: a fixture built from the scanner's own assumptions vouches for the
// scanner instead of testing it, which is how several of these defects survived.
// Specifically, and this is the shape that mattered, v1.0 SendMessage answers with
// the Task NESTED under result.task because SendMessageResponse is a protobuf oneof,
// while v1.0 GetTask answers with a bare Task, flat. The v0.3 slash methods answer
// flat with lowercase state strings.

type matrixTask struct {
	id      string
	ctxID   string
	owner   string
	state   string
	history []map[string]interface{}
}

// matrixAgent is an in-process A2A agent whose posture decides whether task
// ownership is enforced. Authorization is enforced in both.
type matrixAgent struct {
	posture string // "secured" or "idor"

	mu    sync.Mutex
	tasks map[string]*matrixTask
	n     int
}

const (
	matrixTokenA = "alice-token"
	matrixTokenB = "bob-token"
)

// principalFor returns the principal a bearer token identifies, or "" for none.
func principalFor(authz string) string {
	switch strings.TrimPrefix(authz, "Bearer ") {
	case matrixTokenA:
		return "alice"
	case matrixTokenB:
		return "bob"
	}
	return ""
}

func newMatrixAgent(t *testing.T, posture string) *httptest.Server {
	t.Helper()
	ag := &matrixAgent{posture: posture, tasks: map[string]*matrixTask{}}
	return httptest.NewServer(http.HandlerFunc(ag.serve))
}

func (a *matrixAgent) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/.well-known/") {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"Matrix Agent","description":"d","version":"1.0.0",`+
			`"protocolVersion":"1.0","capabilities":{"pushNotifications":true},"skills":[],`+
			`"supportedInterfaces":[{"url":"http://`+r.Host+`/","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`)
		return
	}

	var req map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&req)
	method, _ := req["method"].(string)
	params, _ := req["params"].(map[string]interface{})
	id := req["id"]

	// Authorization first, in both postures, and exactly as the SDK agent answered
	// it: HTTP 401 with a JSON body that is not a JSON-RPC envelope.
	caller := principalFor(r.Header.Get("Authorization"))
	if caller == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthenticated","message":"a valid bearer token is required"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "SendMessage", "message/send":
		a.send(w, id, params, caller, method == "SendMessage")
	case "GetTask", "tasks/get":
		a.get(w, id, params, caller, method == "GetTask")
	case "CancelTask", "tasks/cancel":
		a.cancel(w, id, params, caller, method == "CancelTask")
	case "CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set":
		a.setPush(w, id, params, caller)
	default:
		rpcError(w, id, -32601, "method not found")
	}
}

// mayTouch reports whether caller is allowed to act on t. The postures differ here
// and nowhere else, which is what makes a diff between them meaningful.
func (a *matrixAgent) mayTouch(t *matrixTask, caller string) bool {
	if a.posture == "idor" {
		return true // any authenticated caller: the bug under test
	}
	return t.owner == caller
}

func (a *matrixAgent) send(w http.ResponseWriter, id, params interface{}, caller string, v1 bool) {
	p, _ := params.(map[string]interface{})
	msg, _ := p["message"].(map[string]interface{})
	taskID, _ := msg["taskId"].(string)

	a.mu.Lock()
	defer a.mu.Unlock()

	if taskID != "" {
		// A continuation. The SDK returns the referenced task rather than appending,
		// logging "Task already exists. Ignoring task replacement." Reproduced as
		// observed: what the rules judge is whether the reply references A's task.
		t, ok := a.tasks[taskID]
		if !ok {
			rpcError(w, id, -32001, "Task not found")
			return
		}
		if !a.mayTouch(t, caller) {
			rpcError(w, id, -32600, "not authorized for this task")
			return
		}
		a.writeTask(w, id, t, v1, true)
		return
	}

	a.n++
	t := &matrixTask{
		id:    fmt.Sprintf("task-%d", a.n),
		ctxID: fmt.Sprintf("ctx-%d", a.n),
		owner: caller,
		state: "submitted",
	}
	if msg != nil {
		t.history = append(t.history, msg)
	}
	a.tasks[t.id] = t
	a.writeTask(w, id, t, v1, true)
}

func (a *matrixAgent) get(w http.ResponseWriter, id, params interface{}, caller string, v1 bool) {
	p, _ := params.(map[string]interface{})
	taskID, _ := p["id"].(string)

	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tasks[taskID]
	if !ok {
		rpcError(w, id, -32001, "Task not found")
		return
	}
	if !a.mayTouch(t, caller) {
		rpcError(w, id, -32600, "not authorized for this task")
		return
	}
	// GetTask answers with a bare Task even on v1.0, so never nested.
	a.writeTask(w, id, t, v1, false)
}

func (a *matrixAgent) cancel(w http.ResponseWriter, id, params interface{}, caller string, v1 bool) {
	p, _ := params.(map[string]interface{})
	taskID, _ := p["id"].(string)

	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tasks[taskID]
	if !ok {
		rpcError(w, id, -32001, "Task not found")
		return
	}
	if !a.mayTouch(t, caller) {
		rpcError(w, id, -32600, "not authorized for this task")
		return
	}
	t.state = "canceled"
	a.writeTask(w, id, t, v1, false)
}

func (a *matrixAgent) setPush(w http.ResponseWriter, id, params interface{}, caller string) {
	p, _ := params.(map[string]interface{})
	taskID, _ := p["taskId"].(string)

	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tasks[taskID]
	if !ok {
		rpcError(w, id, -32001, "Task not found")
		return
	}
	if !a.mayTouch(t, caller) {
		rpcError(w, id, -32600, "not authorized for this task")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]interface{}{"taskId": t.id, "url": "set", "token": "set"},
	})
}

// writeTask emits a Task in the envelope the method actually uses. nest is true
// only for v1.0 send-style replies, where SendMessageResponse is a oneof.
func (a *matrixAgent) writeTask(w http.ResponseWriter, id interface{}, t *matrixTask, v1, nest bool) {
	state := t.state
	if v1 {
		state = "TASK_STATE_" + strings.ToUpper(t.state)
	}
	task := map[string]interface{}{
		"id":        t.id,
		"contextId": t.ctxID,
		"status":    map[string]interface{}{"state": state},
		"history":   t.history,
	}
	if !v1 {
		task["kind"] = "task"
	}
	result := interface{}(task)
	if v1 && nest {
		result = map[string]interface{}{"task": task}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": result,
	})
}

func rpcError(w http.ResponseWriter, id interface{}, code int, msg string) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]interface{}{"code": code, "message": msg},
	})
}

// matrixOpts gives both a --token and two principals, because the rules split on
// which they use: task-idor reads opts.Token, the cross-principal rules read
// Principals.
func matrixOpts() attack.Options {
	return attack.Options{
		TimeoutSeconds: 5,
		Token:          matrixTokenA,
		Principals: []attack.Principal{
			{Name: "a", Token: matrixTokenA, Tenant: "A"},
			{Name: "b", Token: matrixTokenB, Tenant: "B"},
		},
	}
}

// The matrix. wantFires says whether the rule must report a finding against a given
// posture; anything else is a defect in one direction or the other.
func TestA2APostureMatrix(t *testing.T) {
	rules := []struct {
		id    string
		build func(attack.RuleContext) attack.Executor
		// Ownership-sensitive rules must fire on idor and stay silent on secured.
		ownershipSensitive bool
	}{
		{"a2a-multitenant-isolation-001", func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewMultiTenantIsolationExecutor(rc)
		}, true},
		{"a2a-delegation-integrity-001", func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewDelegationIntegrityExecutor(rc)
		}, true},
		{"a2a-task-cancel-idor-001", func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewTaskCancelIDORExecutor(rc)
		}, true},
		{"a2a-push-binding-001", func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewPushBindingExecutor(rc)
		}, true},
		// Not ownership-sensitive: its oracle is an ANONYMOUS read, which both
		// postures refuse. It is here as a false-positive control, since it is the
		// rule most likely to be tripped by a cross-principal fixture.
		{"a2a-task-idor-001", func(rc attack.RuleContext) attack.Executor {
			return a2aattack.NewTaskIDORExecutor(rc)
		}, false},
	}

	for _, posture := range []string{"secured", "idor"} {
		for _, r := range rules {
			t.Run(posture+"/"+r.id, func(t *testing.T) {
				srv := newMatrixAgent(t, posture)
				defer srv.Close()

				exec := r.build(attack.RuleContext{ID: r.id, Severity: "high"})
				findings, err := exec.Execute(context.Background(), srv.URL, matrixOpts())

				wantFires := posture == "idor" && r.ownershipSensitive
				switch {
				case wantFires && len(findings) == 0:
					t.Fatalf("this agent lets any authenticated caller act on another "+
						"principal's task, so this rule must fire; got 0 findings, err=%v", err)
				case !wantFires && len(findings) != 0:
					t.Fatalf("expected no findings against the %s posture, got %d: %+v",
						posture, len(findings), findings)
				}
				if !wantFires && err != nil {
					// Setup succeeded on both postures, so a rule that reports nothing
					// here has genuinely tested and found nothing.
					t.Errorf("expected a clean result, got err=%v", err)
				}
			})
		}
	}
}

// The harness has to be able to fail. Ownership enforcement is the only difference
// between the two postures, so if the secured posture does not actually refuse a
// cross-principal read the matrix proves nothing about either direction.
func TestA2APostureMatrix_PosturesDiffer(t *testing.T) {
	for _, tc := range []struct {
		posture   string
		wantAllow bool
	}{{"secured", false}, {"idor", true}} {
		t.Run(tc.posture, func(t *testing.T) {
			srv := newMatrixAgent(t, tc.posture)
			defer srv.Close()

			// alice creates a task, bob reads it.
			created := matrixPost(t, srv.URL, matrixTokenA, map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "message/send",
				"params": map[string]interface{}{"message": map[string]interface{}{
					"role": "user", "messageId": "m1",
					"parts": []interface{}{map[string]string{"kind": "text", "text": "hi"}},
				}},
			})
			result, _ := created["result"].(map[string]interface{})
			taskID, _ := result["id"].(string)
			if taskID == "" {
				t.Fatalf("no task created: %v", created)
			}

			read := matrixPost(t, srv.URL, matrixTokenB, map[string]interface{}{
				"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
				"params": map[string]interface{}{"id": taskID},
			})
			_, allowed := read["result"]
			if allowed != tc.wantAllow {
				t.Errorf("posture %s: cross-principal read allowed=%v, want %v (%v)",
					tc.posture, allowed, tc.wantAllow, read)
			}
		})
	}
}

// v1.0 send replies must be nested and v1.0 GetTask replies flat, or the matrix is
// testing a wire no implementation serves. This is the shape that hid a false
// negative for as long as it did.
func TestA2APostureMatrix_V1EnvelopeShapes(t *testing.T) {
	srv := newMatrixAgent(t, "idor")
	defer srv.Close()

	sent := matrixPost(t, srv.URL, matrixTokenA, map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
		"params": map[string]interface{}{"message": map[string]interface{}{
			"role": 1, "messageId": "m1",
			"parts": []interface{}{map[string]string{"text": "hi"}},
		}},
	})
	result, _ := sent["result"].(map[string]interface{})
	nested, ok := result["task"].(map[string]interface{})
	if !ok {
		t.Fatalf("v1.0 SendMessage must nest the task under result.task, got %v", result)
	}
	taskID, _ := nested["id"].(string)

	got := matrixPost(t, srv.URL, matrixTokenA, map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "GetTask",
		"params": map[string]interface{}{"id": taskID},
	})
	gotResult, _ := got["result"].(map[string]interface{})
	if _, nestedGet := gotResult["task"]; nestedGet {
		t.Errorf("v1.0 GetTask returns a bare Task, so it must not be nested: %v", gotResult)
	}
	if gotResult["id"] != taskID {
		t.Errorf("GetTask should answer flat with the task id, got %v", gotResult)
	}
}

// matrixPost sends one JSON-RPC request and returns the decoded reply.
func matrixPost(t *testing.T, url, token string, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}
