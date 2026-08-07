package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
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

// cardSecServer builds a mock A2A server whose AgentCard security declaration and
// JSON-RPC auth behavior depend on mode:
//   - "vuln-v1":      card declares securityRequirements in the real v1.0 wire
//     shape (names nested under "schemes"), but message/send is served
//     unauthenticated => finding.
//   - "vuln-v1-flat":  the same field carrying the OpenAPI-flat shape, which a
//     server that hand-rolls its card may serve => finding.
//   - "vuln-v03":     same, but the card uses the v0.3 "security" field => finding
//     (proves both field spellings are read).
//   - "secure":       card declares required auth and the server enforces it
//     (401 without a token) => silent.
//   - "anon-allowed": card requirement list includes an empty {} object, so
//     anonymous access is explicitly permitted; even though the endpoint is open,
//     it must not be flagged => silent.
//   - "anon-allowed-v1": the v1.0 spelling of the same statement, an entry whose
//     "schemes" map is empty => silent.
//   - "no-security":  card declares no security requirement; the open endpoint is
//     not a broken promise => silent.
//   - "not-a2a":      no card, everything 404 => inconclusive.
func cardSecServer(mode string) *httptest.Server {
	var mu sync.Mutex
	store := map[string]bool{}
	counter := 0

	card := func() string {
		var sec string
		switch mode {
		case "vuln-v03":
			sec = `"security":[{"bearerAuth":[]}],`
		case "vuln-v1-flat":
			sec = `"securityRequirements":[{"bearerAuth":[]}],`
		case "anon-allowed":
			sec = `"securityRequirements":[{},{"bearerAuth":[]}],`
		case "anon-allowed-v1":
			sec = `"securityRequirements":[{"schemes":{}}],`
		case "no-security":
			sec = ``
		default: // vuln-v1, secure
			// The shape both official SDKs serve: SecurityRequirement is a
			// proto message holding one map field, so the scheme names sit a
			// level below the entry.
			sec = `"securityRequirements":[{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}],`
		}
		return `{
			"name": "Card Security Test Agent",
			"description": "test",
			"version": "1.0.0",
			"capabilities": {},
			"skills": [],
			"securitySchemes": {"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
			` + sec + `
			"defaultInputModes": ["text/plain"],
			"defaultOutputModes": ["text/plain"]
		}`
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "not-a2a" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, card())
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})
		hasToken := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")

		result := func(res map[string]interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": res})
		}
		rpcErr := func(code int, msg string) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}

		// In secure mode every method requires a bearer token.
		if mode == "secure" && !hasToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch method {
		case "SendMessage", "message/send":
			if mode == "result-no-taskid" {
				// A result envelope that carries no task id: not a confirmable
				// task creation, so the rule must not fire.
				result(map[string]interface{}{"status": map[string]interface{}{"state": "submitted"}})
				return
			}
			mu.Lock()
			counter++
			tid := fmt.Sprintf("task-%d", counter)
			store[tid] = true
			mu.Unlock()
			result(map[string]interface{}{"id": tid, "contextId": "ctx-" + tid,
				"status": map[string]interface{}{"state": "submitted"}})
		case "GetTask", "tasks/get":
			taskID, _ := params["id"].(string)
			mu.Lock()
			exists := store[taskID]
			mu.Unlock()
			if !exists {
				rpcErr(-32001, "Task not found")
				return
			}
			result(map[string]interface{}{"id": taskID, "contextId": "ctx-" + taskID,
				"status": map[string]interface{}{"state": "submitted"}})
		default:
			rpcErr(-32601, "method not found")
		}
	}))
}

func runCardSec(t *testing.T, srv *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	exec := a2aattack.NewCardSecurityUnenforcedExecutor(attack.RuleContext{
		ID:   "a2a-card-security-unenforced-001",
		Name: "A2A Agent Card Declares Authentication That Is Not Enforced",
	})
	return exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
}

// TestCardSecurity_VulnV1: v1.0 card requires auth but message/send is open => finding.
func TestCardSecurity_VulnV1(t *testing.T) {
	srv := cardSecServer("vuln-v1")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("expected high/confirmed, got %q/%v", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "declares required authentication") {
		t.Errorf("unexpected title %q", f.Title)
	}
	// The scheme name is the actionable part of the finding: it tells an operator
	// which scheme their server failed to enforce. On the real v1.0 shape the
	// names sit under "schemes", and reading the entry's own keys reported the
	// literal "schemes" on every v1.0 card in existence.
	if !strings.Contains(f.Evidence, "bearerAuth") {
		t.Errorf("evidence must name the declared scheme, got:\n%s", f.Evidence)
	}
	if strings.Contains(f.Evidence, "scheme(s): schemes") {
		t.Errorf("evidence named the proto field instead of the scheme:\n%s", f.Evidence)
	}
}

// TestCardSecurity_VulnV1FlatShape: a server that hand-rolls its card may put the
// names at the top level under the v1.0 field name. Both shapes must be read, so
// fixing the nested shape must not lose this one.
func TestCardSecurity_VulnV1FlatShape(t *testing.T) {
	srv := cardSecServer("vuln-v1-flat")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "bearerAuth") {
		t.Errorf("evidence must name the declared scheme, got:\n%s", findings[0].Evidence)
	}
}

// TestCardSecurity_VulnV03: the v0.3 "security" field must be read, not only the
// v1.0 "securityRequirements".
func TestCardSecurity_VulnV03(t *testing.T) {
	srv := cardSecServer("vuln-v03")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a v0.3 secured-but-open card, got %d: %+v", len(findings), findings)
	}
}

// TestCardSecurity_Secure: card requires auth and the server enforces it => silent.
func TestCardSecurity_Secure(t *testing.T) {
	srv := cardSecServer("secure")
	defer srv.Close()

	if findings, err := runCardSec(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err when auth is enforced, got %d findings, err=%v", len(findings), err)
	}
}

// TestCardSecurity_AnonymousAllowed: an empty {} requirement object permits
// anonymous access, so an open endpoint must not be flagged.
func TestCardSecurity_AnonymousAllowed(t *testing.T) {
	srv := cardSecServer("anon-allowed")
	defer srv.Close()

	if findings, err := runCardSec(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err when the card permits anonymous access, got %d findings, err=%v", len(findings), err)
	}
}

// TestCardSecurity_AnonymousAllowedV1: the v1.0 spelling of "anonymous is
// permitted" is an entry whose schemes map is empty, since a proto message
// always carries its map field. Reading the entry's own keys saw one key and
// called auth required, which would flag an open endpoint the card never
// promised to protect.
func TestCardSecurity_AnonymousAllowedV1(t *testing.T) {
	srv := cardSecServer("anon-allowed-v1")
	defer srv.Close()

	if findings, err := runCardSec(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err when the v1.0 card permits anonymous access, got %d findings, err=%v",
			len(findings), err)
	}
}

// TestCardSecurity_NoSecurity: card declares no requirement, so an open endpoint
// is not a broken promise.
func TestCardSecurity_NoSecurity(t *testing.T) {
	srv := cardSecServer("no-security")
	defer srv.Close()

	if findings, err := runCardSec(t, srv); err != nil || len(findings) != 0 {
		t.Errorf("expected 0 findings / nil err when the card declares no security, got %d findings, err=%v", len(findings), err)
	}
}

// TestCardSecurity_NotA2A: no card / no endpoint => inconclusive.
func TestCardSecurity_NotA2A(t *testing.T) {
	srv := cardSecServer("not-a2a")
	defer srv.Close()

	_, err := runCardSec(t, srv)
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive for a non-A2A endpoint, got err=%v", err)
	}
}

// TestCardSecurity_ResultWithoutTaskID: an unauthenticated message/send that
// returns a result envelope carrying no task id is not a confirmable task
// creation, so the rule must not fire. Previously a bare "result" substring
// promoted this to a confirmed finding with an empty task id.
func TestCardSecurity_ResultWithoutTaskID(t *testing.T) {
	srv := cardSecServer("result-no-taskid")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for a result with no task id, got %d: %+v", len(findings), findings)
	}
}
