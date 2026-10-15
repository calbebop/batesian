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

// cardSecServer serves card and task outcomes for the auth-contract tests.
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
		case "malformed-v1":
			sec = `"securityRequirements":["bearerAuth"],`
		case "malformed-v03":
			sec = `"security":[{"bearerAuth":"read"}],`
		case "malformed-with-anonymous":
			sec = `"securityRequirements":[{}, {"bearerAuth":null}],`
		case "undefined-scheme":
			sec = `"securityRequirements":[{"missing":[]}],`
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
			if mode == "fallback-vuln" || mode == "fallback-secure" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if (mode == "version-fallback-vuln" || mode == "version-fallback-secure") &&
				r.Header.Get("A2A-Version") == "1.0" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, card())
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/.well-known/agent.json" &&
			(mode == "fallback-vuln" || mode == "fallback-secure") {
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
		requestID, _ := id.(string)
		createProbe := strings.HasPrefix(requestID, "batesian-cardsec-send-")
		readProbe := strings.HasPrefix(requestID, "batesian-cardsec-get-")
		params, _ := req["params"].(map[string]interface{})
		hasToken := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")

		result := func(res map[string]interface{}) {
			replyID := id
			if (mode == "wrong-create-id" && createProbe) ||
				(mode == "wrong-v1-create-id" && createProbe && method == "SendMessage") ||
				(mode == "wrong-read-id" && readProbe) {
				replyID = "other-request"
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": replyID, "result": res})
		}
		rpcErr := func(code int, msg string) {
			replyID := id
			if (mode == "wrong-create-error-id" || mode == "wrong-http-error-id") && createProbe {
				replyID = "other-request"
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": replyID,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}

		// In secure mode every method requires a bearer token.
		if (mode == "secure" || mode == "fallback-secure" || mode == "version-fallback-secure") && !hasToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch method {
		case "SendMessage", "message/send":
			switch mode {
			case "wrong-create-error-id":
				rpcErr(-32000, "unauthorized")
				return
			case "wrong-http-error-id":
				w.WriteHeader(http.StatusNotFound)
				rpcErr(-32601, "Method not found")
				return
			case "setup-drop":
				if method == "SendMessage" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
					return
				}
				rpcErr(-32601, "Method not found")
				return
			case "setup-gateway", "setup-fallback-success":
				if method == "SendMessage" {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				if mode == "setup-gateway" {
					rpcErr(-32601, "Method not found")
					return
				}
			case "setup-malformed":
				if method == "SendMessage" {
					_, _ = io.WriteString(w, "not JSON")
				} else {
					rpcErr(-32601, "Method not found")
				}
				return
			case "setup-invalid-params":
				if method == "SendMessage" {
					rpcErr(-32602, "Invalid params")
				} else {
					rpcErr(-32601, "Method not found")
				}
				return
			case "setup-auth-gateway":
				if method == "SendMessage" {
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					w.WriteHeader(http.StatusBadGateway)
				}
				return
			case "setup-unsupported":
				rpcErr(-32601, "Method not found")
				return
			}
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
			if mode == "readback-gateway" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			returnedID := taskID
			if mode == "wrong-read-task" && readProbe {
				returnedID = "other-task"
			}
			result(map[string]interface{}{"id": returnedID, "contextId": "ctx-" + taskID,
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

func TestCardSecurity_MalformedRequirementsAreIncomplete(t *testing.T) {
	for _, mode := range []string{"malformed-v1", "malformed-v03", "malformed-with-anonymous", "undefined-scheme"} {
		t.Run(mode, func(t *testing.T) {
			srv := cardSecServer(mode)
			defer srv.Close()
			findings, err := runCardSec(t, srv)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "invalid Agent Card security metadata") {
				t.Fatalf("malformed declaration must not be judged as anonymous: findings=%+v err=%v", findings, err)
			}
		})
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
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("missing task ID must be incomplete: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for a result with no task id, got %d: %+v", len(findings), findings)
	}
}

func TestCardSecurity_IncompleteCreateProbeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		method string
	}{
		{"setup-drop", "SendMessage"},
		{"setup-gateway", "SendMessage"},
		{"setup-malformed", "SendMessage"},
		{"setup-invalid-params", "SendMessage"},
		{"setup-auth-gateway", "message/send"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := cardSecServer(tc.mode)
			defer srv.Close()
			findings, err := runCardSec(t, srv)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), tc.method) {
				t.Fatalf("unjudged create must be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestCardSecurity_UnsupportedCreateIsNotApplicable(t *testing.T) {
	srv := cardSecServer("setup-unsupported")
	defer srv.Close()
	findings, err := runCardSec(t, srv)
	if len(findings) != 0 || err != nil {
		t.Fatalf("explicitly unsupported methods are not applicable: findings=%+v err=%v", findings, err)
	}
}

func TestCardSecurity_FindingSurvivesFailedFirstMethod(t *testing.T) {
	srv := cardSecServer("setup-fallback-success")
	defer srv.Close()
	findings, err := runCardSec(t, srv)
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "SendMessage") {
		t.Fatalf("v0.3 finding and failed v1.0 probe must both survive: findings=%+v err=%v", findings, err)
	}
}

func TestCardSecurity_FindingRetainsUnreadableReadback(t *testing.T) {
	srv := cardSecServer("readback-gateway")
	defer srv.Close()
	findings, err := runCardSec(t, srv)
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "GetTask returned HTTP 502") ||
		!strings.Contains(err.Error(), "tasks/get returned HTTP 502") {
		t.Fatalf("finding and unreadable task readback must both survive: findings=%+v err=%v", findings, err)
	}
}

func TestCardSecurity_UnobservedPrimaryCard(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		inconclusive bool
		reason       string
	}{
		{"server error", http.StatusServiceUnavailable, true, "HTTP 503"},
		{"auth required", http.StatusUnauthorized, true, "HTTP 401"},
		{"invalid card", http.StatusOK, true, "invalid Agent Card"},
		{"path absent", http.StatusNotFound, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/agent-card.json":
					w.WriteHeader(tc.status)
				case "/.well-known/agent.json":
					_, _ = io.WriteString(w, `{"name":"Legacy Agent","url":"https://agent.example.com/"}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			findings, err := runCardSec(t, srv)
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive {
				t.Fatalf("findings=%v err=%v, want inconclusive=%v", findings, err, tc.inconclusive)
			}
			if tc.inconclusive && !strings.Contains(err.Error(), "/.well-known/agent-card.json: "+tc.reason) {
				t.Fatalf("missing failed card path: %v", err)
			}
		})
	}
}

func TestCardSecurity_FindingNotesUnobservedCard(t *testing.T) {
	srv := cardSecServer("fallback-vuln")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 1 {
		t.Fatalf("want a finding from the fallback card, got findings=%v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "/.well-known/agent-card.json: HTTP 503") {
		t.Fatalf("finding omitted failed primary read: %q", findings[0].Evidence)
	}
}

func TestCardSecurity_SecureFallbackIsIncomplete(t *testing.T) {
	srv := cardSecServer("fallback-secure")
	defer srv.Close()

	findings, err := runCardSec(t, srv)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "/.well-known/agent-card.json: HTTP 503") {
		t.Fatalf("want incomplete result for the unreadable primary card, got findings=%v err=%v", findings, err)
	}
}

func TestCardSecurity_VersionFallbackKeepsUnobservedReadIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantFindings int
	}{
		{"version-fallback-vuln", 1},
		{"version-fallback-secure", 0},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := cardSecServer(tc.mode)
			defer srv.Close()

			findings, err := runCardSec(t, srv)
			if len(findings) != tc.wantFindings || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "/.well-known/agent-card.json: HTTP 503") {
				t.Fatalf("want %d findings and incomplete versioned read, got findings=%v err=%v", tc.wantFindings, findings, err)
			}
			if tc.wantFindings > 0 && !strings.Contains(findings[0].Evidence, "/.well-known/agent-card.json: HTTP 503") {
				t.Fatalf("finding omitted failed versioned read: %q", findings[0].Evidence)
			}
		})
	}
}

func TestCardSecurity_CorrelatesProbeReplies(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantFindings int
		wantReason   string
	}{
		{"wrong-create-id", 0, "reply did not match its request ID"},
		{"wrong-create-error-id", 0, "reply did not match its request ID"},
		{"wrong-http-error-id", 0, "reply did not match its request ID"},
		{"wrong-v1-create-id", 1, "SendMessage reply did not match its request ID"},
		{"wrong-read-id", 1, "reply did not match its request ID"},
		{"wrong-read-task", 1, "returned a different task"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := cardSecServer(tc.mode)
			defer srv.Close()

			findings, err := runCardSec(t, srv)
			if len(findings) != tc.wantFindings || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("findings=%+v err=%v, want %d findings and %q", findings, err, tc.wantFindings, tc.wantReason)
			}
			if len(findings) > 0 && tc.mode != "wrong-v1-create-id" &&
				strings.Contains(findings[0].Evidence, "task returned") {
				t.Fatalf("unobserved readback appeared in evidence: %s", findings[0].Evidence)
			}
		})
	}
}
