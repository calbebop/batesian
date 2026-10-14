package a2a_test

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
	"github.com/calbebop/batesian/internal/attack/a2a"
)

const reqExtURI = "https://ext.example/required-policy/v1"

// extensionServer models an A2A server whose card declares reqExtURI as a
// required extension. mode controls enforcement:
//   - "failopen": SendMessage is accepted whether or not the header is present.
//   - "failclosed": SendMessage without the A2A-Extensions header is rejected.
//   - "noauth-msg": SendMessage is always rejected (control can't succeed).
func extensionServer(mode string, required bool) *httptest.Server {
	mux := http.NewServeMux()
	card := map[string]interface{}{
		"name": "Ext Agent",
		"url":  "https://agent.example/",
		"capabilities": map[string]interface{}{
			"extensions": []interface{}{
				map[string]interface{}{"uri": reqExtURI, "required": required},
			},
		},
	}
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		if mode == "unreadable-card" || mode == "primary-failed-fallback" || mode == "primary-failed-fallback-closed" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	mux.HandleFunc("/.well-known/agent.json", func(w http.ResponseWriter, r *http.Request) {
		if mode == "legacy-failed" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if mode != "primary-failed-fallback" && mode != "primary-failed-fallback-closed" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		// Model a v1.0 server: activation is read from the A2A-Extensions header.
		activated := strings.Contains(r.Header.Get("A2A-Extensions"), reqExtURI)
		var request map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&request)
		reqID := request["id"]
		writeRPC := func(result interface{}) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID, "result": result})
		}
		writeErr := func(code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": reqID,
				"error": map[string]interface{}{"code": code, "message": msg}})
		}
		if request["method"] == "GetTask" || request["method"] == "tasks/get" {
			writeErr(-32001, "Task not found")
			return
		}
		if mode == "control-fallback-open" && request["method"] == "SendMessage" && activated {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch mode {
		case "noauth-msg":
			writeErr(-32600, "authentication required")
		case "failclosed", "failclosed-http", "primary-failed-fallback-closed":
			if !activated {
				if mode == "failclosed-http" {
					w.WriteHeader(http.StatusBadRequest)
				}
				writeErr(-32008, "extension support required")
				return
			}
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		case "omitted-generic":
			if !activated {
				writeErr(-32600, "invalid request")
				return
			}
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		case "omitted-transport":
			if !activated {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		case "omitted-wrong-id":
			if !activated {
				rpcErr(w, "other-request", -32008, "extension support required")
				return
			}
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		case "omitted-service-error", "omitted-rate-limit", "omitted-timeout":
			if !activated {
				status := http.StatusServiceUnavailable
				switch mode {
				case "omitted-rate-limit":
					status = http.StatusTooManyRequests
				case "omitted-timeout":
					status = http.StatusRequestTimeout
				}
				w.WriteHeader(status)
				writeErr(-32008, "extension support required")
				return
			}
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		default: // failopen
			writeRPC(map[string]interface{}{"id": "task-1", "contextId": "ctx-1", "status": "working"})
		}
	})
	return httptest.NewServer(mux)
}

func runExtDowngrade(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestExtDowngrade_FailOpen: required extension declared, server accepts both
// with and without the activation header => confirmed downgrade.
func TestExtDowngrade_FailOpen(t *testing.T) {
	ts := extensionServer("failopen", true)
	defer ts.Close()

	f := onlyFinding(t, runExtDowngrade(t, ts))
	if f.Confidence != attack.ConfirmedExploit || f.Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestExtDowngrade_FailClosed: server rejects requests that omit the required
// extension => secure, no finding.
func TestExtDowngrade_FailClosed(t *testing.T) {
	for _, mode := range []string{"failclosed", "failclosed-http"} {
		t.Run(mode, func(t *testing.T) {
			ts := extensionServer(mode, true)
			defer ts.Close()
			exec := a2a.NewExtensionDowngradeExecutor(testRuleCtx())
			findings, err := exec.Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if err != nil || len(findings) != 0 {
				t.Errorf("expected a clean result against a fail-closed server, got %d findings, err=%v", len(findings), err)
			}
		})
	}
}

func TestExtDowngrade_IncompleteOmission(t *testing.T) {
	for _, mode := range []string{"omitted-generic", "omitted-transport", "omitted-wrong-id",
		"omitted-service-error", "omitted-rate-limit", "omitted-timeout"} {
		t.Run(mode, func(t *testing.T) {
			ts := extensionServer(mode, true)
			defer ts.Close()
			findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
				context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("expected an incomplete result, got %d findings, err=%v", len(findings), err)
			}
		})
	}
}

func TestExtDowngrade_UnreadableCard(t *testing.T) {
	ts := extensionServer("unreadable-card", true)
	defer ts.Close()
	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected an incomplete result, got %d findings, err=%v", len(findings), err)
	}
}

func TestExtDowngrade_InvalidNestedCapabilitiesAreIncomplete(t *testing.T) {
	for _, body := range []string{
		`{"capabilities":{"extensions":"invalid"}}`,
		`{"capabilities":{"extensions":[{"uri":"https://example.test/ext","required":"true"}]}}`,
		`{"capabilities":{"extensions":[{"required":true}]}}`,
	} {
		t.Run(body, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()
			findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
				context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "capabilities.extensions") {
				t.Fatalf("malformed card treated as clean: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestExtDowngrade_PartialCardReadIsInconclusive(t *testing.T) {
	for _, mode := range []string{"primary-failed-fallback", "legacy-failed"} {
		t.Run(mode, func(t *testing.T) {
			ts := extensionServer(mode, false)
			defer ts.Close()
			findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
				context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "HTTP 503") {
				t.Fatalf("want incomplete card read, got findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestExtDowngrade_FindingNotesUnobservedCard(t *testing.T) {
	ts := extensionServer("primary-failed-fallback", true)
	defer ts.Close()
	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(findings[0].Evidence, "/.well-known/agent-card.json: HTTP 503") {
		t.Fatalf("finding and failed card read must both survive: findings=%+v err=%v", findings, err)
	}
}

func TestExtDowngrade_FindingRetainsIncompleteControlVersion(t *testing.T) {
	ts := extensionServer("control-fallback-open", true)
	defer ts.Close()
	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 1 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("finding and failed control version must both survive: findings=%+v err=%v", findings, err)
	}
}

func TestExtDowngrade_FallbackClosedIsInconclusive(t *testing.T) {
	ts := extensionServer("primary-failed-fallback-closed", true)
	defer ts.Close()
	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(
		context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
		!strings.Contains(err.Error(), "/.well-known/agent-card.json: HTTP 503") {
		t.Fatalf("want incomplete primary card read, got findings=%+v err=%v", findings, err)
	}
}

// TestExtDowngrade_NotRequired: extension present but not marked required =>
// nothing to downgrade, no finding.
func TestExtDowngrade_NotRequired(t *testing.T) {
	ts := extensionServer("failopen", false)
	defer ts.Close()

	if findings := runExtDowngrade(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when no extension is required, got %d", len(findings))
	}
}

// TestExtDowngrade_ControlRejected keeps an untested control incomplete.
func TestExtDowngrade_ControlRejected(t *testing.T) {
	ts := extensionServer("noauth-msg", true)
	defer ts.Close()

	exec := a2a.NewExtensionDowngradeExecutor(testRuleCtx())
	findings, err := exec.Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("expected an incomplete result when control is rejected, got %d findings, err=%v", len(findings), err)
	}
}

// TestExtDowngrade_NotACardServer: no card at all means nothing identified as an
// A2A agent, which is different from an agent whose card declares no required
// extension. The first was not tested; only the second is clean.
func TestExtDowngrade_NotACardServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	findings, err := a2a.NewExtensionDowngradeExecutor(testRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive against a non-card server, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a non-card server, got %d", len(findings))
	}
}

// TestExtDowngrade_SendsModernHeader asserts the activation control request
// carries the v1.0 A2A-Extensions header (and the legacy X-A2A-Extensions name
// for older servers). Guards against regressing to the deprecated name only.
func TestExtDowngrade_SendsModernHeader(t *testing.T) {
	// atomic: the handler runs on the server's goroutine while the assertions
	// run on the test goroutine; loopback socket I/O is not a happens-before edge.
	var gotModern, gotLegacy atomic.Bool
	card := map[string]interface{}{
		"name": "Ext Agent",
		"url":  "https://agent.example/",
		"capabilities": map[string]interface{}{
			"extensions": []interface{}{map[string]interface{}{"uri": reqExtURI, "required": true}},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("A2A-Extensions"), reqExtURI) {
			gotModern.Store(true)
		}
		if strings.Contains(r.Header.Get("X-A2A-Extensions"), reqExtURI) {
			gotLegacy.Store(true)
		}
		var b map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["method"] == "GetTask" || b["method"] == "tasks/get" {
			rpcErr(w, b["id"], -32001, "Task not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": b["id"], "result": map[string]interface{}{"id": "task-1"},
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Fail-open server: the rule fires, and the control must have activated the
	// extension via both header names.
	if findings := runExtDowngrade(t, ts); len(findings) == 0 {
		t.Fatal("expected a finding against a fail-open server")
	}
	if !gotModern.Load() {
		t.Error("activation control did not send the A2A-Extensions header")
	}
	if !gotLegacy.Load() {
		t.Error("activation control did not send the legacy X-A2A-Extensions header")
	}
}
