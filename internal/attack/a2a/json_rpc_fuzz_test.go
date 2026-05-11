package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func jsonRPCFuzzRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-json-rpc-fuzz-001",
		Name:        "A2A JSON-RPC Input Fuzzing",
		Severity:    "medium",
		Remediation: "Validate JSON-RPC fields and recover from panics with a generic error response.",
	}
}

// vulnerableFuzzServer returns HTTP 500 for any request whose method field is
// not a string, simulating a server that panics on type assertion.
func vulnerableFuzzServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("goroutine 1 [running]:\npanic: interface conversion\n"))
			return
		}

		method, ok := body["method"].(string)
		if !ok || method == "" {
			// Simulate a server that panics and leaks a Go stack trace.
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("goroutine 1 [running]:\npanic: interface conversion: interface {} is nil, not string\n"))
			return
		}

		// Happy path: echo a minimal JSON-RPC response.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      body["id"],
			"result":  map[string]interface{}{},
		})
	}))
}

// cleanFuzzServer always returns a spec-compliant JSON-RPC -32600 error for
// invalid requests instead of crashing.
func cleanFuzzServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      nil,
				"error":   map[string]interface{}{"code": -32700, "message": "Parse error"},
			})
			return
		}

		method, ok := body["method"].(string)
		if !ok || method == "" || body["jsonrpc"] != "2.0" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      body["id"],
				"error":   map[string]interface{}{"code": -32600, "message": "Invalid Request"},
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      body["id"],
			"result":  map[string]interface{}{},
		})
	}))
}

func TestJSONRPCFuzz_VulnerableServer(t *testing.T) {
	ts := vulnerableFuzzServer(t)
	defer ts.Close()

	exec := a2aattack.NewJSONRPCFuzzExecutor(jsonRPCFuzzRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on vulnerable fuzz server, got none")
	}

	// At least one finding should be for HTTP 5xx or stack trace.
	hasCrashOrTrace := false
	for _, f := range findings {
		if strings.Contains(f.Title, "HTTP 5") || strings.Contains(f.Title, "stack trace") {
			hasCrashOrTrace = true
		}
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("finding %q should have ConfirmedExploit confidence, got %q", f.Title, f.Confidence)
		}
	}
	if !hasCrashOrTrace {
		t.Errorf("expected a crash or stack-trace finding, got: %v", findings)
	}
}

func TestJSONRPCFuzz_StackTraceDetected(t *testing.T) {
	// Server that returns 200 but with a panic dump in the body.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`goroutine 1 [running]:
runtime error: invalid memory address or nil pointer dereference`))
	}))
	defer ts.Close()

	exec := a2aattack.NewJSONRPCFuzzExecutor(jsonRPCFuzzRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings when response contains stack trace keywords, got none")
	}
	for _, f := range findings {
		if f.Severity != "high" {
			t.Errorf("stack-trace finding should have severity high, got %q", f.Severity)
		}
	}
}

func TestJSONRPCFuzz_CleanServer(t *testing.T) {
	ts := cleanFuzzServer(t)
	defer ts.Close()

	exec := a2aattack.NewJSONRPCFuzzExecutor(jsonRPCFuzzRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on clean server, got %d: %v", len(findings), findings)
	}
}
