package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func entropyRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-task-id-entropy-001",
		Name:        "MCP Task Handle Entropy",
		Severity:    "high",
		Remediation: "Generate handles from a CSPRNG; never serialize counters.",
	}
}

type entropyStyle string

const (
	styleSequential entropyStyle = "sequential"
	styleLowAlpha   entropyStyle = "low-alpha"
	styleUUID       entropyStyle = "uuid"
)

// entropyServer advertises one task-capable read-only tool and mints handles
// in the configured style on every task-augmented tools/call.
type entropyServer struct {
	style entropyStyle
}

func (s *entropyServer) nextHandle(callIdx int) string {
	switch s.style {
	case styleSequential:
		return fmt.Sprintf("%d", 100001+callIdx*7)
	case styleLowAlpha:
		// Letter-anchored so the handle is never all digits (the sequence
		// check must stay out of this posture), and thin: 8 positions over
		// a narrow alphabet lands far under the bit bar.
		return fmt.Sprintf("k%07x", callIdx+0x1000)
	default:
		// uuid-shaped: 32 hex chars, dashes in the canonical spots.
		h := fmt.Sprintf("%032x", callIdx+0xdeadbeefcafe)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
}

func (s *entropyServer) handler() http.HandlerFunc {
	callCount := 0
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
			Params struct {
				Task map[string]interface{} `json:"task"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-te")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "entropy-fixture", "version": "1"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": []map[string]interface{}{{
					"name":        "wait_a_moment",
					"annotations": map[string]interface{}{"readOnlyHint": true},
					"execution":   map[string]interface{}{"taskSupport": "optional"},
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
						"required":   []interface{}{},
					},
				}}},
			})
		case "tools/call":
			if req.Params.Task == nil {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32602, "message": "task augmentation required"},
				})
				return
			}
			handle := s.nextHandle(callCount)
			callCount++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"task":    map[string]interface{}{"taskId": handle, "status": "working"},
					"isError": false,
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}
}

func runEntropy(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewTaskIDEntropyExecutor(entropyRC()).
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
}

// TestEntropy_SequentialFiresHigh: counter-minted handles with a constant
// stride. The next id is demonstrated; the high sequential finding MUST fire.
// The thin numeric alphabet will additionally trip the entropy check - both
// readings are true and independent, so exact-count assertions would only
// couple two detectors that are meant to be judged separately.
func TestEntropy_SequentialFiresHigh(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{style: styleSequential}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var seq *attack.Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "sequential integers") {
			seq = &findings[i]
		}
	}
	if seq == nil {
		t.Fatalf("expected a sequential-handles finding among %d: %+v", len(findings), findings)
	}
	if seq.Severity != "high" || seq.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit for sequential handles, got %q/%q", seq.Severity, seq.Confidence)
	}
	if !strings.Contains(seq.Evidence, "predicted next handle") {
		t.Errorf("evidence should include the prediction, got: %q", seq.Evidence)
	}
}

// TestEntropy_LowAlphabetFiresMedium: short ids over a thin hex alphabet land
// far under the bar without being sequential. MUST fire confirmed/medium.
func TestEntropy_LowAlphabetFiresMedium(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{style: styleLowAlpha}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want medium/ConfirmedExploit for low alphabet entropy, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "bits") {
		t.Errorf("evidence should report the bit estimate, got: %q", f.Evidence)
	}
}

// TestEntropy_UUIDCleanSilent: full-width hex ids clear the bar and carry no
// constant stride. MUST stay silent.
func TestEntropy_UUIDCleanSilent(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{style: styleUUID}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against uuid-style handles, got %d: %+v", len(findings), findings)
	}
}

// TestEntropy_NoSafeToolSilent: the only tool carries no annotations and no
// taskSupport declaration, so the safety gate refuses to mint anything.
func TestEntropy_NoSafeToolSilent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-te2")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "bare", "version": "1"},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": []map[string]interface{}{{
					"name":        "counter_tool",
					"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}, "required": []interface{}{}},
				}}},
			})
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when no safe tool exists, got %d: %+v", len(findings), findings)
	}
}

// TestEntropy_RefusalNotTested: every handle mint is refused after the gate
// passes, so the sample premise collapses into not-tested rather than clean.
func TestEntropy_RefusalNotTested(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-te3")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "refusing", "version": "1"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"tools": []map[string]interface{}{{
					"name":        "wait_a_moment",
					"annotations": map[string]interface{}{"readOnlyHint": true},
					"execution":   map[string]interface{}{"taskSupport": "optional"},
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
						"required":   []interface{}{},
					},
				}}},
			})
		case "tools/call":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32000, "message": "task queue disabled"},
			})
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err == nil {
		t.Fatalf("expected an inconclusive error when no handle could be minted")
	}
	if !strings.Contains(err.Error(), "handle") {
		t.Errorf("expected the reason to name the missing handles, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings alongside the inconclusive result, got %d", len(findings))
	}
}
