package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func entropyRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-task-id-entropy-001",
		Name:        "MCP Tasks Extension Handle Entropy",
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

// entropyServer mints modern task handles for one read-only tool.
type entropyServer struct {
	style                entropyStyle
	annotations          map[string]interface{}
	calls                *atomic.Int32
	listRPCError         bool
	noSafeTool           bool
	refuseCalls          bool
	badCallID            bool
	legacyResult         bool
	legacyOnly           bool
	noExtension          bool
	headerParam          bool
	headerMismatchStatus int
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
			Method string                 `json:"method"`
			ID     json.RawMessage        `json:"id"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			if s.legacyOnly {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]interface{}{
						"protocolVersion": "2025-11-25",
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
						"serverInfo":      map[string]interface{}{"name": "entropy-fixture", "version": "1"},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		case "server/discover":
			versions := []string{"2026-07-28"}
			if s.legacyOnly {
				versions = []string{"2025-11-25"}
			}
			capabilities := map[string]interface{}{"tools": map[string]interface{}{}}
			if !s.noExtension && !s.legacyOnly {
				capabilities["extensions"] = map[string]interface{}{"io.modelcontextprotocol/tasks": map[string]interface{}{}}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"resultType":        "complete",
					"supportedVersions": versions,
					"capabilities":      capabilities,
					"serverInfo":        map[string]interface{}{"name": "entropy-fixture", "version": "1"},
				},
			})
		case "tools/list":
			if s.listRPCError {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32001, "message": "not authorized"},
				})
				return
			}
			annotations := s.annotations
			if annotations == nil {
				annotations = map[string]interface{}{"readOnlyHint": true}
			}
			if s.noSafeTool {
				annotations = map[string]interface{}{}
			}
			properties := map[string]interface{}{}
			if s.headerParam {
				properties["message"] = map[string]interface{}{"type": "string", "x-mcp-header": "Message"}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{"resultType": "complete", "tools": []map[string]interface{}{{
					"name":        "wait_a_moment",
					"annotations": annotations,
					"inputSchema": map[string]interface{}{
						"type":       "object",
						"properties": properties,
						"required":   []interface{}{},
					},
				}}},
			})
		case "tools/call":
			if s.calls != nil {
				s.calls.Add(1)
			}
			meta, _ := req.Params["_meta"].(map[string]interface{})
			if s.headerParam {
				args, _ := req.Params["arguments"].(map[string]interface{})
				message, _ := args["message"].(string)
				if message == "" || r.Header.Get("Mcp-Param-Message") != message {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID,
						"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
					})
					return
				}
			}
			caps, _ := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]interface{})
			extensions, _ := caps["extensions"].(map[string]interface{})
			_, taskCapable := extensions["io.modelcontextprotocol/tasks"]
			if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
				r.Header.Get("Mcp-Method") != "tools/call" ||
				r.Header.Get("Mcp-Name") != "wait_a_moment" ||
				meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" ||
				!taskCapable || req.Params["task"] != nil {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32602, "message": "modern task capability required"},
				})
				return
			}
			if s.headerMismatchStatus != 0 {
				w.WriteHeader(s.headerMismatchStatus)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
				})
				return
			}
			if s.refuseCalls {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": -32000, "message": "task queue disabled"},
				})
				return
			}
			handle := s.nextHandle(callCount)
			callCount++
			result := map[string]interface{}{
				"resultType": "task", "taskId": handle, "status": "working",
				"createdAt": "2026-01-01T00:00:00Z", "lastUpdatedAt": "2026-01-01T00:00:00Z", "ttlMs": 60000,
			}
			if s.legacyResult {
				result = map[string]interface{}{"task": map[string]interface{}{"taskId": handle}}
			}
			responseID := interface{}(req.ID)
			if s.badCallID {
				responseID = 999
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": responseID, "result": result,
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
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"wait_a_moment"}})
}

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
	if seq.Severity != "high" || seq.Confidence != attack.RiskIndicator {
		t.Errorf("want high/indicator for sequential handles, got %q/%q", seq.Severity, seq.Confidence)
	}
	if !strings.Contains(seq.Evidence, "predicted next handle") {
		t.Errorf("evidence should include the prediction, got: %q", seq.Evidence)
	}
}

func TestEntropy_MirrorsAnnotatedToolArgument(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{style: styleSequential, headerParam: true, calls: &calls}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if err != nil || len(findings) == 0 || calls.Load() < 2 {
		t.Fatalf("annotated task tool was not assessed: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
	}
}

func TestEntropy_HeaderMismatchIsInconclusive(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			ts := httptest.NewServer((&entropyServer{
				style: styleSequential, headerParam: true, headerMismatchStatus: status, calls: &calls,
			}).handler())
			defer ts.Close()

			findings, err := runEntropy(t, ts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) ||
				!strings.Contains(err.Error(), "HeaderMismatch") || calls.Load() != 1 {
				t.Fatalf("mismatch must stop without retry: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
			}
		})
	}
}

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
	if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
		t.Errorf("want medium/indicator for low alphabet entropy, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "bits") {
		t.Errorf("evidence should report the bit estimate, got: %q", f.Evidence)
	}
}

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

func TestEntropy_NoSafeToolIsNotTested(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{noSafeTool: true, calls: &calls}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
		t.Fatalf("no safe tool must be not tested without calls: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
	}
}

func TestEntropy_NonDestructiveWriteToolIsNotCalled(t *testing.T) {
	var calls atomic.Int32
	srv := &entropyServer{
		style:       styleSequential,
		annotations: map[string]interface{}{"readOnlyHint": false, "destructiveHint": false},
		calls:       &calls,
	}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("non-read-only tool must be not tested: findings=%+v err=%v", findings, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("non-read-only tool was called %d times", calls.Load())
	}
}

func TestEntropy_RequiresExactToolApproval(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{style: styleSequential, calls: &calls}).handler())
	defer ts.Close()
	exec := mcp.NewTaskIDEntropyExecutor(entropyRC())
	for _, approved := range [][]string{nil, {"other_tool"}} {
		findings, err := exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: approved})
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "wait_a_moment") {
			t.Fatalf("approval %v: findings=%+v err=%v", approved, findings, err)
		}
		if calls.Load() != 0 {
			t.Fatalf("tool was called without exact approval: %d", calls.Load())
		}
	}
	_, err := exec.Execute(t.Context(), ts.URL, attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"wait_a_moment"}})
	if err != nil || calls.Load() == 0 {
		t.Fatalf("exact approval did not enable the probe: calls=%d err=%v", calls.Load(), err)
	}
}

func TestEntropy_ToolListRPCErrorIsNotClean(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{listRPCError: true, calls: &calls}).handler())
	defer ts.Close()
	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
		t.Fatalf("tools/list error must be inconclusive without calls: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
	}
}

func TestEntropy_RefusalNotTested(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{refuseCalls: true}).handler())
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

func TestEntropy_LegacyHandleShapeIsNotTested(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{legacyResult: true}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("legacy handle shape must be not tested: findings=%+v err=%v", findings, err)
	}
}

func TestEntropy_UnrelatedCallResponseIsNotTested(t *testing.T) {
	ts := httptest.NewServer((&entropyServer{badCallID: true}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unrelated result must be not tested: findings=%+v err=%v", findings, err)
	}
}

func TestEntropy_LegacyWireIsNotTested(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{legacyOnly: true, calls: &calls}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
		t.Fatalf("legacy-only wire must be not tested: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
	}
}

func TestEntropy_MissingExtensionIsNotTested(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer((&entropyServer{noExtension: true, calls: &calls}).handler())
	defer ts.Close()

	findings, err := runEntropy(t, ts)
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || calls.Load() != 0 {
		t.Fatalf("missing Tasks extension must be not tested: findings=%+v calls=%d err=%v", findings, calls.Load(), err)
	}
}
