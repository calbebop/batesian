package mcp

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
)

type paramHeaderFixture struct {
	acceptMismatch bool
	noAnnotation   bool
	notReadOnly    bool
	badBaseline    bool
	badMismatch    bool
	calls          atomic.Int32
}

func (f *paramHeaderFixture) serve(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	respond := func(result map[string]interface{}, code int, message string) {
		body := map[string]interface{}{"jsonrpc": "2.0", "id": request.ID}
		if result != nil {
			body["result"] = result
		} else {
			body["error"] = map[string]interface{}{"code": code, "message": message}
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	switch request.Method {
	case "initialize":
		respond(nil, -32601, "Method not found")
	case "server/discover":
		respond(map[string]interface{}{
			"resultType": "complete", "supportedVersions": []string{modernEraVersion},
			"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":   map[string]interface{}{"name": "param-fixture", "version": "1"},
		}, 0, "")
	case "tools/list":
		property := map[string]interface{}{"type": "string"}
		if !f.noAnnotation {
			property["x-mcp-header"] = "Region"
		}
		annotations := map[string]interface{}{"readOnlyHint": true}
		if f.notReadOnly {
			annotations["readOnlyHint"] = false
		}
		respond(map[string]interface{}{
			"resultType": "complete", "tools": []map[string]interface{}{{
				"name": "lookup", "annotations": annotations,
				"inputSchema": map[string]interface{}{
					"type": "object", "properties": map[string]interface{}{"region": property},
				},
			}},
		}, 0, "")
	case "tools/call":
		f.calls.Add(1)
		args, _ := request.Params["arguments"].(map[string]interface{})
		region, _ := args["region"].(string)
		meta, _ := request.Params["_meta"].(map[string]interface{})
		if r.Header.Get("Mcp-Method") != "tools/call" || r.Header.Get("Mcp-Name") != "lookup" ||
			r.Header.Get("Mcp-Protocol-Version") != modernEraVersion ||
			meta[metaProtocolVersion] != modernEraVersion || region == "" {
			respond(nil, -32602, "invalid modern request")
			return
		}
		mismatch := r.Header.Get("Mcp-Param-Region") != region
		if (!mismatch && f.badBaseline) || (mismatch && f.badMismatch) {
			respond(nil, -32603, "tool unavailable")
			return
		}
		if mismatch && !f.acceptMismatch {
			w.WriteHeader(http.StatusBadRequest)
			respond(nil, headerMismatchCode, "HeaderMismatch")
			return
		}
		respond(map[string]interface{}{
			"resultType": "complete", "content": []interface{}{}, "isError": false,
		}, 0, "")
	default:
		respond(nil, -32601, "Method not found")
	}
}

func runParamHeaderFixture(t *testing.T, fixture *paramHeaderFixture, approved bool) ([]attack.Finding, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	defer server.Close()
	opts := attack.Options{TimeoutSeconds: 5}
	if approved {
		opts.MCPInvokeTools = []string{"lookup"}
	}
	rule := attack.RuleContext{ID: "mcp-param-header-mismatch-001", Name: "Parameter header mismatch", Remediation: "Reject mismatches."}
	return (&ParamHeaderMismatchExecutor{rule: rule}).Execute(context.Background(), server.URL, opts)
}

func TestParamHeaderMismatch_AcceptedIsIndicator(t *testing.T) {
	fixture := &paramHeaderFixture{acceptMismatch: true}
	findings, err := runParamHeaderFixture(t, fixture, true)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if findings[0].Confidence != attack.RiskIndicator || findings[0].Severity != "medium" ||
		!strings.Contains(findings[0].Evidence, "Mcp-Param-Region") || fixture.calls.Load() != 2 {
		t.Fatalf("unexpected indicator: %+v; calls=%d", findings[0], fixture.calls.Load())
	}
}

func TestParamHeaderMismatch_RejectedIsClean(t *testing.T) {
	fixture := &paramHeaderFixture{}
	findings, err := runParamHeaderFixture(t, fixture, true)
	if err != nil || len(findings) != 0 || fixture.calls.Load() != 2 {
		t.Fatalf("findings=%+v err=%v calls=%d", findings, err, fixture.calls.Load())
	}
}

func TestParamHeaderMismatch_UnsafeOrUnapprovedIsNotRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fixture  *paramHeaderFixture
		approved bool
	}{
		{"unapproved", &paramHeaderFixture{}, false},
		{"no annotation", &paramHeaderFixture{noAnnotation: true}, true},
		{"not read-only", &paramHeaderFixture{notReadOnly: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.fixture
			findings, err := runParamHeaderFixture(t, fixture, tc.approved)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || fixture.calls.Load() != 0 {
				t.Fatalf("findings=%+v err=%v calls=%d", findings, err, fixture.calls.Load())
			}
		})
	}
}

func TestParamHeaderMismatch_AmbiguousResponseIsNotClean(t *testing.T) {
	for _, fixture := range []*paramHeaderFixture{{badBaseline: true}, {badMismatch: true}} {
		findings, err := runParamHeaderFixture(t, fixture, true)
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("findings=%+v err=%v", findings, err)
		}
	}
}

func TestMismatchedParamHeader_Types(t *testing.T) {
	for _, tc := range []struct {
		kind     string
		value    interface{}
		expected string
	}{
		{"string", "west", "batesian-header-mismatch"},
		{"integer", 1, "0"},
		{"boolean", false, "true"},
	} {
		schema := map[string]interface{}{"properties": map[string]interface{}{
			"region": map[string]interface{}{"type": tc.kind, "x-mcp-header": "Region"},
		}}
		name, original, changed, ok := mismatchedParamHeader(schema, map[string]interface{}{"region": tc.value})
		if !ok || name != "Mcp-Param-Region" || original == changed || changed != tc.expected {
			t.Errorf("%s: name=%q original=%q changed=%q ok=%v", tc.kind, name, original, changed, ok)
		}
	}
}
