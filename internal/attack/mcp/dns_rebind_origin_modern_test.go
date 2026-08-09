package mcp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// The 2026-07-28 wire for mcp-dns-rebind-origin-001.
//
// The requirement is byte-identical in that revision, where it moved to the
// transports/streamable-http page: servers MUST validate Origin on all incoming
// connections and MUST answer an invalid one with 403. It is not scoped to a method
// and not conditioned on the server being local. The rule ran its own initialize
// loop, so against a modern-only server every candidate failed and it reported a bare
// "could not test" about a server it could have probed.
//
// The case that justifies probing per wire rather than once is
// TestDNSRebindModern_WiresCanDisagree: Origin checking is usually middleware, and a
// server can put the two wires behind different handlers.

// originWireServer serves whichever wires are asked for and validates Origin
// independently on each.
//
// legacy/modern select which wires exist; legacyChecks/modernChecks select whether
// that wire answers 403 to a request carrying an Origin.
type originWireServer struct {
	legacy, modern             bool
	legacyChecks, modernChecks bool
}

func (s originWireServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		// Which wire this request belongs to, by the header the modern revision
		// requires on every request.
		isModern := r.Header.Get("MCP-Protocol-Version") == "2026-07-28"

		rpcErr := func(status, code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": code, "message": msg},
			})
		}
		result := func(v map[string]interface{}) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": v,
			})
		}

		// Origin validation, per wire, before anything else: it is a transport-level
		// check, which is exactly why the two wires can differ.
		if origin := r.Header.Get("Origin"); origin != "" {
			if (isModern && s.modernChecks) || (!isModern && s.legacyChecks) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		switch {
		case method == "server/discover":
			if !s.modern {
				rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
				return
			}
			result(map[string]interface{}{
				"supportedVersions": []string{"2026-07-28"},
				"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":        map[string]interface{}{"name": "origin-wire", "version": "1.0"},
			})
		case method == "initialize":
			if !s.legacy {
				rpcErr(http.StatusBadRequest, -32022, "UnsupportedProtocolVersion")
				return
			}
			result(map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "origin-wire", "version": "1.0"},
			})
		case strings.HasPrefix(method, "notifications/"):
			w.WriteHeader(http.StatusAccepted)
		default:
			rpcErr(http.StatusOK, -32601, "Method not found")
		}
	}))
}

func runOriginRule(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcpattack.NewDNSRebindOriginExecutor(dnsRebindRC()).
		Execute(t.Context(), ts.URL, testOpts())
}

// A modern-only server that ignores Origin. Before the port this reported a bare
// "could not test", because the rule only knew how to send initialize.
func TestDNSRebindModern_ModernOnlyIgnoresOrigin(t *testing.T) {
	ts := originWireServer{modern: true}.start(t)
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("a modern-only server is testable on this surface: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the Origin finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "2026-07-28 wire") {
		t.Errorf("a modern-wire finding should be labelled as such, got %q", f.Title)
	}
	// The probe must name the request it actually sent. Saying "initialize" here
	// would describe a method this revision does not have.
	if !strings.Contains(f.Evidence, "server/discover with Origin") {
		t.Errorf("evidence should name the request the modern wire was probed with; got:\n%s", f.Evidence)
	}
	if strings.Contains(f.Evidence, "initialize") {
		t.Errorf("the modern wire has no initialize; evidence should not claim one:\n%s", f.Evidence)
	}
}

// A modern-only server that answers 403 is clean, and clean rather than not tested:
// the session was opened by the same request with no Origin, so the refusal is
// attributable to the header.
func TestDNSRebindModern_ModernOnlyValidatesIsClean(t *testing.T) {
	ts := originWireServer{modern: true, modernChecks: true}.start(t)
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("a server that validates Origin is a real clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// The case the port exists for. Origin checking is middleware, and a server can
// serve both wires through different handlers, so a single probe on one wire
// generalises to a claim it has not tested.
func TestDNSRebindModern_WiresCanDisagree(t *testing.T) {
	ts := originWireServer{legacy: true, modern: true, legacyChecks: true}.start(t)
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly the modern-wire finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "2026-07-28 wire") {
		t.Errorf("the unvalidated wire is the modern one, and the finding should say so: %q",
			findings[0].Title)
	}
}

// The reverse asymmetry, so the test above is not passing because the rule only ever
// looks at the modern wire.
func TestDNSRebindModern_LegacyBrokenModernFixed(t *testing.T) {
	ts := originWireServer{legacy: true, modern: true, modernChecks: true}.start(t)
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly the legacy-wire finding, got %d: %+v", len(findings), findings)
	}
	if strings.Contains(findings[0].Title, "2026-07-28 wire") {
		t.Errorf("the unvalidated wire is the legacy one, so the finding must not be labelled "+
			"modern: %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Evidence, "initialize with Origin") {
		t.Errorf("evidence should name the legacy probe; got:\n%s", findings[0].Evidence)
	}
}

// A false positive the port removed, found by running the A2A fixtures.
//
// An A2A agent answers any JSON-RPC method with a Task result, so a raw initialize
// got HTTP 200 and a result envelope, the rule called that a responsive MCP endpoint,
// and a scan of an A2A agent reported a high-severity MCP DNS-rebinding finding
// against a server that speaks no MCP at all. Requiring a real handshake, rather than
// any 200 carrying a result, is what settles it.
func TestDNSRebindModern_EchoServerIsNotAnMCPEndpoint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		// A result envelope for anything, carrying none of protocolVersion,
		// serverInfo or capabilities: the shape of an A2A agent, not an MCP server.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": body["id"],
			"result": map[string]interface{}{
				"id": "task-1", "contextId": "ctx-1", "status": "working",
			},
		})
	}))
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if len(findings) != 0 {
		t.Fatalf("an endpoint that echoes a result for any method is not an MCP server, "+
			"got %d finding(s): %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("want ErrInconclusive naming the incomplete handshake, got %v", err)
	}
}

// A probe that never got an answer has tested nothing, and must not be reported as
// Origin validation. The handshake succeeded, so the target is plainly reachable;
// only the request carrying the Origin died, which is the one shape that could
// otherwise be mistaken for a server rejecting it.
func TestDNSRebindModern_TransportFailureIsNotClean(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)

		if r.Header.Get("Origin") != "" {
			// Hang up without answering, rather than refusing.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"result": map[string]interface{}{
					"supportedVersions": []string{"2026-07-28"},
					"capabilities":      map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": body["id"],
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
			})
		}
	}))
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if len(findings) != 0 {
		t.Fatalf("a probe that never landed cannot produce a finding, got %d: %+v", len(findings), findings)
	}
	if err == nil {
		t.Fatal("a probe that never got an answer must report not tested, not a clean pass")
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Errorf("want ErrInconclusive, got %v", err)
	}
}

// Both wires unvalidated: two findings, one per wire, distinguishable. A server can
// only be fixed one handler at a time, so collapsing them would hide half the work.
func TestDNSRebindModern_BothWiresReportSeparately(t *testing.T) {
	ts := originWireServer{legacy: true, modern: true}.start(t)
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected one finding per wire, got %d: %+v", len(findings), findings)
	}
	modern := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "2026-07-28 wire") {
			modern++
		}
	}
	if modern != 1 {
		t.Errorf("expected exactly one of the two to be labelled modern, got %d: %+v",
			modern, findings)
	}
}

// The baseline and the Origin probe must be the SAME request.
//
// The rule's whole claim is that the pair differs in the Origin header alone. When it
// started taking its baseline from openSessions, the probe still built its own body
// offering a different protocol revision with different capabilities and clientInfo,
// so the pair differed three ways. A server that refuses that revision refused the
// probe for reasons unrelated to Origin, and the rule reported Origin validation.
//
// Asserting the bodies match, rather than asserting a particular revision, keeps this
// test correct across a legitimate bump of the offered revision.
func TestDNSRebindModern_ProbeIsTheBaselineRequestPlusOrigin(t *testing.T) {
	type seen struct {
		body   map[string]interface{}
		origin string
	}
	var inits []seen

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if method != "initialize" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		}
		inits = append(inits, seen{body: body, origin: r.Header.Get("Origin")})
		// Origin is never validated, so the rule must report a finding.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "symmetry", "version": "1.0"},
			},
		})
	}))
	defer ts.Close()

	findings, err := runOriginRule(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("a server that ignores Origin must be reported, got %d: %+v", len(findings), findings)
	}

	if len(inits) != 2 {
		t.Fatalf("expected a baseline handshake and one Origin-bearing repeat, got %d", len(inits))
	}
	withOrigin, withoutOrigin := 0, 0
	for _, in := range inits {
		if in.origin == "" {
			withoutOrigin++
		} else {
			withOrigin++
		}
	}
	if withOrigin != 1 || withoutOrigin != 1 {
		t.Fatalf("the pair should be one request with Origin and one without, got %d/%d",
			withOrigin, withoutOrigin)
	}
	if !reflect.DeepEqual(inits[0].body, inits[1].body) {
		a, _ := json.Marshal(inits[0].body)
		b, _ := json.Marshal(inits[1].body)
		t.Errorf("the Origin probe must repeat the baseline request verbatim, so a refusal is "+
			"attributable to the header.\nbaseline: %s\nprobe:    %s", a, b)
	}
}
