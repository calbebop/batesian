package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// Four MCP rules compared two probes, or gated a finding on a control, while deriving
// "refused" from the absence of acceptance. A transport failure, a 429 from a rate
// limiter, a one-off 502 and a bare 202 all read as an authorization refusal, which in
// every case is the direction that ENABLES the finding.
//
// classifyAccess and classifyProbe exist for this and carry comments describing this
// exact failure. era_downgrade adopted them; these rules had not.
//
// Each case below drives a server with NO authorization anywhere, so any finding is
// fabricated, and makes exactly one probe answer with something that refuses nothing.

// mcp-init-downgrade-001: the modern baseline's listing hits a 429. The rule read that
// as "authorization enforced under the modern version" and, since the legacy listing
// succeeded, emitted a critical downgrade bypass against a server gating nothing.
func TestTransient_InitDowngradeUndeterminedModernBaseline(t *testing.T) {
	// The listing succeeds on a session opened with the legacy version and answers 429
	// on one opened with the modern version. Keyed on the version rather than on a
	// request counter, because the endpoint walk probes several candidate paths and a
	// counter makes only one of them see the failure.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		id := body["id"]

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			offered, _ := params["protocolVersion"].(string)
			// Echo the offered version back, so the follow-up carries it.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": offered,
					"serverInfo":      map[string]interface{}{"name": "open", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
			return
		}
		if method == "resources/list" {
			if r.Header.Get("Mcp-Protocol-Version") != "2024-11-05" {
				w.WriteHeader(http.StatusTooManyRequests) // refuses nothing
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"resources": []interface{}{
					map[string]interface{}{"uri": "file:///a", "name": "a"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
		})
	}))
	defer ts.Close()

	findings, err := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"}).
		Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("a 429 refuses nothing, so no downgrade bypass may be claimed; got %d: %+v",
			len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("the comparison was unavailable, so this is not tested; got %v", err)
	}
}

// The same rule must still fire when the modern baseline is genuinely refused.
func TestTransient_InitDowngradeStillFiresOnARealRefusal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		id := body["id"]
		version, _ := params["protocolVersion"].(string)

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "sess-"+version)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": version,
					"serverInfo":      map[string]interface{}{"name": "downgradable", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
			return
		}
		// Authorization enforced only when the session was opened on a modern version.
		if strings.HasPrefix(r.Header.Get("Mcp-Session-Id"), "sess-2024") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"resources": []interface{}{
					map[string]interface{}{"uri": "file:///secret", "name": "secret"},
				}},
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	findings, err := mcpattack.NewInitDowngradeExecutor(attack.RuleContext{ID: "mcp-init-downgrade-001"}).
		Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("a real refusal on the modern version IS the bypass; got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("want critical, got %s", findings[0].Severity)
	}
}

// mcp-header-body-split-001: the MISMATCH probe is the rule's own subject. When it
// returned no verdict the rule folded it into "the value IS validated" and reported
// the SEP-2243 surface clean.
func TestTransient_HeaderBodySplitUndeterminedMismatchProbe(t *testing.T) {
	// Probe order on a legacy wire: omit (refused), match (granted), mismatch.
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "split", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
			return
		}
		if method != "tools/list" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		}
		switch hdr := r.Header.Get("Mcp-Method"); hdr {
		case "":
			// Presence enforced: the rule's precondition.
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32020, "message": "HeaderMismatch"},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		default:
			// The mismatch probe, and anything after it: no verdict at all.
			calls++
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer ts.Close()

	findings, err := mcpattack.NewHeaderBodySplitExecutor(hbsRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("nothing was observed about the header value; got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("an unobserved mismatch probe is not a clean SEP-2243 result; got %v", err)
	}
	if !strings.Contains(err.Error(), "header") {
		t.Errorf("the reason should name the header probe; got %v", err)
	}
}

// mcp-session-fixation-001: the never-initialized control decides whether the server
// enforces sessions at all, and it is what licenses the finding. A control that
// produced no verdict read as "sessions ARE enforced".
func TestTransient_SessionFixationUndeterminedControl(t *testing.T) {
	// The server adopts ANY session id, so it tracks no sessions and the rule must
	// stay silent. The control request is made to answer 502 instead of succeeding,
	// which is what used to flip the verdict.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "sessionless", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
			return
		}
		// The never-initialized control carries the batesian-generated id; the seeded
		// one carries the rule's own fixed id. Answer the control with no verdict.
		if strings.Contains(r.Header.Get("Mcp-Session-Id"), "never") ||
			strings.Contains(r.Header.Get("Mcp-Session-Id"), "unseeded") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
		})
	}))
	defer ts.Close()

	findings, err := mcpattack.NewSessionFixationExecutor(attack.RuleContext{ID: "mcp-session-fixation-001"}).
		Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("the control never established that sessions are enforced; got %d: %+v",
			len(findings), findings)
	}
	if err != nil && !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want nil or ErrInconclusive, got %v", err)
	}
}

// mcp-era-downgrade-001: the two wires must be compared on the SAME method. A legacy
// wire advertising only resources and a modern wire advertising only tools have no
// common listing, so any difference between them is a capability difference.
func TestTransient_EraDowngradeNeedsACommonMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		isModern := r.Header.Get("MCP-Protocol-Version") == "2026-07-28"

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "split-caps", "version": "1.0"},
					// Legacy wire: resources only.
					"capabilities": map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"supportedVersions": []string{"2026-07-28"},
					// Modern wire: tools only.
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
		case "resources/list":
			if isModern {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"resources": []interface{}{
					map[string]interface{}{"uri": "file:///a", "name": "a"},
				}},
			})
		case "tools/list":
			// Answered on the modern wire, refused on the legacy one: the shape that
			// used to be reported as an era gate on a method never sent to both.
			if !isModern {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
			})
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer ts.Close()

	findings, err := mcpattack.NewEraDowngradeExecutor(attack.RuleContext{ID: "mcp-era-downgrade-001"}).
		Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 {
		t.Fatalf("the wires share no listable method, so no era gate can be claimed; got %d: %+v",
			len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive naming the capability difference, got %v", err)
	}
	if !strings.Contains(err.Error(), "in common") {
		t.Errorf("the reason should say the wires share no method; got %v", err)
	}
}

// mcp-session-as-credential-001: steps 4 and 5 are SUPPRESSION controls, so a
// non-answer on either used to read as "this server does gate the surface", and the
// rule then attributed a step-6 success to the session id.
//
// The server below REFUSES the anonymous handshake, so the anonymous-session
// discriminator cannot settle the question and the later controls run. Its no-session
// control then answers 502, establishing nothing. Without grading that, the rule
// treats it as "the surface is gated" and proceeds toward a finding.
func TestTransient_SessionAsCredentialUndeterminedControl(t *testing.T) {
	issued := map[string]bool{}
	n := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		credentialled := r.Header.Get("Authorization") != ""

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "initialize" {
			// The handshake requires a credential, so the anonymous-session control
			// cannot run and the no-session control below is what the rule relies on.
			if !credentialled {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			n++
			sid := "sess-" + strings.Repeat("x", n)
			issued[sid] = true
			w.Header().Set("Mcp-Session-Id", sid)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "flaky-control", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
			return
		}
		sid := r.Header.Get("Mcp-Session-Id")
		if sid == "" {
			// The no-session no-credential control: answers nothing conclusive.
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if !issued[sid] {
			w.WriteHeader(http.StatusNotFound) // never-issued id: a real refusal
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
		})
	}))
	defer ts.Close()

	opts := testOpts()
	opts.Token = "tok-a"
	findings, err := mcpattack.NewSessionAsCredentialExecutor(
		attack.RuleContext{ID: "mcp-session-as-credential-001"}).
		Execute(context.Background(), ts.URL, opts)
	if len(findings) != 0 {
		t.Fatalf("the no-session control established nothing, so a session-id success cannot be "+
			"attributed to the session; got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive, got %v", err)
	}
	// Pinned to the no-session control specifically. Without this the never-issued-id
	// control catches the same server for a different reason and the assertion passes
	// whether or not step 4 grades its outcome.
	if !strings.Contains(err.Error(), "no-session") {
		t.Errorf("the reason should name the no-session control; got %v", err)
	}
}

// A bare HTTP 404 is the shape the transport prescribes for an unknown session id, and
// it commonly carries no JSON-RPC body, so classifyAccess grades it undetermined. On a
// request that PRESENTED a session id that is a real refusal, and the never-issued-id
// control must read it as one: taking it as undetermined makes a compliant server
// report not tested where the rule should have proceeded.
//
// This server IS vulnerable, and answers every session refusal with a bodyless 404.
func TestTransient_SessionAsCredentialBare404IsARefusal(t *testing.T) {
	issued := map[string]bool{}
	n := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]

		if strings.HasPrefix(method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if method == "initialize" {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			n++
			sid := "sess-" + strings.Repeat("y", n)
			issued[sid] = true
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", sid)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "bare404", "version": "1.0"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				},
			})
			return
		}
		sid := r.Header.Get("Mcp-Session-Id")
		if sid == "" || !issued[sid] {
			// Bodyless 404 for both the no-session and never-issued controls.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The defect: an issued session id alone authorizes, with no credential.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id,
			"result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}},
		})
	}))
	defer ts.Close()

	opts := testOpts()
	opts.Token = "tok-a"
	findings, err := mcpattack.NewSessionAsCredentialExecutor(
		attack.RuleContext{ID: "mcp-session-as-credential-001"}).
		Execute(context.Background(), ts.URL, opts)
	if err != nil {
		t.Fatalf("a bodyless 404 on a session-bearing request is a refusal, so both controls "+
			"resolved and the rule was testable: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("the session id alone authorized, which is the finding; got %d: %+v",
			len(findings), findings)
	}
}
