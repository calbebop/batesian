package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// mcp-log-optin-001 tests one MUST NOT: "The server MUST NOT emit
// notifications/message for a request that does not include this field."
//
// Emitting logs is a MAY, so absence proves nothing, and the control probe is what
// makes the rule honest: only a server that logs WHEN ASKED can be judged on whether
// it logs when not asked. Every case below turns on that asymmetry.

// logMode decides how the fixture treats the per-request opt-in.
type logMode int

const (
	// logAlways emits log frames whether or not logLevel was requested: the finding.
	logAlways logMode = iota
	// logOnOptIn emits only when logLevel is present: compliant.
	logOnOptIn
	// logNever emits nothing at all, so the rule cannot judge the gate.
	logNever
	// logAlwaysUndeclared is logAlways, and also omits the logging capability.
	logAlwaysUndeclared
	// logJSONOnly answers with a single JSON object rather than a stream, so no
	// notification frame is possible either way.
	logJSONOnly
	// logDecoy emits a NON-log notification that mentions a level, and lists a tool
	// called logLevel, so the payloads contain every word a text search would look
	// for while carrying no notifications/message at all. It exists to pin the oracle
	// to the METHOD NAME: matching on field names instead reports this server, which
	// gates its log notifications correctly, as a violation.
	logDecoy
	// logProbeUnreadable streams a log frame for the CONTROL and answers the PROBE
	// with a plain JSON object, so the probe yields no readable stream at all.
	//
	// It pins the one asymmetry the two legs must not share. The control establishes
	// that this server logs here, so silence on the probe would be evidence the gate
	// held; a probe that produced no stream is not silence, it is no observation. Both
	// used to fall through to the same clean verdict.
	logProbeUnreadable
)

// logOptInServer serves the 2026-07-28 wire only, so the rule's era gate is exercised
// as well. requestLogLevel records what each tools/list carried, so a test can assert
// the control probe really did ask.
func logOptInServer(t *testing.T, mode logMode, sawOptIn *[]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		params, _ := body["params"].(map[string]interface{})
		meta, _ := params["_meta"].(map[string]interface{})
		id := body["id"]

		// Modern wire only: refuse the handshake so the rule arrives via discovery.
		if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
			})
			return
		}

		if method == "server/discover" {
			caps := map[string]interface{}{"tools": map[string]interface{}{}}
			if mode != logAlwaysUndeclared {
				caps["logging"] = map[string]interface{}{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"supportedVersions": []string{"2026-07-28"},
					"capabilities":      caps,
				},
			})
			return
		}

		if method != "tools/list" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		}

		_, optedIn := meta["io.modelcontextprotocol/logLevel"]
		if sawOptIn != nil {
			*sawOptIn = append(*sawOptIn, optedIn)
		}

		result := map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}}
		if mode == logDecoy {
			// Every needle a text search might use, in a payload that is not a log frame.
			result = map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "logLevel", "description": "set the level"},
			}}
		}
		// The probe leg gets no stream, only the control does. Answering the probe with
		// a plain JSON object is the cheapest way to produce "no observation" without
		// also killing the connection.
		if mode == logJSONOnly || (mode == logProbeUnreadable && !optedIn) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id, "result": result,
			})
			return
		}

		emitLog := mode == logAlways || mode == logAlwaysUndeclared ||
			(mode == logOnOptIn && optedIn) || (mode == logProbeUnreadable && optedIn)

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if mode == logDecoy {
			// A progress notification, not a log one, mentioning a level.
			decoy, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "method": "notifications/progress",
				"params": map[string]interface{}{"level": "debug", "logger": "decoy", "progress": 1},
			})
			fmt.Fprintf(w, "data: %s\n\n", decoy)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if emitLog {
			// A log notification ahead of the response, which is where the binding
			// says request-scoped notifications flow.
			note, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "method": "notifications/message",
				"params": map[string]interface{}{
					"level": "debug", "logger": "fixture",
					"data": map[string]interface{}{"msg": "listing tools"},
				},
			})
			fmt.Fprintf(w, "data: %s\n\n", note)
			if flusher != nil {
				flusher.Flush()
			}
		}
		reply, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "id": id, "result": result,
		})
		fmt.Fprintf(w, "data: %s\n\n", reply)
		if flusher != nil {
			flusher.Flush()
		}
	}))
}

func logOptInRC() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-log-optin-001", Name: "MCP Log Opt-In", Severity: "medium",
		Remediation: "Gate notifications/message on the request's own logLevel.",
	}
}

func runLogOptIn(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcpattack.NewLogOptInExecutor(logOptInRC()).
		Execute(context.Background(), ts.URL, testOpts())
}

// The finding: log frames arrive for a request that carried no logLevel, and the
// control proved the server logs here.
func TestLogOptIn_EmitsWithoutOptIn(t *testing.T) {
	var sawOptIn []bool
	ts := logOptInServer(t, logAlways, &sawOptIn)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the opt-in violation, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want medium/ConfirmedExploit, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "2026-07-28 wire") {
		t.Errorf("a modern-wire finding should be labelled as such, got %q", f.Title)
	}
	// The control has to have actually asked, or the finding rests on nothing.
	if len(sawOptIn) < 2 || !sawOptIn[0] || sawOptIn[1] {
		t.Errorf("expected a control request WITH the field then a probe WITHOUT it, saw %v", sawOptIn)
	}
	if !strings.Contains(f.Evidence, "notifications/message observed, so the server logs here") {
		t.Errorf("evidence should record the control that makes the claim meaningful; got:\n%s", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "does declare the logging capability") {
		t.Errorf("evidence should record the capability declaration; got:\n%s", f.Evidence)
	}
	// labelEra prepends the wire line, and this rule only ever reports on that wire, so
	// stating it in the finding too printed it twice. Caught by running the fixture, not
	// by these tests, which is the argument for running the fixture.
	if n := strings.Count(f.Evidence, "wire: MCP"); n != 1 {
		t.Errorf("the wire should be named exactly once, got %d times:\n%s", n, f.Evidence)
	}
}

// A server that logs only when asked is compliant, and the control proves the rule
// actually exercised the surface rather than finding silence.
func TestLogOptIn_EmitsOnlyOnOptInIsClean(t *testing.T) {
	ts := logOptInServer(t, logOnOptIn, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if err != nil {
		t.Fatalf("a server that respects the gate is a real clean result: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
	}
}

// A server that never logs cannot be judged: silence is indistinguishable from
// compliance. It must be reported as NOT OBSERVED, never as clean, or the rule would
// claim the server gates its log notifications on the strength of never having seen
// one. This is what makes the control probe load-bearing: without it, silent-control
// and silent-probe produce the same verdict and removing the control changes nothing.
func TestLogOptIn_NeverLogsIsNotObserved(t *testing.T) {
	ts := logOptInServer(t, logNever, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if len(findings) != 0 {
		t.Fatalf("silence is not evidence of anything; got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "silence is not evidence of the gate") {
		t.Errorf("the reason should say why silence settles nothing; got %q", err)
	}
}

// A single JSON object cannot carry a notification frame, so the gate was never
// exercised and the honest answer is not observed rather than clean.
func TestLogOptIn_NonStreamingResponseIsNotObserved(t *testing.T) {
	ts := logOptInServer(t, logJSONOnly, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d: %+v", len(findings), findings)
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if !strings.Contains(err.Error(), "no readable response stream") {
		t.Errorf("the reason should name the missing stream; got %q", err)
	}
}

// Emitting log notifications without declaring the logging capability breaks a second
// requirement, and the evidence should say so rather than leave it to the reader.
func TestLogOptIn_UndeclaredCapabilityIsNamed(t *testing.T) {
	ts := logOptInServer(t, logAlwaysUndeclared, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the opt-in violation, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "two requirements are broken") {
		t.Errorf("evidence should name the undeclared capability; got:\n%s", findings[0].Evidence)
	}
}

// The field and its MUST NOT exist only in 2026-07-28. A handshake-era server has no
// such requirement, so the rule reports not applicable and names the revision rather
// than reporting a clean pass about a surface that does not exist there.
func TestLogOptIn_LegacyOnlyIsNotApplicable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		method, _ := body["method"].(string)
		id := body["id"]
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-11-25",
					"serverInfo":      map[string]interface{}{"name": "legacy", "version": "1"},
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}, "logging": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings, got %d", len(findings))
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive on a legacy-only target, got %v", err)
	}
	if !strings.Contains(err.Error(), "2026-07-28") {
		t.Errorf("the reason should name the revision that introduced the field, got %q", err)
	}
}

// The oracle keys on the METHOD NAME, not on field names. This server gates its log
// notifications correctly and never sends notifications/message, but every payload it
// does send mentions a level and a logger, and one of its tools is called logLevel. A
// text search over the stream reports it; the method-name check does not.
//
// Matching on field names instead of the method name is the vacuous-needle mistake
// corrected in #163, #169 and #181, and this is the case that pins it here.
func TestLogOptIn_DecoyPayloadsAreNotLogFrames(t *testing.T) {
	ts := logOptInServer(t, logDecoy, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if len(findings) != 0 {
		t.Fatalf("a progress notification mentioning a level is not a log frame; got %d: %+v",
			len(findings), findings)
	}
	// It never sends a log frame at all, so the control cannot establish the gate and
	// the honest answer is not observed.
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
}

// The control logged and the probe produced no readable stream. That is NOT a clean
// pass: the control proved the server logs here, so silence on the probe would have
// been evidence, but no stream is not silence. Both legs used to fall through to the
// same clean verdict, which reported "it withheld the frames when they were not asked
// for" about a request that produced no observation at all.
func TestLogOptIn_UnreadableProbeIsNotClean(t *testing.T) {
	ts := logOptInServer(t, logProbeUnreadable, nil)
	defer ts.Close()

	findings, err := runLogOptIn(t, ts)
	if len(findings) != 0 {
		t.Fatalf("a probe that produced no stream cannot yield a finding, got %d: %+v",
			len(findings), findings)
	}
	if err == nil {
		t.Fatal("an unobserved probe must report not tested, not a clean pass")
	}
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive, got %v", err)
	}
	// The reason has to say which leg failed, or an operator cannot tell this from a
	// server that simply does not log.
	if !strings.Contains(err.Error(), "no readable response stream") {
		t.Errorf("the skip reason should name the unreadable probe; got: %v", err)
	}
}
