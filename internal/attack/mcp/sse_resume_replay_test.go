package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func sseRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-sse-resume-replay-001", Name: "MCP SSE Resume Replay", Severity: "high", Remediation: "Scope replay to session."}
}

type sseLogEntry struct {
	eid  string
	sid  string
	data string
}

// resumeServer models an MCP Streamable HTTP server with SSE resumption.
// mode selects replay scoping on a Last-Event-ID resume:
//   - "vulnerable": replays ALL buffered events after the id, any session
//   - "secure":     replays only the requesting session's own events
//   - "ignore":     never replays (no resumption support)
func resumeServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var sessionCounter, eventCounter int
	var log []sseLogEntry

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			method, _ := req["method"].(string)
			id := req["id"]
			w.Header().Set("Content-Type", "application/json")
			switch method {
			case "initialize":
				mu.Lock()
				if mode == "second-init-error" && sessionCounter > 0 {
					mu.Unlock()
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				sessionCounter++
				sid := fmt.Sprintf("sess-%d", sessionCounter)
				if mode == "same-session" {
					sid = "sess-1"
				}
				mu.Unlock()
				if mode != "no-session" {
					w.Header().Set("Mcp-Session-Id", sid)
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{
						"protocolVersion": "2025-06-18",
						"serverInfo":      map[string]interface{}{"name": "resume-fixture", "version": "1.0"},
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
			case "notifications/initialized":
				if mode == "notification-error" {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				if mode == "notification-rpc-error" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": nil,
						"error": map[string]interface{}{"code": -32600, "message": "Not initialized"},
					})
					return
				}
				if got := r.Header.Get("Mcp-Protocol-Version"); got != "2025-06-18" {
					t.Errorf("initialized version = %q, want 2025-06-18", got)
				}
				w.WriteHeader(http.StatusAccepted)
			default:
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}

		// GET => SSE stream.
		if r.Header.Get("Mcp-Protocol-Version") != "2025-06-18" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sid := r.Header.Get("Mcp-Session-Id")
		leid := r.Header.Get("Last-Event-ID")
		if leid == "" {
			switch mode {
			case "stream-error":
				w.WriteHeader(http.StatusBadGateway)
				return
			case "stream-unavailable":
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			case "empty-stream":
				w.Header().Set("Content-Type", "text/event-stream")
				return
			case "stream-wrong-type":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
				return
			}
		} else {
			switch mode {
			case "resume-error":
				w.WriteHeader(http.StatusBadGateway)
				return
			case "resume-drop":
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				_ = conn.Close()
				return
			case "resume-refused":
				w.WriteHeader(http.StatusForbidden)
				return
			case "resume-timeout":
				w.Header().Set("Content-Type", "text/event-stream")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				return
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		writeEvent := func(eid, data string) {
			fmt.Fprintf(w, "id: %s\ndata: %s\n\n", eid, data)
			if flusher != nil {
				flusher.Flush()
			}
		}

		if leid == "" {
			// Emit two session-specific events with OPAQUE (non-numeric) ids, so a
			// resume from the first event's id can replay the second. Real MCP SDKs
			// mint opaque ids; the spec does not guarantee numeric ones.
			mu.Lock()
			var fresh []sseLogEntry
			for i := 0; i < 2; i++ {
				eventCounter++
				eid := fmt.Sprintf("evt-%s-%d", sid, eventCounter)
				data := fmt.Sprintf(`{"sid":%q,"secret":"S-%s-%d"}`, sid, sid, eventCounter)
				entry := sseLogEntry{eid: eid, sid: sid, data: data}
				log = append(log, entry)
				fresh = append(fresh, entry)
			}
			mu.Unlock()
			for _, ev := range fresh {
				writeEvent(ev.eid, ev.data)
			}
			return
		}

		if mode == "ignore" {
			return // never replays on resume
		}
		mu.Lock()
		snapshot := append([]sseLogEntry(nil), log...)
		mu.Unlock()
		// Resume after the event whose opaque id matches Last-Event-ID.
		start := -1
		for i, ev := range snapshot {
			if ev.eid == leid {
				start = i
				break
			}
		}
		if start == -1 {
			return // unknown checkpoint id: nothing to replay
		}
		for _, ev := range snapshot[start+1:] {
			if mode == "secure" && ev.sid != sid {
				continue // compliant: only replay the requester's own events
			}
			writeEvent(ev.eid, ev.data)
		}
	}))
}

func runResume(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewSSEResumeReplayExecutor(sseRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

// TestResume_Vulnerable: cross-session replay => confirmed.
func TestResume_Vulnerable(t *testing.T) {
	ts := resumeServer(t, "vulnerable")
	defer ts.Close()

	findings := runResume(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != attack.ConfirmedExploit || findings[0].Severity != "high" {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Title, "cross-session") {
		t.Errorf("expected cross-session in title, got %q", findings[0].Title)
	}
}

// TestResume_OpaqueEventIDs locks in the opaque-id behaviour. The fixture mints
// non-numeric event ids, so the executor must resume with the captured id
// verbatim. The previous numeric-decrement approach resumed from "0", which an
// opaque-id server does not recognise, so the cross-session replay went
// undetected (false negative). This test fails against that old behaviour.
func TestResume_OpaqueEventIDs(t *testing.T) {
	ts := resumeServer(t, "vulnerable")
	defer ts.Close()

	findings := runResume(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding against opaque-id server, got %d: %+v", len(findings), findings)
	}
	// The evidence must show B resumed with A's opaque checkpoint id, not "0".
	ev := findings[0].Evidence
	if !strings.Contains(ev, "evt-sess-1-1") {
		t.Errorf("expected evidence to reference opaque checkpoint id 'evt-sess-1-1', got:\n%s", ev)
	}
	if strings.Contains(ev, "Last-Event-ID: 0") {
		t.Errorf("evidence shows a numeric '0' resume cursor; the opaque id was not used verbatim:\n%s", ev)
	}
}

// TestResume_Secure: session-scoped replay => no finding.
func TestResume_Secure(t *testing.T) {
	ts := resumeServer(t, "secure")
	defer ts.Close()

	if findings := runResume(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a session-scoped server, got %d: %+v", len(findings), findings)
	}
}

// TestResume_Ignore: no resumption support => no finding.
func TestResume_Ignore(t *testing.T) {
	ts := resumeServer(t, "ignore")
	defer ts.Close()

	if findings := runResume(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when Last-Event-ID is ignored, got %d: %+v", len(findings), findings)
	}
}

// TestResume_NotMCP: non-MCP server => no finding.
func TestResume_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	assertInconclusive(t, mcpattack.NewSSEResumeReplayExecutor(sseRuleCtx()), ts.URL, attack.Options{TimeoutSeconds: 5})
}

func TestResume_IncompleteSetupAndStreams(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"notification-error", "initialized notification"},
		{"notification-rpc-error", "initialized notification"},
		{"no-session", "no session ID"},
		{"stream-error", "session A SSE stream"},
		{"stream-unavailable", "no SSE stream"},
		{"stream-wrong-type", "session A SSE stream"},
		{"empty-stream", "no checkpoint"},
		{"second-init-error", "second distinct session"},
		{"same-session", "second distinct session"},
		{"resume-error", "session B SSE resume"},
		{"resume-drop", "session B SSE resume"},
		{"resume-timeout", "session B SSE resume"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			ts := resumeServer(t, tc.mode)
			defer ts.Close()
			findings, err := mcpattack.NewSSEResumeReplayExecutor(sseRuleCtx()).Execute(
				context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unobserved replay check: findings=%+v, err=%v", findings, err)
			}
		})
	}
}

func TestResume_ExplicitlyRefused(t *testing.T) {
	for _, mode := range []string{"resume-refused"} {
		t.Run(mode, func(t *testing.T) {
			ts := resumeServer(t, mode)
			defer ts.Close()
			if findings := runResume(t, ts); len(findings) != 0 {
				t.Fatalf("explicit refusal: findings=%+v", findings)
			}
		})
	}
}

// resumeServerMultiline is a vulnerable replay server whose SSE events carry a
// trailing empty "data:" line, as a chunked stream whose payload ends in a
// newline can emit:
//
//	id: <eid>
//	data: <payload>
//	data:
//
// The previous reader kept only the last "data:" line, so the empty trailing
// line overwrote the payload, the event was recorded empty, and it was skipped.
// Session A then captured no marker and the rule stayed silent (false negative).
// The joined parser reassembles <payload> and the finding fires.
func resumeServerMultiline() *httptest.Server {
	var mu sync.Mutex
	var sessionCounter, eventCounter int
	var log []sseLogEntry

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			method, _ := req["method"].(string)
			id := req["id"]
			w.Header().Set("Content-Type", "application/json")
			switch method {
			case "initialize":
				mu.Lock()
				sessionCounter++
				sid := fmt.Sprintf("sess-%d", sessionCounter)
				mu.Unlock()
				w.Header().Set("Mcp-Session-Id", sid)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": id,
					"result": map[string]interface{}{
						"protocolVersion": "2025-06-18",
						"serverInfo":      map[string]interface{}{"name": "resume-ml", "version": "1.0"},
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
			default:
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}

		sid := r.Header.Get("Mcp-Session-Id")
		leid := r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		writeMultiline := func(eid, data string) {
			// Payload on the first data: line, then an empty trailing data: line.
			fmt.Fprintf(w, "id: %s\ndata: %s\ndata:\n\n", eid, data)
			if flusher != nil {
				flusher.Flush()
			}
		}

		if leid == "" {
			mu.Lock()
			var fresh []sseLogEntry
			for i := 0; i < 2; i++ {
				eventCounter++
				eid := fmt.Sprintf("evt-%s-%d", sid, eventCounter)
				data := fmt.Sprintf(`{"sid":%q,"secret":"S-%s-%d"}`, sid, sid, eventCounter)
				entry := sseLogEntry{eid: eid, sid: sid, data: data}
				log = append(log, entry)
				fresh = append(fresh, entry)
			}
			mu.Unlock()
			for _, ev := range fresh {
				writeMultiline(ev.eid, ev.data)
			}
			return
		}
		mu.Lock()
		snapshot := append([]sseLogEntry(nil), log...)
		mu.Unlock()
		start := -1
		for i, ev := range snapshot {
			if ev.eid == leid {
				start = i
				break
			}
		}
		if start == -1 {
			return
		}
		for _, ev := range snapshot[start+1:] {
			writeMultiline(ev.eid, ev.data)
		}
	}))
}

func TestResume_MultilineDataEvent(t *testing.T) {
	ts := resumeServerMultiline()
	defer ts.Close()

	findings := runResume(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when events span multiple data: lines, got %d: %+v", len(findings), findings)
	}
	// The full marker must survive reassembly; the trailing empty data: line
	// must not have reduced it to a fragment.
	if !strings.Contains(findings[0].Evidence, "S-sess-1-2") {
		t.Errorf("expected the joined marker in evidence, got:\n%s", findings[0].Evidence)
	}
}
