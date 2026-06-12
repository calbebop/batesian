package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	eid  int
	sid  string
	data string
}

// resumeServer models an MCP Streamable HTTP server with SSE resumption.
// mode selects replay scoping on a Last-Event-ID resume:
//   - "vulnerable": replays ALL buffered events after the id, any session
//   - "secure":     replays only the requesting session's own events
//   - "ignore":     never replays (no resumption support)
func resumeServer(mode string) *httptest.Server {
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
						"serverInfo":      map[string]interface{}{"name": "resume-fixture", "version": "1.0"},
						"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
			default:
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}

		// GET => SSE stream.
		sid := r.Header.Get("Mcp-Session-Id")
		leid := r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		writeEvent := func(eid int, data string) {
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", eid, data)
			if flusher != nil {
				flusher.Flush()
			}
		}

		if leid == "" {
			mu.Lock()
			eventCounter++
			eid := eventCounter
			data := fmt.Sprintf(`{"sid":%q,"secret":"S-%s-%d"}`, sid, sid, eid)
			log = append(log, sseLogEntry{eid: eid, sid: sid, data: data})
			mu.Unlock()
			writeEvent(eid, data)
			return
		}

		L, err := strconv.Atoi(leid)
		if err != nil {
			L = -1
		}
		mu.Lock()
		snapshot := append([]sseLogEntry(nil), log...)
		mu.Unlock()
		for _, ev := range snapshot {
			if ev.eid <= L || mode == "ignore" {
				continue
			}
			if mode == "secure" && ev.sid != sid {
				continue
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
	ts := resumeServer("vulnerable")
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

// TestResume_Secure: session-scoped replay => no finding.
func TestResume_Secure(t *testing.T) {
	ts := resumeServer("secure")
	defer ts.Close()

	if findings := runResume(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a session-scoped server, got %d: %+v", len(findings), findings)
	}
}

// TestResume_Ignore: no resumption support => no finding.
func TestResume_Ignore(t *testing.T) {
	ts := resumeServer("ignore")
	defer ts.Close()

	if findings := runResume(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings when Last-Event-ID is ignored, got %d: %+v", len(findings), findings)
	}
}

// TestResume_NotMCP: non-MCP server => no finding.
func TestResume_NotMCP(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	if findings := runResume(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-MCP server, got %d", len(findings))
	}
}
