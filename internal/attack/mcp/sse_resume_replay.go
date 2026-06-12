package mcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// SSEResumeReplayExecutor tests whether an MCP Streamable HTTP server replays one
// session's buffered SSE events to a DIFFERENT session on resumption (rule
// mcp-sse-resume-replay-001). It uses a raw HTTP client for the SSE GET because
// the shared client only surfaces the first data event, not the event ids this
// rule must read.
type SSEResumeReplayExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-sse-resume-replay", func(rc attack.RuleContext) attack.Executor {
		return NewSSEResumeReplayExecutor(rc)
	})
}

func NewSSEResumeReplayExecutor(r attack.RuleContext) *SSEResumeReplayExecutor {
	return &SSEResumeReplayExecutor{rule: r}
}

type sseEvent struct{ id, data string }

func (e *SSEResumeReplayExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	raw := rawSSEClient(opts)

	// Two principals strengthen the test (cross-principal), but two sessions of
	// the same identity are sufficient to demonstrate cross-session replay.
	tokenA, tokenB := opts.Token, opts.Token
	if len(opts.Principals) >= 2 {
		tokenA, tokenB = opts.Principals[0].Token, opts.Principals[1].Token
	}

	for _, ep := range endpointCandidates(vars.BaseURL) {
		if f := e.probe(ctx, client, raw, ep, tokenA, tokenB); f != nil {
			return f, nil
		}
	}
	return nil, nil
}

func (e *SSEResumeReplayExecutor) probe(ctx context.Context, client *attack.HTTPClient, raw *http.Client, ep, tokenA, tokenB string) []attack.Finding {
	sessionA, ok := e.initialize(ctx, client, ep, tokenA)
	if !ok || sessionA == "" {
		return nil // not MCP here, or server mints no session ids (can't prove cross-session)
	}

	// A's checkpoint: open A's stream and capture an id-bearing, A-specific event.
	aEvents := e.sseCollect(ctx, raw, ep, tokenA, sessionA, "", 3*time.Second)
	checkpointID, marker := firstIDAndMarker(aEvents)
	if checkpointID == "" || marker == "" {
		return nil // no resumable event surface to test
	}

	sessionB, ok := e.initialize(ctx, client, ep, tokenB)
	if !ok || sessionB == "" || sessionB == sessionA {
		return nil // need a second, distinct server-minted session
	}

	// As B, resume from before A's checkpoint and see whether A's event is replayed.
	resumeFrom := lowerEventID(checkpointID)
	bEvents := e.sseCollect(ctx, raw, ep, tokenB, sessionB, resumeFrom, 3*time.Second)
	for _, ev := range bEvents {
		if ev.data == marker {
			return []attack.Finding{{
				RuleID:     e.rule.ID,
				RuleName:   e.rule.Name,
				Severity:   "high",
				Confidence: attack.ConfirmedExploit,
				Title:      "MCP SSE resumption replays another session's events (cross-session redelivery)",
				Description: fmt.Sprintf(
					"At %s, session B resumed an SSE stream with Last-Event-ID=%q and received an event "+
						"that belongs to session A (data marker %q). The server's resumption buffer is not "+
						"scoped to the originating session, so a client can replay another session's "+
						"messages - leaking conversation data, tool outputs, or notifications across "+
						"sessions. The spec requires that resumption MUST NOT replay a different stream's "+
						"messages.", ep, resumeFrom, marker),
				Evidence: fmt.Sprintf(
					"endpoint: %s\nsession A: %s (checkpoint event id %s)\nsession B: %s\n"+
						"B resumed Last-Event-ID: %s\nA's event marker delivered to B: %s",
					ep, sessionA, checkpointID, sessionB, resumeFrom, marker),
				Remediation: e.rule.Remediation,
				TargetURL:   ep,
			}}
		}
	}
	return nil
}

// initialize performs an MCP initialize as the given token and returns the
// server-minted session id.
func (e *SSEResumeReplayExecutor) initialize(ctx context.Context, client *attack.HTTPClient, ep, token string) (string, bool) {
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil || !resp.IsSuccess() {
		return "", false
	}
	if !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return "", false
	}
	sid := resp.Headers.Get("Mcp-Session-Id")
	inited := map[string]string{}
	if token != "" {
		inited["Authorization"] = "Bearer " + token
	}
	if sid != "" {
		inited["Mcp-Session-Id"] = sid
	}
	_, _ = client.POST(ctx, ep, inited, map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return sid, true
}

// sseCollect issues a GET for an SSE stream and returns the events read within
// the window. It uses a raw client so it can read the per-event `id:` lines.
func (e *SSEResumeReplayExecutor) sseCollect(ctx context.Context, client *http.Client, url, token, sessionID, lastEventID string, window time.Duration) []sseEvent {
	cctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "batesian/"+attack.Version+" (https://github.com/calbebop/batesian)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode/100 != 2 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	var events []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.data != "" {
				events = append(events, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, "id:"):
			cur.id = strings.TrimSpace(line[len("id:"):])
		case strings.HasPrefix(line, "data:"):
			cur.data = strings.TrimSpace(line[len("data:"):])
		}
	}
	if cur.data != "" {
		events = append(events, cur)
	}
	return events
}

func rawSSEClient(opts attack.Options) *http.Client {
	tr := &http.Transport{}
	if opts.SkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{Transport: tr}
}

// firstIDAndMarker returns the id of the first event and the data of the last
// event (the session-specific marker the server buffered).
func firstIDAndMarker(events []sseEvent) (id, marker string) {
	if len(events) == 0 {
		return "", ""
	}
	id = events[0].id
	marker = events[len(events)-1].data
	return id, marker
}

// lowerEventID returns an event id one below the given numeric id so a resume
// asks for everything after it; non-numeric ids fall back to "0".
func lowerEventID(id string) string {
	if n, err := strconv.Atoi(id); err == nil && n > 0 {
		return strconv.Itoa(n - 1)
	}
	return "0"
}
