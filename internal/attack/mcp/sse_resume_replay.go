package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/sse"
)

// SSEResumeReplayExecutor checks whether SSE resumption leaks events across
// MCP sessions. It reads event IDs through a raw HTTP client.
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

	var observed initObservation
	var incomplete string
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		result, reached, reason := e.probe(ctx, client, raw, ep, tokenA, tokenB, &observed)
		if reached {
			incomplete = reason
		}
		return result, reached
	})
	if errors.Is(err, attack.ErrInconclusive) && observed.rank > rankNothing {
		return nil, inconclusive(handshakeRefusal{observed.reason})
	}
	if len(findings) != 0 || err != nil {
		return findings, err
	}
	if incomplete != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, incomplete)
	}
	return nil, nil
}

func (e *SSEResumeReplayExecutor) probe(ctx context.Context, client *attack.HTTPClient, raw *http.Client, ep, tokenA, tokenB string,
	observed *initObservation) ([]attack.Finding, bool, string) {
	sessionA, ok, resp, setupReason := e.initialize(ctx, client, ep, tokenA)
	if setupReason != "" {
		return nil, true, "session A " + setupReason
	}
	if !ok {
		if resp != nil {
			observed.observe(classifyInitFailure(ep, tokenA != "" || client.PresentsCredential(ep), resp))
		}
		return nil, false, "" // not a responsive MCP endpoint
	}
	if sessionA.SessionID == "" {
		return nil, true, "the server issued no session ID for the replay comparison"
	}

	// A's checkpoint: open A's stream and capture an id-bearing event plus the
	// data of the events that follow it (the session-A-specific markers a resume
	// from the checkpoint would replay).
	aEvents, aStatus, aErr := e.sseCollect(ctx, raw, ep, tokenA, sessionA, "", 3*time.Second)
	if aStatus == http.StatusNotFound || aStatus == http.StatusMethodNotAllowed ||
		aStatus == http.StatusNotAcceptable || aStatus == http.StatusNotImplemented {
		return nil, true, "the server exposed no SSE stream for session A"
	}
	if (aErr != nil && !errors.Is(aErr, context.DeadlineExceeded)) || aStatus < 200 || aStatus >= 300 {
		return nil, true, "session A SSE stream could not be read"
	}
	checkpointID, markers := resumeCheckpoint(aEvents)
	if checkpointID == "" || len(markers) == 0 {
		return nil, true, "session A stream supplied no checkpoint and later event to compare"
	}

	sessionB, ok, _, setupReason := e.initialize(ctx, client, ep, tokenB)
	if setupReason != "" {
		return nil, true, "session B " + setupReason
	}
	if !ok || sessionB.SessionID == "" || sessionB.SessionID == sessionA.SessionID {
		return nil, true, "a second distinct session was not established"
	}

	// As B, resume from A's checkpoint id and see whether A's later events are
	// replayed into B's session. MCP event ids are opaque (spec: Streamable HTTP
	// resumability), so the checkpoint id is sent verbatim, with no arithmetic.
	bEvents, bStatus, bErr := e.sseCollect(ctx, raw, ep, tokenB, sessionB, checkpointID, 3*time.Second)
	for _, ev := range bEvents {
		if markers[ev.data] {
			marker := ev.data
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
						"messages.", ep, checkpointID, marker),
				Evidence: fmt.Sprintf(
					"endpoint: %s\nsession A: %s (checkpoint event id %s)\nsession B: %s\n"+
						"B resumed Last-Event-ID: %s\nA's event marker delivered to B: %s",
					ep, sessionA.SessionID, checkpointID, sessionB.SessionID, checkpointID, marker),
				Remediation: e.rule.Remediation,
				TargetURL:   ep,
			}}, true, ""
		}
	}
	if bStatus == http.StatusNotImplemented || (bStatus >= 400 && bStatus < 500 &&
		bStatus != http.StatusRequestTimeout && bStatus != http.StatusTooManyRequests) {
		return nil, true, "" // the cross-session resume was refused
	}
	if bErr != nil || bStatus < 200 || bStatus >= 300 {
		return nil, true, "session B SSE resume response could not be read"
	}
	return nil, true, ""
}

// initialize opens a session and reports incomplete notification setup separately.
func (e *SSEResumeReplayExecutor) initialize(ctx context.Context, client *attack.HTTPClient, ep, token string) (mcpSession, bool, *attack.Response, string) {
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": latestStable,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	})
	if err != nil {
		return mcpSession{}, false, nil, ""
	}
	if resp == nil {
		return mcpSession{}, false, nil, ""
	}
	if !resp.IsSuccess() || !initializeSucceeded(resp.Body) {
		return mcpSession{}, false, resp, ""
	}
	session := mcpSession{
		Endpoint: ep, SessionID: resp.Headers.Get("Mcp-Session-Id"),
		ProtocolVersion: negotiatedVersion(resp.Body),
	}
	if session.SessionID == "" {
		return session, true, resp, ""
	}
	inited := session.header()
	if token != "" {
		inited["Authorization"] = "Bearer " + token
	}
	initialized, initErr := client.POST(ctx, ep, inited, map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if initErr != nil || initialized == nil || !initialized.IsSuccess() {
		return mcpSession{}, false, resp, "initialized notification failed"
	}
	if _, rejected := jsonRPCErrorCode(initialized.Body); rejected {
		return mcpSession{}, false, resp, "initialized notification failed"
	}
	return session, true, resp, ""
}

// sseCollect issues a GET for an SSE stream and returns the events read within
// the window. It uses a raw client so it can read the per-event `id:` lines.
func (e *SSEResumeReplayExecutor) sseCollect(ctx context.Context, client *http.Client, url, token string,
	session mcpSession, lastEventID string, window time.Duration) ([]sseEvent, int, error) {
	cctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "batesian/"+attack.Version+" (https://github.com/calbebop/batesian)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range session.header() {
		req.Header.Set(name, value)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, resp.StatusCode, nil
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil, resp.StatusCode, fmt.Errorf("unexpected SSE content type")
	}
	// Read events for the window via the shared parser, which joins a payload
	// split across several "data:" lines so a marker or checkpoint id is not
	// reduced to its last fragment. The stream is bounded by the request
	// context: when the window expires the body read errors and the loop stops.
	rd := sse.NewReader(resp.Body)
	var events []sseEvent
	for {
		ev, err := rd.Next()
		if err != nil {
			if errors.Is(cctx.Err(), context.DeadlineExceeded) {
				return events, resp.StatusCode, context.DeadlineExceeded
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return events, resp.StatusCode, err
		}
		if ctx.Err() != nil {
			return events, resp.StatusCode, ctx.Err()
		}
		events = append(events, sseEvent{id: ev.ID, data: ev.Data})
	}
	return events, resp.StatusCode, nil
}

func rawSSEClient(opts attack.Options) *http.Client {
	return &http.Client{
		Transport: attack.Transport(opts),
		// Match the shared scan client: do not follow redirects. The SSE GET
		// must hit the stream endpoint the rule selected, not whatever a 3xx
		// would bounce it to.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// resumeCheckpoint selects the first id-bearing event as the resume cursor and
// collects the data of every later event as session-specific markers. Resuming
// from the cursor's exact id asks the server for the events after it, so a
// vulnerable server replays those markers into a different session. MCP event
// ids are opaque (spec: Streamable HTTP resumability), so the cursor id is used
// verbatim with no arithmetic. It returns an empty id when no event carries an
// id, or no markers when nothing follows the checkpoint (nothing to replay).
func resumeCheckpoint(events []sseEvent) (checkpointID string, markers map[string]bool) {
	markers = map[string]bool{}
	idx := -1
	for i, ev := range events {
		if ev.id != "" {
			idx = i
			break
		}
	}
	if idx == -1 {
		return "", markers
	}
	for _, ev := range events[idx+1:] {
		if ev.data != "" {
			markers[ev.data] = true
		}
	}
	return events[idx].id, markers
}
