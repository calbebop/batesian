package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/sse"
)

// LogOptInExecutor tests whether an MCP server emits log notifications to a request
// that never asked for them (rule mcp-log-optin-001).
//
// The 2026-07-28 revision removed logging/setLevel and replaced it with a per-request
// opt-in. The logging page is explicit: "To receive log messages for a specific
// request, include io.modelcontextprotocol/logLevel in the request's _meta. The server
// MUST NOT emit notifications/message for a request that does not include this field."
//
// That is the bug the revision created. A server carried over from the setLevel era
// holds a connection-global level and emits unconditionally, so a client that never
// opted in receives server-side log content. Log frames are where internal detail
// lives, which the same page acknowledges by requiring that they contain no
// credentials, personal data or internal system details, and an MCP client feeds what
// the server sends into a model's context.
//
// Two properties of this surface shape the rule:
//
// Emitting is a MAY, so ABSENCE PROVES NOTHING. A server that never logs is
// indistinguishable from one that respects the gate. The control probe below settles
// that by asking WITH the field first: only a server that logs when asked can be
// judged on whether it logs when not asked.
//
// The frames are only visible on the raw stream. The shared client collapses an SSE
// response to its JSON-RPC response event by design (see readSSEResponse), which
// discards exactly the notification frames this rule is looking for, so the probes
// here read the stream themselves.
//
// Currency: the field, and the MUST NOT, exist only in 2026-07-28, so the rule runs
// on that wire alone. It is also worth knowing that the whole Logging feature is
// deprecated as of the same revision (SEP-2577), eligible for removal in the first
// revision released on or after 2027-07-28, with new implementations told to use
// stderr or OpenTelemetry instead. The requirement is normative until then, and the
// servers most likely to break it are the ones migrating off setLevel.
type LogOptInExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-log-optin", func(rc attack.RuleContext) attack.Executor {
		return NewLogOptInExecutor(rc)
	})
}

func NewLogOptInExecutor(r attack.RuleContext) *LogOptInExecutor {
	return &LogOptInExecutor{rule: r}
}

// metaLogLevel is the reserved _meta key that opts a single request in to log
// notifications. It is absent from modernMeta on purpose: not asking is the default,
// and it is what the probe below relies on.
const metaLogLevel = "io.modelcontextprotocol/logLevel"

// logProbeLevel is the level the control probe asks for. debug is the most permissive
// of the RFC 5424 set the specification enumerates, so a server that logs at all has
// something at or above it.
const logProbeLevel = "debug"

func (e *LogOptInExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)
	raw := rawSSEClient(opts)

	sessions, err := openSessions(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}

	modernSeen := false
	notObserved := ""
	var findings []attack.Finding
	for _, session := range sessions {
		if session.Era != EraModern {
			continue
		}
		modernSeen = true

		// Control: ask for logs. A server that sends none when asked does not log on
		// this surface, so the probe below cannot tell compliance from silence.
		//
		// That case is reported as NOT OBSERVED rather than clean, and the distinction
		// is the whole point of the control. Falling through to clean would make the
		// control dead logic: silent-control and silent-probe would produce the same
		// verdict, and the rule would claim a server gates its log notifications on the
		// strength of never having seen one. Removing the control then changed no
		// output at all, which is how this was caught.
		switch e.emitsLogFrame(ctx, raw, client, session, opts, true) {
		case logNone:
			notObserved = fmt.Sprintf("%s emitted no notifications/message even for a request that "+
				"asked for them with %s=%s, so whether it gates them on the opt-in could not be "+
				"established; emitting is a MAY, and silence is not evidence of the gate",
				session.Endpoint, metaLogLevel, logProbeLevel)
			continue
		case logUnreadable:
			notObserved = fmt.Sprintf("the log-level probe at %s produced no readable response stream, "+
				"and only a stream can carry a notifications/message frame, so the opt-in gate was "+
				"never exercised", session.Endpoint)
			continue
		}

		// Probe: the same request with no logLevel in _meta. Any notifications/message
		// frame here is the violation, and no interpretation stands between the
		// observation and the claim.
		//
		// logUnreadable is graded separately from logNone. Both used to fall through to
		// the clean tail, so a probe that died in transport after a control which HAD
		// established that the server logs here was reported as "it withheld the frames
		// when they were not asked for" - a clean verdict resting on a request that
		// produced no observation. Only logNone is evidence the gate held.
		switch e.emitsLogFrame(ctx, raw, client, session, opts, false) {
		case logEmitted:
			findings = append(findings, labelEra(session, []attack.Finding{
				e.finding(session, e.advertisesLogging(session)),
			})...)
		case logUnreadable:
			notObserved = fmt.Sprintf("the control at %s established that the server emits log "+
				"notifications, but the probe that omits %s produced no readable response stream, so "+
				"whether the opt-in gate held was never observed", session.Endpoint, metaLogLevel)
		}
	}

	if len(findings) > 0 {
		return findings, nil
	}
	if !modernSeen {
		// The field and its MUST NOT arrived with 2026-07-28. On an earlier wire the
		// mechanism is logging/setLevel, which this rule is not about, so there is no
		// requirement here to violate.
		return nil, fmt.Errorf("%w: the per-request log opt-in exists only in MCP %s, and %s serves "+
			"no wire on that revision", attack.ErrInconclusive, modernEraVersion, vars.BaseURL)
	}
	if notObserved != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, notObserved)
	}
	// The control logged and the probe did not: the server demonstrably logs here and
	// withheld the frames when they were not asked for. That is a tested clean result.
	return nil, nil
}

// logOutcome is what a single probe saw on the response stream.
type logOutcome int

const (
	// logNone: the stream carried no log notification. On the control probe that
	// means the server does not log here; on the real probe it means the gate held.
	logNone logOutcome = iota
	// logEmitted: at least one notifications/message frame was present.
	logEmitted
	// logUnreadable: the request did not produce a stream that could be read.
	logUnreadable
)

// emitsLogFrame sends one tools/list on this wire and reports whether the response
// stream carried a log notification. optIn adds the logLevel field to _meta.
//
// tools/list is the body because it is a read that every server implements, and this
// rule needs the server to do a unit of work rather than to do anything in
// particular. Nothing is created, called or modified.
func (e *LogOptInExecutor) emitsLogFrame(ctx context.Context, raw *http.Client, client *attack.HTTPClient,
	session mcpSession, opts attack.Options, optIn bool) logOutcome {
	headers, body := session.request(4, "tools/list", nil)
	if optIn {
		addMeta(body, metaLogLevel, logProbeLevel)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return logUnreadable
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, session.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return logUnreadable
	}
	req.Header.Set("Content-Type", "application/json")
	// Both content types, because the server chooses: a single JSON object carries no
	// notifications at all, and only a stream can.
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "batesian/"+attack.Version+" (https://github.com/calbebop/batesian)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// The raw client bypasses the shared client's token injection, so the decision is
	// delegated back to it: PresentsCredential answers the same question the injection
	// site asks, including the off-host guard, so this cannot drift from it.
	if client.PresentsCredential(session.Endpoint) {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}

	resp, err := raw.Do(req)
	if err != nil {
		return logUnreadable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return logUnreadable
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		// A single JSON object cannot carry a notification frame, so nothing about the
		// gate follows from it either way.
		return logUnreadable
	}

	// One matching frame is all the oracle needs: the question is whether ANY log
	// notification was sent, so the scan stops at the first.
	if _, found, err := sse.FirstMatching(resp.Body, maxLogStream, isLogNotification); err == nil && found {
		return logEmitted
	}
	return logNone
}

// maxLogStream bounds the stream read. A response stream ends with the response, so
// this only guards against a server that streams without terminating.
const maxLogStream = 1 << 20

// addMeta sets one key inside a request's _meta block, which request() has already
// built for the era. Legacy requests carry no _meta and are left untouched.
func addMeta(body map[string]interface{}, key string, value interface{}) {
	params, ok := body["params"].(map[string]interface{})
	if !ok {
		return
	}
	meta, ok := params["_meta"].(map[string]interface{})
	if !ok {
		return
	}
	meta[key] = value
}

// isLogNotification reports whether an SSE payload is a notifications/message frame.
//
// It keys on the method name, not on the presence of "level" or "logger", because
// those are field names that appear in plenty of unrelated payloads and this rule's
// whole claim rests on the frame being a log notification.
func isLogNotification(payload []byte) bool {
	var frame struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(payload, &frame) != nil {
		return false
	}
	return frame.Method == "notifications/message"
}

// advertisesLogging reports whether the server's discover result declares the logging
// capability. A server that emits log notifications MUST declare it, so a server
// emitting them unasked AND undeclared is breaking two requirements, which is worth
// saying in the evidence rather than leaving the reader to check.
func (e *LogOptInExecutor) advertisesLogging(session mcpSession) bool {
	return session.ServerSupports("logging")
}

func (e *LogOptInExecutor) finding(session mcpSession, declared bool) attack.Finding {
	capability := "the server also does not declare the logging capability, which it MUST when it " +
		"emits log notifications, so two requirements are broken here"
	if declared {
		capability = "the server does declare the logging capability, so the defect is the opt-in " +
			"gate rather than the declaration"
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "medium",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server emits log notifications to a request that did not opt in",
		Description: fmt.Sprintf(
			"At %s, a tools/list request whose _meta carried no %s was answered with a stream "+
				"containing a notifications/message frame. MCP %s replaced logging/setLevel with a "+
				"per-request opt-in and requires that a server MUST NOT emit notifications/message for "+
				"a request that does not include that field. The same page requires that log messages "+
				"carry no credentials, personal data or internal system details, which is an "+
				"acknowledgement of what they usually do carry, and an MCP client feeds what the server "+
				"sends into a model's context. So a client that never asked for logs receives "+
				"server-side detail it did not request and cannot anticipate. A control request that DID "+
				"carry the field produced log frames too, which is what establishes that this server "+
				"logs on this surface and that the unasked-for frames are not an artefact of the probe.",
			session.Endpoint, metaLogLevel, modernEraVersion),
		// No wire line here: this rule only ever reports on the modern wire, so labelEra
		// always prepends one, and naming it twice is how the live fixture run read.
		Evidence: fmt.Sprintf(
			"endpoint: %s\ncontrol, _meta WITH %s=%s: notifications/message observed, so the "+
				"server logs here\nprobe, _meta WITHOUT %s: notifications/message observed anyway "+
				"(MUST NOT)\n%s",
			session.Endpoint, metaLogLevel, logProbeLevel, metaLogLevel, capability),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
