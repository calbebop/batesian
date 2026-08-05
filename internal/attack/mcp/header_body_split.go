package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// HeaderBodySplitExecutor tests for the SEP-2243 header/body routing split-brain
// (rule mcp-header-body-split-001): a Streamable HTTP server that enforces the
// presence of the Mcp-Method routing header but does not validate that its value
// matches the JSON-RPC body method.
type HeaderBodySplitExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-header-body-split", func(rc attack.RuleContext) attack.Executor {
		return NewHeaderBodySplitExecutor(rc)
	})
}

func NewHeaderBodySplitExecutor(r attack.RuleContext) *HeaderBodySplitExecutor {
	return &HeaderBodySplitExecutor{rule: r}
}

func (e *HeaderBodySplitExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	client := attack.NewHTTPClient(opts, vars)

	// Set only when the server turned out not to enforce Mcp-Method presence, in
	// which case it carries the version that session negotiated. A server that
	// does enforce presence is tested on its merits and never sets this, whatever
	// version it advertises.
	unawareAt := ""
	findings, err := probeCandidates(vars.BaseURL, func(ep string) ([]attack.Finding, bool) {
		f, reached, unaware := e.probe(ctx, client, ep)
		if unaware != "" {
			unawareAt = unaware
		}
		return f, reached
	})
	if err != nil || len(findings) > 0 {
		return findings, err
	}

	// The server did not enforce Mcp-Method presence, so the rule stopped at its
	// first probe. Whether that is a clean result depends on the revision.
	//
	// Mcp-Method mirroring and its -32020 HeaderMismatch rejection were introduced
	// by SEP-2243 in 2026-07-28. On an earlier wire there is no requirement to
	// violate, so probe 1 is always accepted and nothing is ever tested. Calling
	// that clean asserted header/body consistency about a server that was never
	// asked, on every scan. A server on 2026-07-28 or later that ignores the header
	// is a different matter and still reports clean here, because this rule's
	// subject is the mismatch, not the absence.
	//
	// The dated revisions sort lexicographically, which is what makes the compare
	// safe.
	if unawareAt != "" && unawareAt < headerValidationVersion {
		return nil, fmt.Errorf("%w: no SEP-2243 surface at MCP %s; Mcp-Method validation was introduced in %s",
			attack.ErrInconclusive, unawareAt, headerValidationVersion)
	}
	return nil, nil
}

// headerValidationVersion is the revision that introduced Mcp-Method mirroring
// and the -32020 HeaderMismatch rejection this rule tests for.
const headerValidationVersion = modernEraVersion

// probe returns the findings, whether the endpoint answered as MCP, and, only
// when the server turned out not to enforce Mcp-Method presence, the version the
// session negotiated. Callers use that last value to decide whether "no
// enforcement" is expected for the revision in play.
func (e *HeaderBodySplitExecutor) probe(ctx context.Context, client *attack.HTTPClient, ep string) (findings []attack.Finding, reached bool, unawareAt string) {
	session, ok := e.initialize(ctx, client, ep)
	if !ok {
		return nil, false, "" // not an MCP endpoint here
	}

	// Probe 1: omit Mcp-Method. If the server still executes tools/list, it does
	// not enforce header presence (not SEP-2243-aware) - nothing to confirm.
	if e.toolsList(ctx, client, ep, session, nil) {
		return nil, true, session.ProtocolVersion
	}

	// Probe 2: matching Mcp-Method. Must be accepted, otherwise we cannot drive
	// the mismatch test (the endpoint may require headers we are not sending).
	// Presence is enforced by this point, so the rule is testing a server that
	// implements SEP-2243 whatever version it advertises.
	matched := "tools/list"
	if !e.toolsList(ctx, client, ep, session, &matched) {
		return nil, true, ""
	}

	// Probe 3: mismatched Mcp-Method. A compliant server MUST reject; if it
	// executes the body's tools/list, header value is not validated.
	mismatched := "tools/call"
	if e.toolsList(ctx, client, ep, session, &mismatched) {
		return []attack.Finding{{
			RuleID:     e.rule.ID,
			RuleName:   e.rule.Name,
			Severity:   "high",
			Confidence: attack.ConfirmedExploit,
			Title:      "MCP server enforces Mcp-Method presence but not header/body consistency (SEP-2243 split-brain)",
			Description: fmt.Sprintf(
				"At %s, a tools/list request was REJECTED when the Mcp-Method header was omitted (the "+
					"server enforces header presence), but a tools/list request with a MISMATCHED "+
					"Mcp-Method: tools/call header was still EXECUTED as tools/list. The MCP Streamable "+
					"HTTP spec requires rejecting such a mismatch with 400 / -32020 (HeaderMismatch). "+
					"Because the header is enforced for "+
					"presence but not value, an intermediary that routes or rate-limits on Mcp-Method can "+
					"be bypassed by labelling a sensitive body operation with an innocuous method.",
				ep),
			Evidence: fmt.Sprintf(
				"endpoint: %s\nomit Mcp-Method: rejected (presence enforced)\nMcp-Method: tools/list (match): executed\n"+
					"Mcp-Method: tools/call (mismatch) + body tools/list: EXECUTED body (should be 400/-32020)",
				ep),
			Remediation: e.rule.Remediation,
			TargetURL:   ep,
		}}, true, ""
	}
	return nil, true, ""
}

// initialize performs an MCP initialize (sending a matching Mcp-Method so a
// header-enforcing server accepts it) and returns the session.
func (e *HeaderBodySplitExecutor) initialize(ctx context.Context, client *attack.HTTPClient, ep string) (mcpSession, bool) {
	resp, err := client.POST(ctx, ep, map[string]string{"Mcp-Method": "initialize"}, map[string]interface{}{
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
		return mcpSession{}, false
	}
	if !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
		return mcpSession{}, false
	}
	session := mcpSession{Endpoint: ep, SessionID: resp.Headers.Get("Mcp-Session-Id"), ProtocolVersion: negotiatedVersion(resp.Body), RawInit: resp.Body}
	initedHeaders := session.header()
	if initedHeaders == nil {
		initedHeaders = map[string]string{}
	}
	initedHeaders["Mcp-Method"] = "notifications/initialized"
	_, _ = client.POST(ctx, ep, initedHeaders, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	return session, true
}

// toolsList sends a tools/list body. methodHeader controls the Mcp-Method header:
// nil omits it; otherwise it is set to the given (possibly mismatched) value. It
// reports whether the server EXECUTED tools/list (returned a result.tools array).
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, ep string, session mcpSession, methodHeader *string) bool {
	headers := session.header()
	if headers == nil {
		headers = map[string]string{}
	}
	if methodHeader != nil {
		headers["Mcp-Method"] = *methodHeader
	}
	resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return false
	}
	var b map[string]interface{}
	if json.Unmarshal(resp.Body, &b) != nil {
		return false
	}
	if _, hasErr := b["error"]; hasErr {
		return false
	}
	result, ok := b["result"].(map[string]interface{})
	if !ok {
		return false
	}
	_, hasTools := result["tools"]
	return hasTools
}
