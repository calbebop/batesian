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

	sessions, err := openSessions(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}

	// Set when a wire turned out not to enforce Mcp-Method presence, carrying the
	// version that wire speaks. A wire that does enforce presence is tested on its
	// merits and never sets this.
	unawareAt := ""
	anyTested := false
	var findings []attack.Finding
	for _, session := range sessions {
		f, unaware, tested := e.probe(ctx, client, session)
		findings = append(findings, labelEra(session, f)...)
		if unaware != "" {
			unawareAt = unaware
		}
		if tested {
			anyTested = true
		}
	}
	if len(findings) > 0 {
		return findings, nil
	}
	// A wire that got past the presence probe exercised the rule, so a clean result
	// is a real one even when another wire had no such requirement. Without this a
	// dual-era server whose modern wire validates the header correctly would still
	// be reported as not tested, on the strength of its legacy wire.
	if anyTested {
		return nil, nil
	}

	// Nothing found. Whether that is a clean result depends on the wires available.
	//
	// Mcp-Method mirroring and its -32020 HeaderMismatch rejection were introduced
	// by SEP-2243 in 2026-07-28. On an earlier wire there is no requirement to
	// violate, so probe 1 is always accepted and nothing is tested. Reporting that
	// as clean asserted header/body consistency about a server that was never
	// asked. A server on 2026-07-28 or later that ignores the header is a different
	// matter and reports clean, because this rule's subject is the mismatch, not
	// the absence.
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

// probe runs the three-step check against one already-opened wire.
//
// unawareAt is set only when the server did not enforce Mcp-Method presence, and
// carries the version that wire speaks. tested says whether the mismatch was
// actually driven, which is what separates a clean result from one where the rule
// never got far enough to judge.
func (e *HeaderBodySplitExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, unawareAt string, tested bool) {
	wireVersion := session.ProtocolVersion

	// Probe 1: omit Mcp-Method. If the server still executes tools/list, it does
	// not enforce header presence (not SEP-2243-aware) - nothing to confirm.
	if e.toolsList(ctx, client, session, omitMethodHeader) {
		return nil, wireVersion, false
	}

	// Probe 2: matching Mcp-Method. Must be accepted, otherwise we cannot drive
	// the mismatch test (the endpoint may require headers we are not sending).
	// Presence is enforced by this point, so the rule is testing a server that
	// implements SEP-2243 whatever version it advertises.
	if !e.toolsList(ctx, client, session, matchMethodHeader) {
		return nil, "", false
	}

	// Probe 3: mismatched Mcp-Method. A compliant server MUST reject; if it
	// executes the body's tools/list, header value is not validated.
	if e.toolsList(ctx, client, session, mismatchMethodHeader) {
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
				session.Endpoint),
			Evidence: fmt.Sprintf(
				"endpoint: %s\nomit Mcp-Method: rejected (presence enforced)\nMcp-Method: tools/list (match): executed\n"+
					"Mcp-Method: tools/call (mismatch) + body tools/list: EXECUTED body (should be 400/-32020)",
				session.Endpoint),
			Remediation: e.rule.Remediation,
			TargetURL:   session.Endpoint,
		}}, "", true
	}
	return nil, "", true
}

// The two deliberate malformations. Omitting the header tests whether presence is
// enforced at all; mismatching it tests whether the value is validated, which is
// the split-brain this rule confirms.
func omitMethodHeader(h map[string]string) { delete(h, "Mcp-Method") }

// The matching header is set explicitly rather than left to the era: a modern
// request already carries it, but a legacy one does not, and probe 2 has to send
// it on either wire for the mismatch in probe 3 to mean anything.
func matchMethodHeader(h map[string]string)    { h["Mcp-Method"] = "tools/list" }
func mismatchMethodHeader(h map[string]string) { h["Mcp-Method"] = "tools/call" }

// toolsList sends a tools/list body. methodHeader controls the Mcp-Method header:
// nil omits it; otherwise it is set to the given (possibly mismatched) value. It
// reports whether the server EXECUTED tools/list (returned a result.tools array).
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, session mcpSession, shape func(map[string]string)) bool {
	resp, err := session.postShaping(ctx, client, 2, "tools/list", nil, shape)
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
