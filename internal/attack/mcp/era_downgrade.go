package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// EraDowngradeExecutor probes whether a server that serves both protocol wires
// gates them differently (rule mcp-era-downgrade-001).
//
// The 2026-07-28 revision is a second, independent entry point. A server built on
// the current SDKs serves it alongside the handshake revisions on the same URL, so
// an authorization check bolted onto one request path leaves the other open, and a
// caller simply asks on the wire that answers. This is
// mcp-init-downgrade-001's bug with wires in place of versions.
type EraDowngradeExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-era-downgrade", func(rc attack.RuleContext) attack.Executor {
		return NewEraDowngradeExecutor(rc)
	})
}

func NewEraDowngradeExecutor(r attack.RuleContext) *EraDowngradeExecutor {
	return &EraDowngradeExecutor{rule: r}
}

func (e *EraDowngradeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Probe UNAUTHENTICATED, for the reason mcp-init-downgrade-001 does: attaching
	// opts.Token would have a gated wire grant the call too, and the discriminator
	// below could never fire. Reaching protected functionality without credentials
	// is the whole claim.
	client := attack.NewUnauthHTTPClient(opts, vars)

	sessions, err := openSessions(ctx, client, vars.BaseURL)
	if err != nil {
		return nil, err
	}

	var legacy, modern *mcpSession
	for i := range sessions {
		switch sessions[i].Era {
		case EraLegacy:
			legacy = &sessions[i]
		case EraModern:
			modern = &sessions[i]
		case EraUnknown:
			// openSessions never returns one; nothing to compare against.
		}
	}
	if legacy == nil || modern == nil {
		// One wire cannot disagree with itself. A server serving a single era is
		// covered by the unauth rules, not here.
		return nil, nil
	}

	// ONE method, advertised by BOTH wires. Each wire used to choose its own from its
	// own advertisement, and nothing then required the two to match: a legacy wire
	// advertising {resources} and a modern wire advertising {tools} were compared as
	// though they were the same call. The difference measured was the capability or a
	// per-method policy, not the era gate, and the finding text rendered one wire's
	// method for both sides while the evidence printed both, so the two contradicted
	// each other.
	legacyMethods := advertisedListMethods(*legacy)
	modernMethods := advertisedListMethods(*modern)
	if len(legacyMethods) == 0 || len(modernMethods) == 0 {
		// A wire advertising nothing listable leaves nothing whose gating could be
		// compared, and that is a genuine not-applicable.
		return nil, nil
	}
	method := firstCommon(legacyMethods, modernMethods)
	if method == "" {
		return nil, fmt.Errorf("%w: the two wires at %s advertise no listable method in common "+
			"(legacy: %s; %s: %s), so any difference between them would be a capability "+
			"difference rather than an authorization gate",
			attack.ErrInconclusive, legacy.Endpoint, strings.Join(legacyMethods, ", "),
			modernEraVersion, strings.Join(modernMethods, ", "))
	}

	legacyOutcome := e.probeList(ctx, client, *legacy, method)
	modernOutcome := e.probeList(ctx, client, *modern, method)
	if !legacyOutcome.comparable() || !modernOutcome.comparable() {
		// One wire did not answer: a transport failure, a bare 202, a 429, a 502.
		// The comparison is unavailable, and calling the silent wire "refused" is
		// how this rule fabricated a critical against a server gating nothing.
		return nil, fmt.Errorf("%w: the %s wire answered %s with HTTP %d, which is "+
			"neither a result nor a refusal, so the two wires' gating could not be compared",
			attack.ErrInconclusive, undeterminedEra(legacyOutcome, modernOutcome),
			undeterminedMethod(legacyOutcome, modernOutcome),
			undeterminedStatus(legacyOutcome, modernOutcome))
	}

	// Both granted: if both return data, no auth at all (tools-unauth territory).
	// But if one returned data and the other an empty list, the empty side
	// enforces via result-level filtering that the non-empty side bypasses.
	if legacyOutcome.granted() && modernOutcome.granted() {
		if legacyOutcome.count > 0 && modernOutcome.count == 0 {
			return []attack.Finding{e.finding(*legacy, legacyOutcome, modernOutcome)}, nil
		}
		if modernOutcome.count > 0 && legacyOutcome.count == 0 {
			return []attack.Finding{e.finding(*legacy, modernOutcome, legacyOutcome)}, nil
		}
		return nil, nil
	}
	// Both refused is the secure outcome. No asymmetry to report.
	if legacyOutcome.granted() == modernOutcome.granted() {
		return nil, nil
	}

	open, closed := legacyOutcome, modernOutcome
	if modernOutcome.granted() {
		open, closed = modernOutcome, legacyOutcome
	}
	return []attack.Finding{e.finding(*legacy, open, closed)}, nil
}

// listableMethods are the read-only listings this rule will compare, in preference
// order, each with the capability that advertises it.
var listableMethods = []struct{ capability, method string }{
	{"tools", "tools/list"},
	{"resources", "resources/list"},
	{"prompts", "prompts/list"},
}

// advertisedListMethods returns the listings this wire advertises, in preference
// order.
func advertisedListMethods(session mcpSession) []string {
	var out []string
	for _, c := range listableMethods {
		if session.ServerSupports(c.capability) {
			out = append(out, c.method)
		}
	}
	return out
}

// firstCommon returns the first entry of a that also appears in b, preserving a's
// preference order, or "" when they share nothing.
func firstCommon(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

// listOutcome is one wire's answer to a read-only list call.
type listOutcome struct {
	era    Era
	method string // "" when the wire advertised nothing listable
	status int
	body   string
	// verdict is what the probe established: granted, refused, or neither. It used
	// to be a bool derived from IsAccepted, which made every non-answer a refusal.
	verdict accessVerdict
	// count is the number of items in a granted listing. Zero on a granted call
	// means the server enforced authorization via result-level filtering (empty
	// list) rather than hard-refusing. Non-zero means data was returned.
	count int
}

// granted reports whether the wire answered the unauthenticated call.
func (o listOutcome) granted() bool { return o.verdict == accessGranted }

// comparable reports whether this outcome can take part in a wire comparison. An
// undetermined probe cannot: it says nothing about authorization.
func (o listOutcome) comparable() bool {
	return o.method != "" && o.verdict != accessUndetermined
}

// probeList asks one wire for a listing, choosing a method that wire advertises.
//
// The capability is read from that wire's own advertisement, because the two need
// not agree: on a server built on the Python SDK the handshake reports
// experimental, prompts, resources and tools while server/discover reports
// prompts, resources and tools. Comparing a method one wire does not implement
// against one it does would measure the capability difference, not the gate.
func (e *EraDowngradeExecutor) probeList(ctx context.Context, client *attack.HTTPClient, session mcpSession,
	method string) listOutcome {
	out := listOutcome{era: session.Era, method: method}

	resp, err := session.post(ctx, client, 2, out.method, nil)
	out.verdict = classifyAccess(resp, err)
	if err != nil {
		// A transport failure is not a refusal. The method stays set so the caller
		// can distinguish "this wire did not answer" from "this wire advertised
		// nothing listable"; comparable() excludes it from the comparison either way.
		// Blanking the method conflated the two, and Execute then reported clean
		// under a comment claiming neither wire advertised a listable capability.
		return out
	}
	out.status = resp.StatusCode
	out.body = resp.BodyString()
	if out.verdict == accessGranted {
		var rb map[string]interface{}
		if json.Unmarshal([]byte(out.body), &rb) == nil {
			if result, ok := rb["result"].(map[string]interface{}); ok {
				if items, ok := result[strings.TrimSuffix(method, "/list")].([]interface{}); ok {
					out.count = len(items)
				}
			}
		}
	}
	return out
}

func (e *EraDowngradeExecutor) finding(session mcpSession, open, closed listOutcome) attack.Finding {
	closedDesc := "was REFUSED"
	closedEvidence := "refused"
	if closed.verdict == accessGranted {
		closedDesc = "returned 0 items (authorization enforced via result-level filtering)"
		closedEvidence = "0 items returned (filtered)"
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title: fmt.Sprintf("MCP authorization enforced on the %s wire but not the %s wire (era downgrade bypass)",
			closed.era, open.era),
		Description: fmt.Sprintf(
			"At %s, an unauthenticated %s %s on the %s wire but ANSWERED on the %s wire. "+
				"The server serves both protocol eras on one endpoint and applies its authorization "+
				"check to only one of them, so a caller reaches protected functionality by asking on "+
				"the other. Nothing about the two eras changes who is allowed to read what.",
			session.Endpoint, open.method, closedDesc, closed.era, open.era),
		Evidence: fmt.Sprintf(
			"endpoint: %s\n%s wire: %s -> HTTP %d, %s\n%s wire: %s -> HTTP %d, answered\nanswered body: %.300s",
			session.Endpoint,
			closed.era, closed.method, closed.status, closedEvidence,
			open.era, open.method, open.status, open.body),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}

// undeterminedEra names the wire that did not answer, for the inconclusive reason.
func undeterminedEra(legacy, modern listOutcome) Era {
	if !legacy.comparable() {
		return legacy.era
	}
	return modern.era
}

func undeterminedMethod(legacy, modern listOutcome) string {
	if !legacy.comparable() {
		return legacy.method
	}
	return modern.method
}

func undeterminedStatus(legacy, modern listOutcome) int {
	if !legacy.comparable() {
		return legacy.status
	}
	return modern.status
}
