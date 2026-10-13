package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

	sessions, sessionErr := openSessions(ctx, client, vars.BaseURL)
	if len(sessions) == 0 {
		return nil, sessionErr
	}

	// Set when a wire turned out not to enforce Mcp-Method presence, carrying the
	// version that wire speaks. A wire that does enforce presence is tested on its
	// merits and never sets this.
	unawareAt := ""
	blockedReason := ""
	// Kept apart from blockedReason so an undetermined Mcp-Name probe can never
	// override a verdict the Mcp-Method dimension actually reasoned its way to. That
	// dimension is the rule's headline subject; the name dimension is additive, and an
	// additive probe that could not decide anything must not turn a considered clean
	// result into "not tested". It is used only when nothing else had anything to say.
	nameBlockedReason := ""
	anyTested := false
	var findings []attack.Finding
	for _, session := range sessions {
		f, unaware, tested, blocked := e.probe(ctx, client, session)
		findings = append(findings, labelEra(session, f)...)
		if unaware != "" {
			unawareAt = unaware
		}
		if tested {
			anyTested = true
		}
		if blocked != "" && blockedReason == "" {
			blockedReason = blocked
		}

		if session.ProtocolVersion < headerValidationVersion {
			continue
		}
		// Check Mcp-Name independently of Mcp-Method.
		nf, nameTested, nameBlocked := e.probeName(ctx, client, session)
		findings = append(findings, labelEra(session, nf)...)
		if nameTested {
			anyTested = true
		}
		if nameBlocked != "" && nameBlockedReason == "" {
			nameBlockedReason = nameBlocked
		}
	}
	if blockedReason != "" {
		return findings, errors.Join(sessionErr, fmt.Errorf("%w: %s", attack.ErrInconclusive, blockedReason))
	}
	if nameBlockedReason != "" {
		return findings, errors.Join(sessionErr, fmt.Errorf("%w: %s", attack.ErrInconclusive, nameBlockedReason))
	}
	if len(findings) > 0 {
		return findings, sessionErr
	}
	if sessionErr != nil {
		return nil, sessionErr
	}
	if anyTested {
		return nil, nil
	}
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
func (e *HeaderBodySplitExecutor) probe(ctx context.Context, client *attack.HTTPClient, session mcpSession) (findings []attack.Finding, unawareAt string, tested bool, blocked string) {
	wireVersion := session.ProtocolVersion

	// Probe 1: omit Mcp-Method. Executing tools/list anyway means the server does
	// not enforce header presence (not SEP-2243-aware) and there is nothing to
	// confirm. Only an explicit REFUSAL establishes that presence is enforced; a
	// probe that merely failed to answer establishes nothing, so the rule stops
	// rather than treating it as enforcement.
	switch e.toolsList(ctx, client, session, omitMethodHeader) {
	case accessGranted:
		return nil, wireVersion, false, ""
	case accessUndetermined:
		return nil, "", false, "the tools/list probe with no Mcp-Method header " +
			"returned neither a result nor a refusal, so whether the server enforces " +
			"header presence could not be established"
	}

	// Probe 2: matching Mcp-Method. Must be accepted, otherwise we cannot drive
	// the mismatch test (the endpoint may require headers we are not sending).
	// Presence is enforced by this point, so the rule is testing a server that
	// implements SEP-2243 whatever version it advertises.
	if e.toolsList(ctx, client, session, matchMethodHeader) != accessGranted {
		return nil, "", false, "tools/list was refused even with a matching Mcp-Method " +
			"header, so the header/body mismatch could never be sent"
	}

	// Probe 3: mismatched Mcp-Method. A compliant server MUST reject; if it
	// executes the body's tools/list, header value is not validated.
	//
	// accessUndetermined is graded separately here, exactly as it is for probe 1. It
	// used to fold into the "value IS validated" branch, which is the rule's own
	// subject: a 502 or a rate limit on this one request reported the SEP-2243 surface
	// clean. Worse, it then ran the case-folded follow-up, so an undetermined mismatch
	// plus a server that ignores the header value outright emitted the CASE-FOLDING
	// finding, whose text asserts that a mismatched Mcp-Method was rejected - something
	// this path never observed.
	switch e.toolsList(ctx, client, session, mismatchMethodHeader) {
	case accessUndetermined:
		return nil, "", false, "the tools/list probe whose Mcp-Method disagreed with the body " +
			"returned neither a result nor a refusal, so whether the server validates the header " +
			"VALUE could not be established"
	case accessRefused:
		// Check whether the server compares header values case-insensitively.
		switch e.toolsList(ctx, client, session, caseFoldedMethodHeader) {
		case accessGranted:
			return []attack.Finding{e.caseFoldedFinding(session)}, "", true, ""
		case accessUndetermined:
			return nil, "", true, "the case-folded Mcp-Method probe returned neither a tools/list result nor a header-mismatch rejection"
		}
		return nil, "", true, ""
	}

	// The value is not validated at all: the server executed the body under a header
	// naming a different method.
	return []attack.Finding{
		{
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
		},
	}, "", true, ""
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

// toolsList accepts only a matching listing or an explicit header-mismatch rejection.
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, session mcpSession, shape func(map[string]string)) accessVerdict {
	resp, err := session.postShaping(ctx, client, 2, "tools/list", nil, shape)
	if err != nil || resp == nil {
		return accessUndetermined
	}
	b, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(b, 2) {
		return accessUndetermined
	}
	if resp.StatusCode == http.StatusBadRequest && validRPCError(b) {
		if rpcErrorCode(b["error"].(map[string]interface{})["code"]) == headerMismatchCode {
			return accessRefused
		}
	}
	if resp.IsSuccess() && validRPCResult(b) {
		result, ok := b["result"].(map[string]interface{})
		if ok {
			if _, ok := result["tools"].([]interface{}); ok {
				return accessGranted
			}
		}
	}
	return accessUndetermined
}

// nameProbeSubject is the resource URI and prompt name the Mcp-Name probes ask for.
// It is deliberately absent from every server: the point is to compare which error
// comes back, and a subject that does not exist cannot be executed. That is what
// keeps these probes read-only.
const nameProbeSubject = "batesian-nonexistent-subject"

// nameBearingProbe is one method that carries a subject in its params, and the
// params field the subject travels in.
//
// tools/call is deliberately absent. Testing Mcp-Name on it would mean sending a
// tools/call whose header disagrees with its body, and a server that does not
// validate the header is exactly a server that would then EXECUTE the tool. A
// scanner must not invoke a tool to find out. resources/read and prompts/get are
// reads, and with a subject that does not exist there is nothing to read.
type nameBearingProbe struct {
	method     string
	field      string
	capability string
}

var nameBearingProbes = []nameBearingProbe{
	{"resources/read", "uri", "resources"},
	{"prompts/get", "name", "prompts"},
}

// probeName tests the Mcp-Name header on one wire.
//
// Mcp-Name is REQUIRED for tools/call, resources/read and prompts/get, its value
// MUST match params.name or params.uri, and a missing or mismatched value MUST earn
// 400 with -32020. The rule covered only Mcp-Method, so a server that validated the
// method and ignored the name passed: an intermediary blocklisting a dangerous tool
// or resource by name inspects Mcp-Name, and that is the header this exercises.
func (e *HeaderBodySplitExecutor) probeName(ctx context.Context, client *attack.HTTPClient,
	session mcpSession) (findings []attack.Finding, tested bool, blocked string) {
	for _, np := range nameBearingProbes {
		if !session.ServerSupports(np.capability) {
			continue
		}
		params := map[string]interface{}{np.field: nameProbeSubject}

		// Control: omit Mcp-Name. A dispatch here means presence is not enforced.
		omitted := e.nameVerdict(ctx, client, session, np, params, func(h map[string]string) {
			delete(h, "Mcp-Name")
		})
		switch omitted {
		case nameNotImplemented:
			blocked = "the server advertised " + np.capability + " but " + np.method + " returned method not found"
			continue
		case nameUndetermined:
			blocked = "the " + np.method + " probe with no Mcp-Name header returned neither a " +
				"header-mismatch error nor a dispatched answer, so whether the server enforces " +
				"Mcp-Name presence could not be established"
			continue
		case nameDispatched:
			// Presence is not enforced, so a mismatch here would prove nothing about
			// value validation and this method is not a surface for the dimension.
			//
			// Deliberately NOT a finding, for consistency with how the Mcp-Method
			// dimension treats the same observation: omission is the PRECONDITION
			// detector for both, and this rule's subject is whether the value is
			// validated. The binding does list "a required standard header
			// (MCP-Protocol-Version, Mcp-Method, Mcp-Name) is missing" as its own
			// validation failure, so a server that dispatches without one is violating
			// something, and reporting that is a separate rule with its own oracle
			// rather than a second verdict smuggled into this one. Reporting it here for
			// Mcp-Name while the Mcp-Method path called the identical observation
			// "not SEP-2243-aware" was incoherent, which the existing tests caught.
			continue
		}

		// Presence is enforced. Now the value: same body, a name that disagrees.
		mismatched := e.nameVerdict(ctx, client, session, np, params, func(h map[string]string) {
			h["Mcp-Name"] = nameProbeSubject + "-different"
		})
		switch mismatched {
		case nameRejected:
			tested = true
		case nameDispatched:
			return []attack.Finding{e.nameMismatchFinding(session, np)}, true, ""
		default:
			blocked = "the " + np.method + " probe with a mismatched Mcp-Name header returned " +
				"neither a header-mismatch error nor a dispatched answer, so the value check " +
				"could not be established"
		}
	}
	return nil, tested, blocked
}

// nameVerdict grades one shaped name-bearing call by which error came back.
type nameVerdict int

const (
	// nameUndetermined: a transport failure, or an answer that settles nothing.
	nameUndetermined nameVerdict = iota
	// nameRejected: -32020 HeaderMismatch, so the header was validated.
	nameRejected
	// nameDispatched: the server acted on the body rather than rejecting the
	// header, whether it answered a result or a subject-not-found error.
	nameDispatched
	// nameNotImplemented: -32601, so this method is not a surface here.
	nameNotImplemented
)

func (e *HeaderBodySplitExecutor) nameVerdict(ctx context.Context, client *attack.HTTPClient,
	session mcpSession, np nameBearingProbe, params map[string]interface{},
	shape func(map[string]string)) nameVerdict {
	resp, err := session.postShaping(ctx, client, 3, np.method, params, shape)
	if err != nil || resp == nil {
		return nameUndetermined
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok || !matchesRPCID(body, 3) {
		return nameUndetermined
	}
	if resp.IsSuccess() && validRPCResult(body) {
		// A result for a subject that does not exist is odd, but it is still the
		// server acting on the body rather than rejecting the header.
		return nameDispatched
	}
	if !validRPCError(body) {
		return nameUndetermined
	}
	code := rpcErrorCode(body["error"].(map[string]interface{})["code"])
	if resp.StatusCode == http.StatusBadRequest && code == headerMismatchCode {
		return nameRejected
	}
	if !resp.IsSuccess() {
		return nameUndetermined
	}
	if code == mcpMethodNotFound {
		return nameNotImplemented
	}
	message, _ := body["error"].(map[string]interface{})["message"].(string)
	if strings.Contains(strings.ToLower(message), "not found") && strings.Contains(message, nameProbeSubject) {
		return nameDispatched
	}
	return nameUndetermined
}

// caseFoldedMethodHeader spells the body's method in upper case. Header VALUES are
// case-sensitive per the specification ("Header values (such as method names) are
// case-sensitive"), so a server that treats this as equal to the body's tools/list
// is comparing case-insensitively, and an intermediary matching an exact method name
// can be walked past with a different spelling.
func caseFoldedMethodHeader(h map[string]string) { h["Mcp-Method"] = "TOOLS/LIST" }

// nameMismatchFinding: the header said one subject, the body another, and the server
// acted on the body. Same class and severity as the Mcp-Method split, because the
// bypass is the same: an intermediary inspecting the header sees a value the server
// never used.
func (e *HeaderBodySplitExecutor) nameMismatchFinding(session mcpSession, np nameBearingProbe) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server does not validate Mcp-Name against the request body (SEP-2243 split-brain)",
		Description: fmt.Sprintf(
			"At %s, a %s request was REJECTED when the Mcp-Name header was omitted (the server "+
				"enforces header presence), but a request whose Mcp-Name disagreed with params.%s was "+
				"acted on rather than refused. The Streamable HTTP binding makes Mcp-Name REQUIRED for "+
				"tools/call, resources/read and prompts/get, requires its value to match the body, and "+
				"requires a mismatch to be rejected with 400 and -32020 (HeaderMismatch). An "+
				"intermediary that blocklists or routes on the named subject, which is how a gateway "+
				"gates a dangerous tool or resource, inspects a value this server does not enforce, so "+
				"the body can name something else.",
			session.Endpoint, np.method, np.field),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nmethod: %s\nomit Mcp-Name: rejected with -32020 (presence enforced)\n"+
				"Mcp-Name disagreeing with params.%s: acted on the body (should be 400/-32020)\n"+
				"subject probed: %s (deliberately absent, so nothing was executed)",
			session.Endpoint, np.method, np.field, nameProbeSubject),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}

// caseFoldedFinding: the server validates the Mcp-Method value but compares it
// case-insensitively, so an exact-match intermediary can be walked past.
func (e *HeaderBodySplitExecutor) caseFoldedFinding(session mcpSession) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP server compares the Mcp-Method value case-insensitively (SEP-2243)",
		Description: fmt.Sprintf(
			"At %s, a tools/list request was rejected when Mcp-Method disagreed with the body, so the "+
				"value is validated, but the same request with Mcp-Method: TOOLS/LIST was executed. The "+
				"binding states that header names are case-insensitive while header VALUES, such as "+
				"method names, are case-sensitive, so the two spellings are different values and the "+
				"mismatch MUST be rejected. An intermediary matching an exact method name sees a "+
				"spelling it does not recognize while the server executes the body regardless.",
			session.Endpoint),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nMcp-Method: tools/call (mismatch): rejected, so the value is validated\n"+
				"Mcp-Method: TOOLS/LIST (case-folded) + body tools/list: EXECUTED body "+
				"(should be 400/-32020)",
			session.Endpoint),
		Remediation: e.rule.Remediation,
		TargetURL:   session.Endpoint,
	}
}
