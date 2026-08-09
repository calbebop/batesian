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

		// Mcp-Name is a separate required header on the name-bearing methods, with the
		// same MUST behind it, and a server can validate Mcp-Method while ignoring it.
		// It is probed independently so one dimension passing does not hide the other.
		nf, nameTested, nameBlocked := e.probeName(ctx, client, session)
		findings = append(findings, labelEra(session, nf)...)
		if nameTested {
			anyTested = true
		}
		if nameBlocked != "" && nameBlockedReason == "" {
			nameBlockedReason = nameBlocked
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
	// A run that could not reach the mismatch probe has not shown the header/body
	// surface to be sound. This used to fall through to clean, so any server whose
	// tools/list is credential-gated, or which answers -32601 because it exposes no
	// tools, had its SEP-2243 handling reported as fine without a single mismatch
	// being sent.
	if blockedReason != "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, blockedReason)
	}
	// Last resort, and the guard on unawareAt is the point: a wire that carries the
	// requirement and ignores the header is a REASONED clean result (the observation
	// was made, it is simply not this rule's subject), so the name dimension failing to
	// decide must not convert it into "not tested". Only when the Mcp-Method dimension
	// reached no conclusion whatsoever does the name dimension get to explain the run.
	if nameBlockedReason != "" && unawareAt == "" {
		return nil, fmt.Errorf("%w: %s", attack.ErrInconclusive, nameBlockedReason)
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
	if e.toolsList(ctx, client, session, mismatchMethodHeader) != accessGranted {
		// The value IS validated. One narrower way to get it wrong remains: comparing
		// case-insensitively. This runs only here, because a server that ignores the
		// value outright already reports above and a second finding would say the same
		// thing twice.
		if e.toolsList(ctx, client, session, caseFoldedMethodHeader) == accessGranted {
			return []attack.Finding{e.caseFoldedFinding(session)}, "", true, ""
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

// toolsList sends a tools/list body. methodHeader controls the Mcp-Method header:
// nil omits it; otherwise it is set to the given (possibly mismatched) value. It
// reports whether the server EXECUTED tools/list (returned a result.tools array).
// toolsList grades one shaped tools/list call.
//
// This returned a bool, so a transport failure, a 502, a 429 and an unparseable
// body were all indistinguishable from the server REFUSING the call. Probe 1's
// failure is read as "the server enforces Mcp-Method presence", so one transient
// failure on a legacy server carried the rule into probes 2 and 3, which succeed by
// construction there because the header means nothing, and it emitted a
// high/ConfirmedExploit finding asserting presence was enforced on a server with no
// such requirement.
func (e *HeaderBodySplitExecutor) toolsList(ctx context.Context, client *attack.HTTPClient, session mcpSession, shape func(map[string]string)) accessVerdict {
	resp, err := session.postShaping(ctx, client, 2, "tools/list", nil, shape)
	v := classifyAccess(resp, err)
	if v != accessGranted {
		return v
	}
	// A result envelope that is not a tools listing is not an execution of
	// tools/list, and nothing follows from it either way.
	var b map[string]interface{}
	if json.Unmarshal(resp.Body, &b) != nil {
		return accessUndetermined
	}
	result, ok := b["result"].(map[string]interface{})
	if !ok {
		return accessUndetermined
	}
	if _, hasTools := result["tools"]; !hasTools {
		return accessUndetermined
	}
	return accessGranted
}

// headerMismatchCode is the JSON-RPC error a server MUST answer a header/body
// validation failure with. SEP-2243 specified -32001; the specification renumbered
// it into the range reserved for protocol-defined errors, and this rule keys on the
// spec value. It is the oracle for the Mcp-Name probes below, which unlike the
// Mcp-Method ones cannot use "did the body execute": their subject deliberately does
// not exist, so a compliant and a non-compliant server both answer with an error and
// only the CODE separates them.
const headerMismatchCode = -32020

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
	method string
	field  string
}

var nameBearingProbes = []nameBearingProbe{
	{"resources/read", "uri"},
	{"prompts/get", "name"},
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
		params := map[string]interface{}{np.field: nameProbeSubject}

		// Control: omit Mcp-Name. A dispatch here means presence is not enforced.
		omitted := e.nameVerdict(ctx, client, session, np, params, func(h map[string]string) {
			delete(h, "Mcp-Name")
		})
		switch omitted {
		case nameNotImplemented:
			continue // this server does not offer the method; try the next one
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
			return nil, true, "" // validated: the mismatch was refused with -32020
		case nameDispatched:
			return []attack.Finding{e.nameMismatchFinding(session, np)}, true, ""
		default:
			blocked = "the " + np.method + " probe with a mismatched Mcp-Name header returned " +
				"neither a header-mismatch error nor a dispatched answer, so the value check " +
				"could not be established"
		}
	}
	return nil, false, blocked
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
	if resp.IsAccepted() {
		// A result for a subject that does not exist is odd, but it is still the
		// server acting on the body rather than rejecting the header.
		return nameDispatched
	}
	code, hasErr := jsonRPCErrorCode(resp.Body)
	if !hasErr {
		return nameUndetermined
	}
	switch code {
	case headerMismatchCode:
		return nameRejected
	case mcpMethodNotFound:
		return nameNotImplemented
	}
	// Any other error is the server having dispatched far enough to complain about
	// the subject, the params or authorization, none of which is a header rejection.
	return nameDispatched
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
