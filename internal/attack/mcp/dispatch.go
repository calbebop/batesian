package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// probeVerdict says what a probe attempt established, before its body is
// interpreted. The distinction the rules were missing is the first one: a probe
// that failed to produce an answer is not the same as a server that refused.
type probeVerdict int

const (
	// probeInconclusive means nothing was established. The request failed in
	// transport, or the server answered in a way that carries no protocol-level
	// verdict (a gateway 502, an HTML 500, an empty 400), or the body would not
	// parse. Reporting a surface clean on this basis claims it is secure when it
	// was never tested.
	probeInconclusive probeVerdict = iota
	// probeRejected means the server answered and the answer was not a usable
	// result: an auth status, or a JSON-RPC error. Whether that is authorization
	// being enforced or the method being absent, the surface is closed and a
	// clean result is correct.
	probeRejected
	// probeAnswered means an HTTP 2xx carrying a parseable JSON object, which the
	// caller can interpret.
	probeAnswered
)

// classifyProbe decides what a probe established.
//
// The gate this replaces was `if err != nil || !resp.IsSuccess() { return nil }`
// followed by `if json.Unmarshal(...) != nil { return nil }`, which collapsed
// "refused", "unreachable" and "unparseable" into a clean result. Measured
// against a wide-open server whose listings answered 502, the unauth rules
// reported all three surfaces clean, indistinguishably from the same server
// answering 401.
//
// Every non-2xx that carries a JSON-RPC error stays rejected rather than
// inconclusive, deliberately. A -32601 says the method is absent and a -32001
// says access was denied; both mean the surface is closed, which is what the
// rules concluded before. Only a non-2xx with no protocol-level answer in it
// changes meaning. Keeping that case out of probeAnswered also matters because
// classifyDispatch is documented for 2xx bodies only: a 500 carrying -32603
// would otherwise read as "the handler ran" and invent a finding.
func classifyProbe(resp *attack.Response, err error) (probeVerdict, map[string]interface{}) {
	if err != nil || resp == nil {
		return probeInconclusive, nil
	}

	var body map[string]interface{}
	parsed := json.Unmarshal(resp.Body, &body) == nil && body != nil

	if resp.IsSuccess() {
		if !parsed {
			return probeInconclusive, nil
		}
		return probeAnswered, body
	}

	// An auth status is an answer on its own, whatever the body looks like.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return probeRejected, nil
	}
	// Otherwise the server must have said something in JSON-RPC terms for this to
	// count as an answer.
	if parsed {
		if _, hasErr := body["error"]; hasErr {
			return probeRejected, nil
		}
	}
	return probeInconclusive, nil
}

// authFlavoredError reports whether a JSON-RPC error signals an authentication
// or authorization rejection rather than a request-processing or validation
// error. MCP auth rejections are normally delivered as HTTP 401/403; this guards
// the uncommon case of a server that signals auth failure through a 200 response
// carrying a JSON-RPC error.
//
// The match is deliberately precise. This predicate is used to suppress an
// unauth-reachability finding, and for a scanner a false negative (missing a
// method reachable without auth) is worse than a false positive, so only
// unambiguous auth signals count. Bare substrings that occur in unrelated error
// messages are avoided: in particular "token" alone is not matched, since a
// validation message such as "unexpected token" would otherwise hide a real
// finding.
func authFlavoredError(code int, msg string) bool {
	switch code {
	case -32001, -32002: // unauthenticated / forbidden (project convention)
		return true
	}
	// The keyword list lives in internal/attack so the A2A rules share it; three
	// divergent copies is how a secured agent came to be accused of a bypass.
	return attack.AuthFlavoredMessage(msg)
}

// dispatchSignal classifies how an unauthenticated probe response proves the
// handler was reached past the auth layer.
type dispatchSignal int

const (
	// dispatchNone means the handler was not reached: the method is unsupported
	// (-32601) or auth was enforced via a JSON-RPC error.
	dispatchNone dispatchSignal = iota
	// dispatchResult means the response carried a JSON-RPC result envelope.
	dispatchResult
	// dispatchError means the response carried a non-auth, non-not-found
	// JSON-RPC error, so the handler ran and validated/rejected the request.
	dispatchError
)

// classifyDispatch inspects an unauthenticated probe response body (already
// known to be HTTP 2xx, since the caller returns early on a non-2xx auth gate).
// At HTTP 2xx a result envelope, or any JSON-RPC error that is not "method not
// found" (-32601) and not auth-flavored, means the request was processed past
// the auth layer. It returns the signal and, for dispatchError, the JSON-RPC
// error code.
func classifyDispatch(body map[string]interface{}) (dispatchSignal, int) {
	if errObj, ok := body["error"].(map[string]interface{}); ok {
		c, _ := errObj["code"].(float64)
		msg, _ := errObj["message"].(string)
		code := int(c)
		if code == -32601 {
			return dispatchNone, 0 // method not found despite the advertised capability
		}
		if authFlavoredError(code, msg) {
			return dispatchNone, 0 // auth enforced via a JSON-RPC error
		}
		return dispatchError, code // dispatched: the handler validated and rejected
	}
	if _, ok := body["result"]; ok {
		return dispatchResult, 0
	}
	return dispatchNone, 0
}

// accessVerdict is what an unauthenticated probe established about a surface.
type accessVerdict int

const (
	// accessUndetermined: the server did not say. A transport failure, a bare 202,
	// a 429, a 502, an unparseable body. Nothing about authorization follows.
	accessUndetermined accessVerdict = iota
	// accessGranted: answered with a JSON-RPC result, so no gate stopped the call.
	accessGranted
	// accessRefused: an auth status, or a JSON-RPC error envelope. The server said no.
	accessRefused
)

// classifyAccess grades an unauthenticated probe as granted, refused, or neither.
//
// The rules that compare two probes to each other need this three-way split, and
// deriving "refused" from the absence of acceptance is what made them fabricate
// findings. era_downgrade set granted = resp.IsAccepted() and treated everything
// else as a refusal, so a dual-era server that delivers POST responses over the GET
// stream and answers with a bare 202 Accepted on the legacy wire, which the
// transport permits, looked like a wire that refused an unauthenticated call while
// the stateless wire answered inline. That is a critical/ConfirmedExploit
// "authorization enforced on the legacy wire but not the modern wire" against a
// server enforcing nothing, and a 429 from a rate limiter or a one-off 502
// produced the same report.
//
// A comparison rule must treat accessUndetermined as "no comparison available"
// rather than folding it into either side.
func classifyAccess(resp *attack.Response, err error) accessVerdict {
	if err != nil || resp == nil {
		return accessUndetermined
	}
	if resp.IsAccepted() {
		return accessGranted
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return accessRefused
	}
	var body map[string]interface{}
	if json.Unmarshal(resp.Body, &body) == nil && body != nil {
		if _, hasErr := body["error"]; hasErr {
			return accessRefused
		}
	}
	return accessUndetermined
}
