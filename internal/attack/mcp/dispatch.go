package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/calbebop/batesian/internal/attack"
)

// probeVerdict records whether a probe received a usable answer.
type probeVerdict int

const (
	// probeInconclusive means no protocol-level verdict was established.
	probeInconclusive probeVerdict = iota
	// probeRejected means an auth status or matching JSON-RPC error was returned.
	probeRejected
	// probeAnswered means a matching JSON-RPC response arrived over HTTP 2xx.
	probeAnswered
)

// classifyProbe requires the response ID to match, except for HTTP 401/403.
func classifyProbe(resp *attack.Response, err error, expectedID int) (probeVerdict, map[string]interface{}) {
	if err != nil || resp == nil {
		return probeInconclusive, nil
	}

	body, parsed := parseResponseBody(resp.Body)
	if parsed {
		id, ok := body["id"].(json.Number)
		parsed = ok && id.String() == strconv.Itoa(expectedID)
	}

	if resp.IsSuccess() {
		if !parsed || (!validRPCResult(body) && !validRPCError(body)) {
			return probeInconclusive, nil
		}
		return probeAnswered, body
	}

	// An auth status is an answer on its own, whatever the body looks like.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return probeRejected, nil
	}
	if parsed && validRPCError(body) {
		return probeRejected, nil
	}
	return probeInconclusive, nil
}

func parseResponseBody(raw []byte) (map[string]interface{}, bool) {
	var body map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&body) != nil || body == nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return body, true
}

func validRPCResult(body map[string]interface{}) bool {
	if body["jsonrpc"] != "2.0" {
		return false
	}
	if _, hasID := body["id"]; !hasID {
		return false
	}
	if _, hasError := body["error"]; hasError {
		return false
	}
	_, hasResult := body["result"]
	return hasResult
}

func validRPCError(body map[string]interface{}) bool {
	if body["jsonrpc"] != "2.0" {
		return false
	}
	if _, hasID := body["id"]; !hasID {
		return false
	}
	if _, hasResult := body["result"]; hasResult {
		return false
	}
	errObj, ok := body["error"].(map[string]interface{})
	if !ok {
		return false
	}
	code, ok := errObj["code"].(json.Number)
	if !ok {
		return false
	}
	if _, err := strconv.ParseInt(code.String(), 10, 64); err != nil {
		return false
	}
	_, ok = errObj["message"].(string)
	return ok
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
		msg, _ := errObj["message"].(string)
		code := rpcErrorCode(errObj["code"])
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

func rpcErrorCode(value interface{}) int {
	switch code := value.(type) {
	case json.Number:
		parsed, _ := strconv.Atoi(code.String())
		return parsed
	case float64:
		return int(code)
	default:
		return 0
	}
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
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return accessRefused
	}
	body, ok := parseResponseBody(resp.Body)
	if !ok {
		return accessUndetermined
	}
	if resp.IsSuccess() && validRPCResult(body) {
		return accessGranted
	}
	if validRPCError(body) {
		return accessRefused
	}
	return accessUndetermined
}
