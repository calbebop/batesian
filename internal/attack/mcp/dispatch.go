package mcp

import "strings"

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
	m := strings.ToLower(msg)
	for _, kw := range authErrorKeywords {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// authErrorKeywords are message substrings that unambiguously indicate an auth
// rejection. Kept specific to avoid suppressing real findings.
var authErrorKeywords = []string{
	"unauth",
	"authentic",
	"authoriz",
	"forbidden",
	"credential",
	"permission",
	"access denied",
	"not allowed",
	"invalid token",
	"missing token",
	"log in",
	"login",
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
