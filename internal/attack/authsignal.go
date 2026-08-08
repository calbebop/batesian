package attack

import "strings"

// authErrorKeywords are substrings that mark a JSON-RPC error message as an
// authentication or authorization refusal rather than a request-processing or
// validation error.
//
// Bare "token" is deliberately absent. A validation message such as "unexpected
// token" would otherwise read as an auth refusal, which in the rules that gate on
// this either hides a real finding or invents one.
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

// AuthFlavoredMessage reports whether a JSON-RPC error message reads as an auth
// refusal. It is the one place that judgement lives.
//
// Three copies of this list existed and had drifted, which is how a scanner came
// to accuse a correctly secured agent. The A2A copy omitted "authoriz", "access
// denied" and "login", so a batch refused with "Not authorized" was not recognized
// as gated; because that rule's predicate is inverted, the unrecognized refusal
// counted as proof the dispatcher had run, and a2a-jsonrpc-batch-bypass-001
// emitted a high/confirmed "authentication bypassed by JSON-RPC batch wrapping"
// whose evidence read "batch [request]: HTTP 200 (processed)" about a request the
// server had refused. The MCP batch copy diverged the other way, including bare
// "token" that the canonical list excludes on purpose.
func AuthFlavoredMessage(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range authErrorKeywords {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}
