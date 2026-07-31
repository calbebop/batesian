package mcp

import "testing"

func errBody(code int, msg string) map[string]interface{} {
	// json.Unmarshal decodes numbers as float64, so the fixture must too.
	return map[string]interface{}{"error": map[string]interface{}{"code": float64(code), "message": msg}}
}

func TestClassifyDispatch_ResultEnvelope(t *testing.T) {
	for _, tc := range []map[string]interface{}{
		{"result": map[string]interface{}{}},
		{"result": map[string]interface{}{"completion": map[string]interface{}{}}},
	} {
		sig, code := classifyDispatch(tc)
		if sig != dispatchResult || code != 0 {
			t.Errorf("classifyDispatch(%v) = %d/%d, want result/0", tc, sig, code)
		}
	}
}

func TestClassifyDispatch_ErrorDispatched(t *testing.T) {
	// Any non-auth, non-not-found JSON-RPC error proves the handler ran. This is
	// the convergence fix: tools/completion previously accepted only -32602.
	for _, code := range []int{-32602, -32603, -32600, -32700} {
		sig, got := classifyDispatch(errBody(code, "some validation failure"))
		if sig != dispatchError || got != code {
			t.Errorf("code %d: got %d/%d, want error/%d", code, sig, got, code)
		}
	}
}

func TestClassifyDispatch_MethodNotFound(t *testing.T) {
	sig, _ := classifyDispatch(errBody(-32601, "Method not found"))
	if sig != dispatchNone {
		t.Errorf("got %d, want none (method not found excludes dispatch)", sig)
	}
}

func TestClassifyDispatch_AuthCodes(t *testing.T) {
	for _, code := range []int{-32001, -32002} {
		sig, _ := classifyDispatch(errBody(code, ""))
		if sig != dispatchNone {
			t.Errorf("auth code %d: got %d, want none", code, sig)
		}
	}
}

func TestClassifyDispatch_AuthKeywords(t *testing.T) {
	for _, msg := range []string{
		"Unauthorized", "Authentication required", "authorization denied",
		"Forbidden", "permission denied", "access denied", "not allowed",
		"invalid token", "missing token", "please log in",
	} {
		sig, _ := classifyDispatch(errBody(-32603, msg))
		if sig != dispatchNone {
			t.Errorf("auth message %q: got %d, want none", msg, sig)
		}
	}
}

// TestClassifyDispatch_BareTokenNotSuppressed locks in the precise keyword set:
// a validation message containing bare "token" must NOT be treated as auth and
// must still count as a dispatch, so a real unauth-reachable method is reported.
func TestClassifyDispatch_BareTokenNotSuppressed(t *testing.T) {
	sig, code := classifyDispatch(errBody(-32603, "unexpected token in argument"))
	if sig != dispatchError || code != -32603 {
		t.Errorf("bare-token message: got %d/%d, want error/-32603 (not suppressed)", sig, code)
	}
}

func TestClassifyDispatch_NoResultNoError(t *testing.T) {
	sig, _ := classifyDispatch(map[string]interface{}{"jsonrpc": "2.0"})
	if sig != dispatchNone {
		t.Errorf("got %d, want none", sig)
	}
}

func TestAuthFlavoredError_Code(t *testing.T) {
	if !authFlavoredError(-32001, "") || !authFlavoredError(-32002, "") {
		t.Error("expected -32001/-32002 to be auth-flavored")
	}
	if authFlavoredError(-32602, "Unknown tool") {
		t.Error("-32602 must not be auth-flavored")
	}
}
