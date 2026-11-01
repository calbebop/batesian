package mcp

import (
	"encoding/json"
	"testing"
)

func errBody(code int, msg string) map[string]interface{} {
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

func TestClassifyDispatch_JSONNumberCodes(t *testing.T) {
	tests := []struct {
		code     string
		want     dispatchSignal
		wantCode int
	}{
		{"-32601", dispatchNone, 0},
		{"-32001", dispatchNone, 0},
		{"-32602", dispatchError, -32602},
	}
	for _, tc := range tests {
		body := map[string]interface{}{"error": map[string]interface{}{
			"code": json.Number(tc.code), "message": "validation failure",
		}}
		sig, code := classifyDispatch(body)
		if sig != tc.want || code != tc.wantCode {
			t.Errorf("code %s: got %d/%d, want %d/%d", tc.code, sig, code, tc.want, tc.wantCode)
		}
	}
}

func TestClassifyDispatch_AmbiguousSessionCode(t *testing.T) {
	for _, msg := range []string{"", "Session not found", "Permission denied"} {
		sig, _ := classifyDispatch(errBody(-32001, msg))
		if sig != dispatchNone {
			t.Errorf("session code %q: got %d, want none", msg, sig)
		}
	}
}

func TestClassifyDispatch_LegacyResourceNotFound(t *testing.T) {
	sig, code := classifyDispatch(errBody(-32002, "Resource not found"))
	if sig != dispatchError || code != -32002 {
		t.Errorf("resource error: got %d/%d, want error/-32002", sig, code)
	}
	for _, msg := range []string{"", "Permission denied"} {
		sig, _ := classifyDispatch(errBody(-32002, msg))
		if sig != dispatchNone {
			t.Errorf("resource code %q: got %d, want none", msg, sig)
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
	if !authFlavoredError(-32001, "Unauthorized") || !authFlavoredError(-32002, "Permission denied") {
		t.Error("expected explicit auth refusals to be recognized")
	}
	if authFlavoredError(-32001, "Session not found") || authFlavoredError(-32001, "") ||
		authFlavoredError(-32002, "Resource not found") || authFlavoredError(-32002, "") ||
		authFlavoredError(-32602, "Unknown tool") {
		t.Error("resource and validation errors must not be treated as auth refusals")
	}
}
