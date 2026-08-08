package attack

import "testing"

// Three copies of this judgement existed and drifted. The A2A copy omitted
// "authoriz", "access denied" and "login", which is how a correctly secured agent
// was accused of a JSON-RPC batch auth bypass.
func TestAuthFlavoredMessage(t *testing.T) {
	refusals := []string{
		"Not authorized", "Unauthorized", "Access denied", "Forbidden",
		"Login required", "Please log in", "Invalid token", "Missing token",
		"Authentication failed", "insufficient permission", "missing credential",
		"NOT ALLOWED",
	}
	for _, msg := range refusals {
		if !AuthFlavoredMessage(msg) {
			t.Errorf("AuthFlavoredMessage(%q) = false; a refusal in this wording was read as a "+
				"processed request, which is what accused a secured agent", msg)
		}
	}

	// Bare "token" is excluded on purpose: a validation message must not pass as an
	// auth refusal, or the batch rules attempt a bypass against an ungated method.
	notRefusals := []string{
		"unexpected token in JSON at position 4", "Invalid params", "Method not found",
		"Task not found", "Internal error", "",
	}
	for _, msg := range notRefusals {
		if AuthFlavoredMessage(msg) {
			t.Errorf("AuthFlavoredMessage(%q) = true; this is not an auth refusal", msg)
		}
	}
}
