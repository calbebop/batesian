package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/calbebop/batesian/internal/attack"
)

// Task-dependent rules are inconclusive when setup is refused or unanswered.
// Explicitly unsupported task surfaces remain not applicable.

// Ranked because a task-creating attempt is made on more than one wire, and the
// wires can fail differently: v1.0 SendMessage may be absent while v0.3
// message/send is refused as unauthorized. The most explanatory observation wins,
// so the answer does not depend on which wire happened to be tried first.
const (
	// setupNothing is the zero value before any setup attempt is classified.
	setupNothing = iota
	// setupFeatureAbsent means the agent does not implement this surface. It is the
	// one outcome that is genuinely not applicable rather than untested, and the
	// only one that still yields a clean result.
	setupFeatureAbsent
	// setupOtherRefusal is any other refusal, or an answer carrying no task.
	setupOtherRefusal
	// setupAuthRefused means authorization blocked the setup probe.
	setupAuthRefused
)

// setupObservation is the best explanation seen while attempting to establish the
// precondition a rule needs.
type setupObservation struct {
	rank   int
	reason string
}

// observe keeps o when it explains more than what is already held.
func (s *setupObservation) observe(o setupObservation) {
	if o.rank > s.rank {
		*s = o
	}
}

// err returns what the rule should report: nil when the absence of a task is a
// genuine not-applicable, and ErrInconclusive carrying the reason otherwise.
//
// Only "the agent does not implement this surface" maps to nil. That follows the
// convention the OAuth-gated rules already use, where a server exposing no OAuth is
// not applicable rather than insecure. Everything else means the rule did not get
// to run, and saying so is the whole point.
func (s setupObservation) err() error {
	switch s.rank {
	case setupFeatureAbsent:
		return nil
	case setupNothing:
		return fmt.Errorf("%w: nothing answered a task-creating request, so there was no task "+
			"to test with", attack.ErrInconclusive)
	default:
		return fmt.Errorf("%w: %s", attack.ErrInconclusive, s.reason)
	}
}

// partialErr keeps an unjudged setup attempt when a later wire creates a task.
func (s setupObservation) partialErr() error {
	if s.rank != setupOtherRefusal {
		return nil
	}
	return fmt.Errorf("%w: an earlier task-creation attempt was unjudged before fallback created a task", attack.ErrInconclusive)
}

func taskSetupReplyAccepted(resp *attack.Response, requestID string) bool {
	if resp == nil || !resp.IsSuccess() {
		return false
	}
	_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	return valid && !hasError && sendReplyHasResult(resp)
}

func sendReplyHasResult(resp *attack.Response) bool {
	if resp == nil || !resp.IsAccepted() {
		return false
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil {
		return false
	}
	var wrapped struct {
		Task    json.RawMessage `json:"task"`
		Message json.RawMessage `json:"message"`
	}
	if json.Unmarshal(envelope.Result, &wrapped) != nil {
		return false
	}
	if len(wrapped.Task) > 0 || len(wrapped.Message) > 0 {
		if len(wrapped.Task) > 0 && len(wrapped.Message) > 0 {
			return false
		}
		if len(wrapped.Task) > 0 {
			envelope.Result = wrapped.Task
		} else {
			envelope.Result = wrapped.Message
		}
	}
	var result struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
		MessageID string            `json:"messageId"`
		Role      json.RawMessage   `json:"role"`
		Parts     []json.RawMessage `json:"parts"`
	}
	if json.Unmarshal(envelope.Result, &result) != nil {
		return false
	}
	return result.ID != "" && result.Status.State != "" ||
		result.MessageID != "" && len(result.Role) > 0 && string(result.Role) != "null" && len(result.Parts) > 0
}

func correlatedTaskSetup(what, endpoint string, credentialed bool, resp *attack.Response, requestID string) setupObservation {
	if resp != nil && resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden &&
		resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed && json.Valid(resp.Body) {
		_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, what + " reply did not match its request ID"}
		}
		if resp.IsSuccess() && !hasError && !sendReplyHasResult(resp) {
			return setupObservation{setupOtherRefusal, what + " reply did not contain a Task or Message"}
		}
	}
	return classifyTaskSetup(what, endpoint, credentialed, resp)
}

// A2A's own error codes for a surface the agent does not offer. A rule cannot test
// what is not implemented, and reporting that as clean is the same call the OAuth
// rules make for a server with no OAuth.
//
//	-32003 PushNotificationNotSupportedError
//	-32004 UnsupportedOperationError
const (
	a2aPushNotSupported     = -32003
	a2aUnsupportedOperation = -32004
)

// jsonRPCMethodNotFound is what a JSON-RPC service returns for a method it does
// not implement, which is how a v0.3-only agent answers the v1.0 method name and
// vice versa.
const jsonRPCMethodNotFound = -32601

// classifyTaskSetup explains why one attempt to establish a task did not produce
// one. what names the attempt, so a rule's reason reads as its own.
//
// resp is nil when the request got no answer at all.
func classifyTaskSetup(what, endpoint string, credentialed bool, resp *attack.Response) setupObservation {
	if resp == nil {
		return setupObservation{setupOtherRefusal, what + " did not answer, so no task existed to test with"}
	}

	// An auth refusal can arrive as an HTTP status or as a JSON-RPC error at HTTP
	// 200. A2A defines no numeric auth code, so the JSON-RPC form is judged on the
	// message, using the one keyword list in internal/attack.
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return setupObservation{setupAuthRefused, fmt.Sprintf(
			"%s at %s was refused with HTTP %d %s, so no task existed to test with",
			what, endpoint, resp.StatusCode, attack.CredentialNote(credentialed))}
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= http.StatusInternalServerError {
		return setupObservation{setupOtherRefusal, fmt.Sprintf(
			"%s at %s returned HTTP %d, so no task existed to test with",
			what, endpoint, resp.StatusCode)}
	}

	code, hasErr := jsonRPCErrorCode(resp.Body)
	msg := jsonRPCErrorMessage(resp.Body)
	if hasErr && attack.AuthFlavoredMessage(msg) {
		return setupObservation{setupAuthRefused, fmt.Sprintf(
			"%s at %s was refused as unauthorized (JSON-RPC %d: %q) %s, so no task existed "+
				"to test with", what, endpoint, code, msg, attack.CredentialNote(credentialed))}
	}
	if hasErr {
		switch code {
		case jsonRPCMethodNotFound, a2aPushNotSupported, a2aUnsupportedOperation:
			// The agent does not offer this surface. Nothing to test, and nothing wrong.
			return setupObservation{setupFeatureAbsent, ""}
		}
		return setupObservation{setupOtherRefusal, fmt.Sprintf(
			"%s at %s was refused (JSON-RPC %d: %q), so no task existed to test with",
			what, endpoint, code, msg)}
	}
	if !resp.IsSuccess() {
		return setupObservation{setupOtherRefusal, fmt.Sprintf(
			"%s at %s was answered with HTTP %d and no JSON-RPC error, so no task existed "+
				"to test with", what, endpoint, resp.StatusCode)}
	}
	// Answered, and carried no task. A2A lets an agent reply with a Message instead
	// of a Task, which is legal and still leaves this rule nothing to work with.
	return setupObservation{setupOtherRefusal, fmt.Sprintf(
		"%s at %s was accepted but the reply carried no task id, so no task existed to "+
			"test with", what, endpoint)}
}

// classifyPushRegistration keeps a failed config write distinct from unsupported push.
func classifyPushRegistration(method string, resp *attack.Response) setupObservation {
	if resp == nil {
		return setupObservation{setupOtherRefusal, method + " push registration did not answer"}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return setupObservation{setupAuthRefused, fmt.Sprintf("%s push registration was refused with HTTP %d", method, resp.StatusCode)}
	}
	if resp.IsSuccess() {
		if attack.AuthFlavoredMessage(jsonRPCErrorMessage(resp.Body)) {
			return setupObservation{setupAuthRefused, method + " push registration was refused as unauthorized"}
		}
		if code, ok := jsonRPCErrorCode(resp.Body); ok {
			switch code {
			case jsonRPCMethodNotFound, a2aPushNotSupported, a2aUnsupportedOperation:
				return setupObservation{setupFeatureAbsent, ""}
			}
		}
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return setupObservation{setupFeatureAbsent, ""}
	}
	return setupObservation{setupOtherRefusal, fmt.Sprintf("%s push registration returned HTTP %d without an accepted config", method, resp.StatusCode)}
}
