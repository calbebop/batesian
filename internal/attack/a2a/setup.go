package a2a

import (
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// Eight A2A rules need a task before they can test anything: task IDOR, push SSRF,
// session smuggling, context fixation, delegation integrity, multi-tenant
// isolation, push binding, cross-principal cancel. Each of them used to return a
// clean result when no task could be created, and "this agent does not leak tasks
// across principals" and "the scan never got a task" are different claims.
//
// It went unnoticed because it needs an agent that is reachable AND enforces
// authorization, and no fixture in testdata/ is one. Measured against an a2a-sdk
// agent that requires a bearer token: with no credential three rules reported
// clean, and with two configured principals whose tokens the agent rejected, eight
// did. That is the shape of every correctly secured production deployment scanned
// with the wrong credential, which is the worst place to be silently wrong.
//
// a2a-artifact-tamper-001 already reported this honestly, because PR #150 fixed it
// there. This is the same fix for the rest, with one shared judgement rather than
// eight copies.

// Ranked because a task-creating attempt is made on more than one wire, and the
// wires can fail differently: v1.0 SendMessage may be absent while v0.3
// message/send is refused as unauthorized. The most explanatory observation wins,
// so the answer does not depend on which wire happened to be tried first.
const (
	// setupNothing is the zero value: no answer was obtained at all.
	setupNothing = iota
	// setupFeatureAbsent means the agent does not implement this surface. It is the
	// one outcome that is genuinely not applicable rather than untested, and the
	// only one that still yields a clean result.
	setupFeatureAbsent
	// setupOtherRefusal is any other refusal, or an answer carrying no task.
	setupOtherRefusal
	// setupAuthRefused is an authorization refusal, which is the case that used to
	// be read as clean.
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

// errIfAuthRefused is err() narrowed to authorization refusals.
//
// Two rules send a request the agent is SUPPOSED to reject, so for them a non-auth
// rejection is the secure behaviour they test for rather than a failure to test:
// a2a-session-smuggle-001 sends a message claiming the agent role, which the
// specification requires the server to refuse, and a2a-context-fixation-001 sends a
// client-chosen contextId, which a server is right to refuse outright. Mapping
// those refusals to "not tested" would take a genuine pass away from every
// well-behaved agent. An authorization refusal is different in kind: it says nothing
// about the behaviour under test, because the request never reached it.
func (s setupObservation) errIfAuthRefused() error {
	if s.rank != setupAuthRefused {
		return nil
	}
	return s.err()
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
		return setupObservation{}
	}

	// An auth refusal can arrive as an HTTP status or as a JSON-RPC error at HTTP
	// 200. A2A defines no numeric auth code, so the JSON-RPC form is judged on the
	// message, using the one keyword list in internal/attack.
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return setupObservation{setupAuthRefused, fmt.Sprintf(
			"%s at %s was refused with HTTP %d %s, so no task existed to test with",
			what, endpoint, resp.StatusCode, attack.CredentialNote(credentialed))}
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
