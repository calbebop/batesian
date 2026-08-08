package a2a

import "encoding/json"

// resultReferencesTask reports whether a JSON-RPC result really is the task
// identified by taskID/contextID, by comparing the identifiers rather than
// searching the body for text.
//
// Two rules used to decide this with
// resp.ContainsAny(`"history"`, `"contextId"`, taskID, contextID). ContainsAny is
// OR, and the first two needles are KEY NAMES present in virtually every A2A Task
// envelope, so the check reduced to "the caller got some accepted result".
//
// That is a live false positive in a2a-delegation-integrity-001, which asks
// whether principal B's continuation landed on principal A's task. A server with
// tenant-scoped task stores does not error on an unknown taskId: it treats the
// message as a new conversation and answers with a NEW task, whose envelope
// contains "contextId" and therefore matched. The rule then emitted
// high/ConfirmedExploit "A2A delegated task continued by the wrong principal",
// with a chain step asserting the wrong principal advanced the delegated step,
// about a server that had correctly refused to expose A's task.
//
// a2a-multitenant-isolation-001 carried the same needles. There the secure answer
// to a get-by-id is a JSON-RPC error, which IsAccepted already filters, so it was
// latent rather than live; it is corrected here because the flaw is identical.
//
// A Task carries id and contextId in both revisions. A result that is a Message
// rather than a Task has neither, and returns false: whether it touched A's task
// cannot be established from it.
//
// Both envelope shapes are read, and the first version of this helper knew only the
// flat one, which cost a2a-delegation-integrity-001 its whole oracle on the v1.0
// wire. In v1.0 a send-style reply is a SendMessageResponse, a protobuf oneof of
// task or message, so protobuf JSON mapping renders the Task NESTED under
// result.task. GetTask returns a bare Task, so it arrives flat. Reading only the
// flat shape therefore worked for the read checks and silently failed for the
// continuation check: measured against an a2a-sdk agent with no ownership check,
// principal B's continuation landed on A's task, the agent confirmed it by
// returning A's task under result.task, and the rule reported that the delegation
// binding held.
func resultReferencesTask(body []byte, taskID, contextID string) bool {
	// task carries the identifiers wherever it appears in the envelope.
	type task struct {
		ID        string `json:"id"`
		TaskID    string `json:"taskId"`
		ContextID string `json:"contextId"`
	}
	var envelope struct {
		Result *struct {
			task
			// v1.0 send-style responses: the oneof member's field name.
			Task *task `json:"task"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Result == nil {
		return false
	}
	candidates := []task{envelope.Result.task}
	if envelope.Result.Task != nil {
		candidates = append(candidates, *envelope.Result.Task)
	}
	for _, c := range candidates {
		if taskID != "" && (c.ID == taskID || c.TaskID == taskID) {
			return true
		}
		// contextId alone is enough: a continuation accepted into A's context is the
		// boundary crossing, whatever task id the server chose to report.
		if contextID != "" && c.ContextID == contextID {
			return true
		}
	}
	return false
}
