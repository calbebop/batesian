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
func resultReferencesTask(body []byte, taskID, contextID string) bool {
	var envelope struct {
		Result *struct {
			ID        string `json:"id"`
			TaskID    string `json:"taskId"`
			ContextID string `json:"contextId"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Result == nil {
		return false
	}
	r := envelope.Result
	if taskID != "" && (r.ID == taskID || r.TaskID == taskID) {
		return true
	}
	// contextId alone is enough: a continuation accepted into A's context is the
	// boundary crossing, whatever task id the server chose to report.
	return contextID != "" && r.ContextID == contextID
}
