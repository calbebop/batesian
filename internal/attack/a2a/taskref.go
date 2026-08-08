package a2a

import (
	"encoding/json"
	"strings"
)

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

// countListedTasks returns how many tasks a task-list response actually carried.
//
// The oracle it replaced was ContainsAny(`"tasks"`, `"contextId"`, `"history"`) over
// the raw body, which are KEY NAMES. A server that scopes its list correctly and
// answers an anonymous caller with {"tasks":[],"totalSize":0} contains `"tasks"`, so
// it matched, and a2a-task-idor-001 reported "server-wide task disclosure" at
// critical/confirmed against a server that disclosed nothing at all. That is the same
// vacuous-needle class as the checks corrected in PR #163 and PR #169, and the
// highest-severity instance of it.
//
// Both shapes are counted: the documented {"tasks":[...]} envelope, and the bare
// array some REST bindings return. An element counts only when it is an object with
// at least one non-empty field, so an empty list, a list of empty objects, and a
// bare count all fail to qualify. Something has to have been disclosed before this
// says something was disclosed.
func countListedTasks(body []byte) int {
	var envelope struct {
		Tasks []map[string]json.RawMessage `json:"tasks"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Tasks != nil {
		return countNonEmpty(envelope.Tasks)
	}
	var bare []map[string]json.RawMessage
	if json.Unmarshal(body, &bare) == nil {
		return countNonEmpty(bare)
	}
	return 0
}

// countNonEmpty counts objects carrying at least one field with a non-empty value.
func countNonEmpty(items []map[string]json.RawMessage) int {
	n := 0
	for _, item := range items {
		for _, v := range item {
			s := strings.TrimSpace(string(v))
			if s != "" && s != "null" && s != `""` && s != "{}" && s != "[]" {
				n++
				break
			}
		}
	}
	return n
}

// listedTaskIDs returns the task identifiers a list response carried.
//
// Identifiers, never key names: a2a-task-enumeration-001 asks whether one
// principal's task appears in another principal's listing, and that question can only
// be answered by comparing ids. The same body-shape knowledge as countListedTasks
// lives here so the two cannot disagree about what a list looks like.
//
// Three envelopes are read. ListTasks over JSON-RPC answers {"result":{"tasks":[...]}}
// and, unlike a send-style reply, is not a oneof, so the tasks sit directly under
// result. The other two are the bare {"tasks":[...]} and the plain array that REST
// bindings return.
func listedTaskIDs(body []byte) []string {
	type task struct {
		ID     string `json:"id"`
		TaskID string `json:"taskId"`
	}
	collect := func(tasks []task) []string {
		out := make([]string, 0, len(tasks))
		for _, t := range tasks {
			switch {
			case t.ID != "":
				out = append(out, t.ID)
			case t.TaskID != "":
				out = append(out, t.TaskID)
			}
		}
		return out
	}

	var wrapped struct {
		Result *struct {
			Tasks []task `json:"tasks"`
		} `json:"result"`
		Tasks []task `json:"tasks"`
	}
	if json.Unmarshal(body, &wrapped) == nil {
		if wrapped.Result != nil && wrapped.Result.Tasks != nil {
			return collect(wrapped.Result.Tasks)
		}
		if wrapped.Tasks != nil {
			return collect(wrapped.Tasks)
		}
	}
	var bare []task
	if json.Unmarshal(body, &bare) == nil {
		return collect(bare)
	}
	return nil
}

// containsTaskID reports whether ids includes want.
func containsTaskID(ids []string, want string) bool {
	if want == "" {
		return false
	}
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
