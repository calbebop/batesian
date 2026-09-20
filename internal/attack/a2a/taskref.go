package a2a

import (
	"encoding/json"
	"strings"
)

// resultReferencesTask matches task or context identifiers in bare Task results
// and nested v1.0 SendMessageResponse tasks. Message results cannot prove access.
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

// countListedTasks counts non-empty task objects in an envelope or bare array.
// Empty collections, objects, and count-only responses do not prove disclosure.
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
