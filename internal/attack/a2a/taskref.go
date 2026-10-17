package a2a

import (
	"encoding/json"
)

func taskResultContext(result json.RawMessage) (taskID, contextID string) {
	_, taskID, contextID = validatedTaskResult(result)
	return taskID, contextID
}

func validatedTaskResult(result json.RawMessage) (json.RawMessage, string, string) {
	var reply map[string]json.RawMessage
	if json.Unmarshal(result, &reply) != nil || reply == nil {
		return nil, "", ""
	}
	if task, ok := reply["task"]; ok {
		if _, hasMessage := reply["message"]; hasMessage {
			return nil, "", ""
		}
		result = task
	} else if _, hasMessage := reply["message"]; hasMessage {
		return nil, "", ""
	}
	var task struct {
		Kind      string `json:"kind"`
		ID        string `json:"id"`
		ContextID string `json:"contextId"`
		Status    struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if json.Unmarshal(result, &task) != nil ||
		(task.Kind != "" && task.Kind != "task") || task.ID == "" || task.Status.State == "" {
		return nil, "", ""
	}
	return result, task.ID, task.ContextID
}

// restTaskPageToken accepts legacy lists without a continuation field.
func restTaskPageToken(body []byte) (string, bool) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) == nil && envelope != nil {
		raw, present := envelope["nextPageToken"]
		if !present {
			return "", true
		}
		var token *string
		if json.Unmarshal(raw, &token) != nil || token == nil {
			return "", false
		}
		return *token, true
	}
	var bare []json.RawMessage
	if json.Unmarshal(body, &bare) == nil && bare != nil {
		return "", true
	}
	return "", false
}

func parseRESTTaskListPage(body []byte) ([]string, string, bool) {
	type task struct {
		ID     string `json:"id"`
		TaskID string `json:"taskId"`
	}
	var wrapped struct {
		Tasks *[]task `json:"tasks"`
	}
	var tasks []task
	if json.Unmarshal(body, &wrapped) == nil && wrapped.Tasks != nil {
		tasks = *wrapped.Tasks
	} else if json.Unmarshal(body, &tasks) != nil || tasks == nil {
		return nil, "", false
	}
	ids := make([]string, 0, len(tasks))
	for _, t := range tasks {
		id := t.ID
		if id == "" {
			id = t.TaskID
		}
		if id == "" {
			return nil, "", false
		}
		ids = append(ids, id)
	}
	token, ok := restTaskPageToken(body)
	return ids, token, ok
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
