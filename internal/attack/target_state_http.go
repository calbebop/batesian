package attack

import (
	"encoding/json"
	"net/url"
	"strings"
)

type taskResult struct {
	ID   string      `json:"id"`
	Task *taskResult `json:"task"`
}

func recordA2ATask(state *TargetState, endpoint string, request []byte, resp *Response) {
	if state == nil || resp == nil || !resp.IsSuccess() {
		return
	}
	var call struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(request, &call) != nil {
		return
	}
	isRPC := call.Method == "SendMessage" || call.Method == "message/send" || call.Method == "tasks/send"
	isREST := false
	if parsed, err := url.Parse(endpoint); err == nil {
		isREST = strings.HasSuffix(parsed.Path, "/message:send")
	}
	if !isRPC && !isREST {
		return
	}
	if isRPC && !resp.IsAccepted() {
		return
	}
	body := resp.Body
	if isRPC {
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(body, &envelope) != nil || len(envelope.Result) == 0 {
			return
		}
		body = envelope.Result
	}
	var result taskResult
	if json.Unmarshal(body, &result) != nil {
		return
	}
	if result.Task != nil {
		result = *result.Task
	}
	if result.ID == "" {
		return
	}
	state.Record(TargetObject{
		Kind:          "a2a_task",
		Creation:      "accepted",
		ID:            result.ID,
		Endpoint:      endpoint,
		Cleanup:       CleanupUnavailable,
		CleanupDetail: "A2A has no task deletion operation",
	})
}

func recordMCPTask(state *TargetState, endpoint string, request []byte, resp *Response) {
	if state == nil || resp == nil {
		return
	}
	var call struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(request, &call) != nil || call.Method != "tools/call" {
		return
	}
	if !resp.IsAccepted() {
		return
	}
	var envelope struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Task       struct {
				TaskID string `json:"taskId"`
			} `json:"task"`
		} `json:"result"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil {
		return
	}
	id := envelope.Result.Task.TaskID
	if id == "" && envelope.Result.ResultType == "task" {
		id = envelope.Result.TaskID
	}
	if id == "" {
		return
	}
	state.Record(TargetObject{
		Kind:          "mcp_task",
		Creation:      "accepted",
		ID:            id,
		Endpoint:      endpoint,
		Cleanup:       CleanupUnavailable,
		CleanupDetail: "MCP Tasks has no task deletion operation; cancellation is not deletion",
	})
}
