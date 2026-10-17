package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type pushSetupObservation struct {
	best       setupObservation
	incomplete error
}

func (s *pushSetupObservation) observe(o setupObservation) {
	s.best.observe(o)
	if o.rank == setupOtherRefusal {
		s.incomplete = errors.Join(s.incomplete, fmt.Errorf("%w: %s", attack.ErrInconclusive, o.reason))
	}
}

func (s pushSetupObservation) err() error {
	return s.best.err()
}

func (s pushSetupObservation) partialErr() error {
	return s.incomplete
}

func pushTaskReplyID(resp *attack.Response, requestID string) string {
	if resp == nil || !resp.IsSuccess() {
		return ""
	}
	result, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid || hasError {
		return ""
	}
	return pushTaskResultID(result)
}

func pushTaskResultID(result json.RawMessage) string {
	var reply map[string]json.RawMessage
	if json.Unmarshal(result, &reply) != nil || reply == nil {
		return ""
	}
	if task, ok := reply["task"]; ok {
		if _, hasMessage := reply["message"]; hasMessage {
			return ""
		}
		result = task
	} else if _, hasMessage := reply["message"]; hasMessage {
		return ""
	}
	var task struct {
		Kind   string `json:"kind"`
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if json.Unmarshal(result, &task) != nil ||
		(task.Kind != "" && task.Kind != "task") || task.ID == "" || task.Status.State == "" {
		return ""
	}
	return task.ID
}

func pushMessageResultAccepted(result json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(result, &fields) != nil || fields == nil {
		return false
	}
	if _, hasTask := fields["task"]; hasTask {
		return false
	}
	if message, wrapped := fields["message"]; wrapped {
		result = message
		if json.Unmarshal(result, &fields) != nil || fields == nil {
			return false
		}
	}
	if _, hasID := fields["id"]; hasID {
		return false
	}
	if _, hasStatus := fields["status"]; hasStatus {
		return false
	}
	var message struct {
		Kind      string            `json:"kind"`
		MessageID string            `json:"messageId"`
		Role      json.RawMessage   `json:"role"`
		Parts     []json.RawMessage `json:"parts"`
	}
	return json.Unmarshal(result, &message) == nil &&
		(message.Kind == "" || message.Kind == "message") &&
		message.MessageID != "" && len(message.Role) > 0 && string(message.Role) != "null" &&
		len(message.Parts) > 0
}

func restPushTaskID(resp *attack.Response) string {
	if resp == nil || !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) {
		return ""
	}
	return pushTaskResultID(resp.Body)
}

func pushRegistrationReplyAccepted(resp *attack.Response, requestID, method, taskID, callbackURL string) bool {
	if resp == nil || !resp.IsSuccess() {
		return false
	}
	result, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid || hasError {
		return false
	}
	var config struct {
		TaskID                 string `json:"taskId"`
		URL                    string `json:"url"`
		PushNotificationConfig *struct {
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	}
	if json.Unmarshal(result, &config) != nil || config.TaskID != taskID || callbackURL == "" {
		return false
	}
	if method == "CreateTaskPushNotificationConfig" {
		return config.URL == callbackURL
	}
	return method == "tasks/pushNotificationConfig/set" && config.PushNotificationConfig != nil &&
		config.PushNotificationConfig.URL == callbackURL
}

func pushTaskSetupOutcome(what, endpoint string, credentialed bool, resp *attack.Response, requestID string) setupObservation {
	if resp != nil && resp.IsSuccess() {
		result, _, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, what + " reply did not match its request ID"}
		}
		if !hasError && pushTaskReplyID(resp, requestID) == "" {
			if pushMessageResultAccepted(result) {
				return setupObservation{rank: setupFeatureAbsent}
			}
			return setupObservation{setupOtherRefusal, what + " reply did not contain a Task or Message"}
		}
	}
	return classifyPushTaskSetup(what, endpoint, credentialed, resp)
}

func pushRegistrationOutcome(method string, resp *attack.Response, requestID, taskID, callbackURL string) setupObservation {
	if resp != nil && resp.IsSuccess() {
		_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, method + " reply did not match its request ID"}
		}
		if !hasError && !pushRegistrationReplyAccepted(resp, requestID, method, taskID, callbackURL) {
			return setupObservation{setupOtherRefusal, method + " reply did not confirm the task and callback URL"}
		}
	}
	return classifyPushRegistration(method, resp)
}

func restPushRegistrationReplyAccepted(resp *attack.Response, taskID, callbackURL, version string) bool {
	if resp == nil || !resp.IsSuccess() || !resp.IsJSON() || isJSONRPCError(resp.Body) || callbackURL == "" {
		return false
	}
	var config struct {
		TaskID                 string `json:"taskId"`
		URL                    string `json:"url"`
		Name                   string `json:"name"`
		PushNotificationConfig *struct {
			URL string `json:"url"`
		} `json:"pushNotificationConfig"`
	}
	if json.Unmarshal(resp.Body, &config) != nil {
		return false
	}
	if version == "1.0" {
		return config.URL == callbackURL && (config.TaskID == "" || config.TaskID == taskID)
	}
	prefix := "tasks/" + taskID + "/pushNotificationConfigs/"
	return version == "0.3.0" && config.PushNotificationConfig != nil &&
		config.PushNotificationConfig.URL == callbackURL &&
		strings.HasPrefix(config.Name, prefix) && len(config.Name) > len(prefix)
}

func restPushRegistrationOutcome(method string, resp *attack.Response, taskID, callbackURL, version string) setupObservation {
	if resp != nil && resp.IsSuccess() && resp.IsJSON() && !isJSONRPCError(resp.Body) &&
		!restPushRegistrationReplyAccepted(resp, taskID, callbackURL, version) {
		return setupObservation{setupOtherRefusal, method + " reply did not confirm the task and callback URL"}
	}
	return classifyPushRegistration(method, resp)
}

func classifyPushTaskSetup(what, endpoint string, credentialed bool, resp *attack.Response) setupObservation {
	if resp != nil {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return setupObservation{rank: setupFeatureAbsent}
		}
	}
	return classifyTaskSetup(what, endpoint, credentialed, resp)
}
