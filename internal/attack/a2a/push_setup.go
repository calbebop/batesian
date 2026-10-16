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

func pushReplyAccepted(resp *attack.Response, requestID string) bool {
	if resp == nil || !resp.IsSuccess() {
		return false
	}
	_, _, hasError, valid := discoveryResponse(resp.Body, requestID)
	return valid && !hasError
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
		_, _, _, valid := discoveryResponse(resp.Body, requestID)
		if !valid {
			return setupObservation{setupOtherRefusal, what + " reply did not match its request ID"}
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
		if resp.IsAccepted() {
			var reply struct {
				Result struct {
					Kind string `json:"kind"`
				} `json:"result"`
			}
			if json.Unmarshal(resp.Body, &reply) == nil && reply.Result.Kind == "message" {
				return setupObservation{rank: setupFeatureAbsent}
			}
		}
	}
	return classifyTaskSetup(what, endpoint, credentialed, resp)
}
