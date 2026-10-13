package a2a

import (
	"encoding/json"

	"github.com/calbebop/batesian/internal/attack"
)

func recordPushConfig(state *attack.TargetState, endpoint, taskID, version string, resp *attack.Response) {
	if state == nil {
		return
	}
	var payload struct {
		ID                     string `json:"id"`
		ConfigID               string `json:"configId"`
		PushNotificationConfig *struct {
			ID string `json:"id"`
		} `json:"pushNotificationConfig"`
	}
	body := []byte(nil)
	if resp != nil {
		body = resp.Body
		var envelope map[string]json.RawMessage
		if json.Unmarshal(body, &envelope) == nil {
			if result, ok := envelope["result"]; ok {
				body = result
			}
		}
	}
	_ = json.Unmarshal(body, &payload)
	configID := payload.ConfigID
	if version == "1.0" {
		configID = payload.ID
	}
	if payload.PushNotificationConfig != nil && payload.PushNotificationConfig.ID != "" {
		configID = payload.PushNotificationConfig.ID
	}
	state.Record(attack.TargetObject{
		Kind:          "a2a_push_config",
		Creation:      "accepted",
		ID:            configID,
		ParentID:      taskID,
		Endpoint:      endpoint,
		Cleanup:       attack.CleanupNotAttempted,
		CleanupDetail: "Batesian does not remove callback configurations",
	})
}

func recordPossiblePushConfig(state *attack.TargetState, endpoint, taskID string) {
	state.Record(attack.TargetObject{
		Kind:          "a2a_push_config",
		Creation:      "unverified",
		ParentID:      taskID,
		Endpoint:      endpoint,
		Cleanup:       attack.CleanupNotAttempted,
		CleanupDetail: "inline callback sent; registration was not separately confirmed",
	})
}
