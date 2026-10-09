package a2a

func restTaskSendRequest(messageID, text, version string) map[string]interface{} {
	field := "parts"
	if version != "1.0" {
		field = "content"
	}
	request := map[string]interface{}{"message": map[string]interface{}{
		"messageId": "batesian-" + messageID,
		"role":      "ROLE_USER",
		field:       []interface{}{map[string]string{"text": text}},
	}}
	if version == "1.0" {
		request["configuration"] = map[string]interface{}{"returnImmediately": true}
	}
	return request
}
