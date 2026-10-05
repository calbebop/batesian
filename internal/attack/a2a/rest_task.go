package a2a

func restTaskSendRequest(messageID, text, version string) map[string]interface{} {
	role := "ROLE_USER"
	part := map[string]string{"text": text}
	if version != "1.0" {
		role = "user"
		part["kind"] = "text"
	}
	request := map[string]interface{}{"message": map[string]interface{}{
		"messageId": "batesian-" + messageID,
		"role":      role,
		"parts":     []interface{}{part},
	}}
	if version == "1.0" {
		request["configuration"] = map[string]interface{}{"returnImmediately": true}
	}
	return request
}
