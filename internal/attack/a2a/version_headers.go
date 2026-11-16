package a2a

import "strings"

func a2aVersionHeaders(extra map[string]string, version string) map[string]string {
	headers := make(map[string]string, len(extra)+1)
	for key, value := range extra {
		if !strings.EqualFold(key, "A2A-Version") {
			headers[key] = value
		}
	}
	if version != "" {
		headers["A2A-Version"] = version
	}
	return headers
}
