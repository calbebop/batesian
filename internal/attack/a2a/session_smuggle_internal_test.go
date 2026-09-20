package a2a

import "testing"

func TestClassifyHistoryMarker(t *testing.T) {
	const marker = "probe-marker"
	message := func(role interface{}) map[string]interface{} {
		return map[string]interface{}{
			"role":  role,
			"parts": []interface{}{map[string]string{"text": marker}},
		}
	}
	missingRole := map[string]interface{}{
		"parts": []interface{}{map[string]string{"text": marker}},
	}

	tests := []struct {
		name    string
		history []interface{}
		want    historyMarkerState
	}{
		{name: "absent", history: []interface{}{map[string]interface{}{
			"role": "user", "parts": []interface{}{map[string]string{"text": "other"}},
		}}, want: historyMarkerAbsent},
		{name: "numeric user", history: []interface{}{message(float64(1))}, want: historyMarkerUser},
		{name: "user", history: []interface{}{message("user")}, want: historyMarkerUser},
		{name: "symbolic user", history: []interface{}{message("ROLE_USER")}, want: historyMarkerUser},
		{name: "numeric agent", history: []interface{}{message(float64(2))}, want: historyMarkerAgent},
		{name: "agent", history: []interface{}{message("agent")}, want: historyMarkerAgent},
		{name: "symbolic agent", history: []interface{}{message("ROLE_AGENT")}, want: historyMarkerAgent},
		{name: "missing role", history: []interface{}{missingRole}, want: historyMarkerUnknown},
		{name: "unknown over user", history: []interface{}{message("moderator"), message("user")}, want: historyMarkerUnknown},
		{name: "agent over unknown", history: []interface{}{message("moderator"), message("agent")}, want: historyMarkerAgent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHistoryMarker(tt.history, marker); got != tt.want {
				t.Fatalf("classifyHistoryMarker() = %d, want %d", got, tt.want)
			}
		})
	}
}
