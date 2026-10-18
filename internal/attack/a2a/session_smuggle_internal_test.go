package a2a

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyHistoryMarker(t *testing.T) {
	const marker = "probe-marker"
	message := func(role interface{}) map[string]interface{} {
		return map[string]interface{}{
			"role":      role,
			"messageId": marker,
			"parts":     []interface{}{map[string]string{"text": marker}},
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
		{name: "marker in message ID only", history: []interface{}{map[string]interface{}{
			"role": "agent", "messageId": marker, "parts": []interface{}{map[string]string{"text": "other"}},
		}}, want: historyMarkerAbsent},
		{name: "marker in metadata only", history: []interface{}{map[string]interface{}{
			"role": "agent", "metadata": map[string]string{"marker": marker},
			"parts": []interface{}{map[string]string{"text": "other"}},
		}}, want: historyMarkerAbsent},
		{name: "marker in part metadata only", history: []interface{}{map[string]interface{}{
			"role": "agent", "parts": []interface{}{map[string]interface{}{
				"metadata": map[string]string{"marker": marker}, "text": "other",
			}},
		}}, want: historyMarkerAbsent},
		{name: "malformed history item", history: []interface{}{marker}, want: historyMarkerUnknown},
		{name: "missing role", history: []interface{}{missingRole}, want: historyMarkerUnknown},
		{name: "user over unknown", history: []interface{}{message("moderator"), message("user")}, want: historyMarkerUser},
		{name: "agent over unknown", history: []interface{}{message("moderator"), message("agent")}, want: historyMarkerAgent},
		{name: "agent echo after normalized user", history: []interface{}{message("user"), map[string]interface{}{
			"role": "agent", "messageId": "reply", "parts": []interface{}{map[string]string{"text": "You said: " + marker}},
		}}, want: historyMarkerUser},
		{name: "agent echo without client turn", history: []interface{}{map[string]interface{}{
			"role": "agent", "messageId": "reply", "parts": []interface{}{map[string]string{"text": marker}},
		}}, want: historyMarkerUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyHistoryMarker(tt.history, marker); got != tt.want {
				t.Fatalf("classifyHistoryMarker() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWaitForSessionHistoryStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForSessionHistory(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForSessionHistory() error = %v, want context.Canceled", err)
	}
}
