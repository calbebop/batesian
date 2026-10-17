package a2a

import "testing"

func TestTaskReadbacksRequireStatus(t *testing.T) {
	const marker = "batesian delegation continuation marker"
	const history = `[{"role":"user","parts":[{"text":"batesian delegation continuation marker"}]}]`
	for _, status := range []string{"", `,"status":null`, `,"status":"working"`, `,"status":{}`} {
		result := `{"id":"task-1","history":` + history + status + `}`
		body := []byte(`{"jsonrpc":"2.0","id":"request-1","result":` + result + `}`)
		if readable, found := contextTaskHistoryHasText(body, "request-1", "task-1", marker); readable || found {
			t.Errorf("context readback accepted status %q", status)
		}
		if readable, found := taskHistoryHasMarker(body, "request-1", "task-1", "marker"); readable || found {
			t.Errorf("delegation readback accepted status %q", status)
		}
		if _, state := taskHistory(body, "task-1"); state != taskHistoryMalformed {
			t.Errorf("session readback state = %v for status %q", state, status)
		}
		if location, matched := taskReadMarkerLocation(body, "task-1", marker); location != "" || matched {
			t.Errorf("IDOR readback accepted status %q", status)
		}
	}
}

func TestTaskReadbacksUseValidatedNestedTask(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":"request-1","result":{"id":"task-1",` +
		`"history":[{"role":"user","parts":[{"text":"batesian delegation continuation marker"}]}],` +
		`"task":{"id":"task-1","status":{"state":"working"},"history":[]}}}`
	if readable, found := contextTaskHistoryHasText([]byte(body), "request-1", "task-1", "marker"); !readable || found {
		t.Fatalf("context readback used outer history: readable=%t found=%t", readable, found)
	}
	if readable, found := taskHistoryHasMarker([]byte(body), "request-1", "task-1", "marker"); !readable || found {
		t.Fatalf("delegation readback used outer history: readable=%t found=%t", readable, found)
	}
	if history, state := taskHistory([]byte(body), "task-1"); state != taskHistoryPresent || len(history) != 0 {
		t.Fatalf("session readback used outer history: state=%v history=%v", state, history)
	}
	if location, matched := taskReadMarkerLocation([]byte(body), "task-1", "marker"); location != "" || !matched {
		t.Fatalf("IDOR readback used outer history: location=%q matched=%t", location, matched)
	}
}
