package attack_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// sseJSONRPCServer answers every POST over SSE, the way a real streamable-HTTP MCP
// server does. prelude events are emitted before the response, which the binding
// permits: notifications and server-initiated requests may interleave.
func sseJSONRPCServer(t *testing.T, prelude []string, response string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, p := range prelude {
			fmt.Fprintf(w, "data: %s\n\n", p)
		}
		if response != "" {
			fmt.Fprintf(w, "data: %s\n\n", response)
		}
	}))
}

func post(t *testing.T, target string) (*attack.Response, error) {
	t.Helper()
	c := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(target, ""))
	return c.POST(context.Background(), target, nil, map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	})
}

// The plain case: the response is the only event.
func TestSSE_ResponseIsRead(t *testing.T) {
	srv := sseJSONRPCServer(t, nil, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	defer srv.Close()

	resp, err := post(t, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsAccepted() {
		t.Errorf("expected the result to be read, got body %q", resp.BodyString())
	}
}

// The binding lets a server emit notifications on the POST stream before the
// response. Taking the FIRST data event made a progress notification the parsed
// reply, so the real result was never seen and the surface read as refused.
func TestSSE_NotificationBeforeResponseIsSkipped(t *testing.T) {
	prelude := []string{
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"starting"}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		`{}`, // a data-bearing keepalive
	}
	srv := sseJSONRPCServer(t, prelude, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"}]}}`)
	defer srv.Close()

	resp, err := post(t, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsAccepted() {
		t.Fatalf("the response event was not reached; body = %q", resp.BodyString())
	}
	if !resp.ContainsAny(`"echo"`) {
		t.Errorf("expected the real result, got %q", resp.BodyString())
	}
}

// A server-initiated request carries an id but neither result nor error. It is
// also not the answer to our call.
func TestSSE_ServerRequestBeforeResponseIsSkipped(t *testing.T) {
	prelude := []string{`{"jsonrpc":"2.0","id":"srv-1","method":"roots/list"}`}
	srv := sseJSONRPCServer(t, prelude, `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Unauthorized"}}`)
	defer srv.Close()

	resp, err := post(t, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.ContainsAny("Unauthorized") {
		t.Errorf("expected the error envelope, got %q", resp.BodyString())
	}
}

// A stream that never carries a response is not an empty answer. Reporting a nil
// body on an HTTP 200 made IsAccepted false, which every rule using that oracle
// reads as "the server refused".
func TestSSE_NoResponseEventIsAnError(t *testing.T) {
	srv := sseJSONRPCServer(t, []string{`{"jsonrpc":"2.0","method":"notifications/message"}`}, "")
	defer srv.Close()

	if _, err := post(t, srv.URL); err == nil {
		t.Error("a stream with no response event must be an error, not a nil body on a 200")
	}
}

// Malformed JSON is the server's answer and must be surfaced, not scanned past.
func TestSSE_MalformedPayloadIsSurfaced(t *testing.T) {
	srv := sseJSONRPCServer(t, nil, `{"jsonrpc":"2.0","id":1,"result":`)
	defer srv.Close()

	resp, err := post(t, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsAccepted() {
		t.Error("a truncated body is not an accepted result")
	}
	if len(resp.Body) == 0 {
		t.Error("the malformed payload should be surfaced so rules can see what the server sent")
	}
}
