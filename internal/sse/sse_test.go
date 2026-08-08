package sse

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func collect(t *testing.T, input string) []Event {
	t.Helper()
	rd := NewReader(strings.NewReader(input))
	var got []Event
	for {
		ev, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got = append(got, ev)
	}
	return got
}

func eventsEqual(a, b []Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReader_SingleLine(t *testing.T) {
	got := collect(t, "data: hello\n\n")
	want := []Event{{Data: "hello"}}
	if !eventsEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestReader_MultiLineJoined is the core fix: a payload split across several
// data: lines is rejoined with newlines, so a chunked JSON-RPC message still
// parses. A first-line-only reader would return a fragment here.
func TestReader_MultiLineJoined(t *testing.T) {
	input := "data: {\"jsonrpc\":\"2.0\",\"result\":{\"x\":\ndata: 1}}\n\n"
	got := collect(t, input)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1: %v", len(got), got)
	}
	want := "{\"jsonrpc\":\"2.0\",\"result\":{\"x\":\n1}}"
	if got[0].Data != want {
		t.Errorf("data %q, want %q", got[0].Data, want)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(got[0].Data), &v); err != nil {
		t.Errorf("joined data did not parse as JSON: %v", err)
	}
}

func TestReader_LeadingSpace(t *testing.T) {
	// Exactly one leading space is stripped (per spec), the rest is preserved.
	got := collect(t, "data:  two spaces\n\n")
	if len(got) != 1 || got[0].Data != " two spaces" {
		t.Errorf("got %v, want one event with data %q", got, " two spaces")
	}
}

func TestReader_NoSpaceAfterColon(t *testing.T) {
	got := collect(t, "data:nospace\n\n")
	if len(got) != 1 || got[0].Data != "nospace" {
		t.Errorf("got %v, want %q", got, "nospace")
	}
}

func TestReader_CommentLines(t *testing.T) {
	got := collect(t, ": keepalive\ndata: x\n\n")
	if len(got) != 1 || got[0].Data != "x" {
		t.Errorf("got %v, want one event with data %q (comment ignored)", got, "x")
	}
}

func TestReader_EventFieldIgnored(t *testing.T) {
	got := collect(t, "event: message\ndata: x\n\n")
	if len(got) != 1 || got[0].Data != "x" {
		t.Errorf("got %v, want one event with data %q (event field ignored)", got, "x")
	}
}

func TestReader_BareDataNoValue(t *testing.T) {
	// A block whose only data line has no value yields no event.
	got := collect(t, "data\n\n")
	if len(got) != 0 {
		t.Errorf("got %v, want no events for a bare data line", got)
	}
}

func TestReader_IDTracking(t *testing.T) {
	got := collect(t, "id:5\ndata:x\n\nid:6\ndata:y\n\n")
	want := []Event{{ID: "5", Data: "x"}, {ID: "6", Data: "y"}}
	if !eventsEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReader_IDResetsPerEvent(t *testing.T) {
	// The id field is scoped to its block: an event with no id: line has empty ID.
	got := collect(t, "id:5\ndata:x\n\ndata:y\n\n")
	want := []Event{{ID: "5", Data: "x"}, {ID: "", Data: "y"}}
	if !eventsEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReader_IDWithNULIgnored(t *testing.T) {
	got := collect(t, "id:bad\x00id\ndata:x\n\n")
	if len(got) != 1 || got[0].ID != "" || got[0].Data != "x" {
		t.Errorf("got %v, want empty ID (NUL id line ignored) with data x", got)
	}
}

func TestReader_CRLFLineEndings(t *testing.T) {
	got := collect(t, "data:x\r\n\r\n")
	if len(got) != 1 || got[0].Data != "x" {
		t.Errorf("got %v, want one event with data %q", got, "x")
	}
}

func TestReader_PartialAtEOF(t *testing.T) {
	// No terminating blank line: the trailing block is still dispatched.
	got := collect(t, "data: x\n")
	if len(got) != 1 || got[0].Data != "x" {
		t.Errorf("got %v, want one event with data %q", got, "x")
	}
}

func TestReader_IDOnlyEventNotEmitted(t *testing.T) {
	// An id: line with no data does not produce an event on its own.
	got := collect(t, "id:1\n\ndata:x\n\n")
	want := []Event{{ID: "", Data: "x"}}
	if !eventsEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReader_OversizedLineErrors(t *testing.T) {
	huge := "data: " + strings.Repeat("x", 200) + "\n\n"
	rd := NewReaderSize(strings.NewReader(huge), 64)
	_, err := rd.Next()
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("got err %v, want bufio.ErrTooLong", err)
	}
}

func TestFirstData_MultiLine(t *testing.T) {
	input := "data: {\"a\":\ndata: 1}\n\n"
	got, err := FirstData(strings.NewReader(input), MaxBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{\"a\":\n1}"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFirstData_NoDataEvent(t *testing.T) {
	// Only comments: no payload, no error.
	got, err := FirstData(strings.NewReader(": ping\n\n"), MaxBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("got %q, want nil", got)
	}
}

func TestFirstData_OversizedLine(t *testing.T) {
	huge := "data: " + strings.Repeat("x", 200) + "\n\n"
	_, err := FirstData(strings.NewReader(huge), 64)
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("got err %v, want bufio.ErrTooLong", err)
	}
}

// TestFirstData_DoesNotDrain verifies FirstData returns after the first event
// without blocking on the rest of an open stream (the original reason the scan
// client reads only one event). The second Read would block forever, so a
// draining implementation would hang this test until the timeout fires.
func TestFirstData_DoesNotDrain(t *testing.T) {
	r := newBlockingAfterFirst()
	done := make(chan struct{})
	var got []byte
	var err error
	go func() {
		got, err = FirstData(r, MaxBytes)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		r.unblock()
		t.Fatal("FirstData did not return after the first event (drained a blocking stream)")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "first" {
		t.Errorf("got %q, want %q", got, "first")
	}
}

// blockingAfterFirst serves one event, then blocks on the second Read as a live
// SSE stream with no further event would.
type blockingAfterFirst struct {
	served bool
	ch     chan struct{}
}

func newBlockingAfterFirst() *blockingAfterFirst {
	return &blockingAfterFirst{ch: make(chan struct{})}
}

func (r *blockingAfterFirst) Read(p []byte) (int, error) {
	if !r.served {
		r.served = true
		n := copy(p, []byte("data: first\n\n"))
		return n, nil
	}
	<-r.ch
	return 0, io.EOF
}

func (r *blockingAfterFirst) unblock() { close(r.ch) }

// FirstMatching must skip events the predicate rejects. Taking the first data
// event was wrong for MCP Streamable HTTP, which lets a server interleave
// notifications on the POST response stream ahead of the response.
func TestFirstMatching_SkipsNonResponses(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n" +
		"data: {}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"roots/list\"}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"

	got, found, err := FirstMatching(strings.NewReader(stream), 0, IsJSONRPCResponse)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected the response event to be found")
	}
	if !strings.Contains(string(got), `"result"`) {
		t.Errorf("returned the wrong event: %s", got)
	}
}

func TestFirstMatching_NoMatchReportsNotFound(t *testing.T) {
	stream := "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"
	got, found, err := FirstMatching(strings.NewReader(stream), 0, IsJSONRPCResponse)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || got != nil {
		t.Errorf("expected found=false and no payload, got found=%v payload=%q", found, got)
	}
}

// A nil predicate keeps the old first-data-event behaviour, for callers that want it.
func TestFirstMatching_NilPredicateTakesFirst(t *testing.T) {
	stream := "data: first\n\ndata: second\n\n"
	got, found, err := FirstMatching(strings.NewReader(stream), 0, nil)
	if err != nil || !found || string(got) != "first" {
		t.Errorf("got %q found=%v err=%v, want \"first\"", got, found, err)
	}
}

func TestIsJSONRPCResponse(t *testing.T) {
	cases := map[string]bool{
		`{"jsonrpc":"2.0","id":1,"result":{}}`:               true,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32001}}`:   true,
		`{"jsonrpc":"2.0","method":"notifications/message"}`: false,
		`{"jsonrpc":"2.0","id":"s1","method":"roots/list"}`:  false,
		`{}`:                                false,
		`{"jsonrpc":"2.0","id":1,"result":`: true, // malformed: the server's answer, surfaced
	}
	for payload, want := range cases {
		if got := IsJSONRPCResponse([]byte(payload)); got != want {
			t.Errorf("IsJSONRPCResponse(%s) = %v, want %v", payload, got, want)
		}
	}
}
