// Package sse parses Server-Sent Events, including multiline data payloads used
// by MCP Streamable HTTP.
package sse

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// MaxBytes is the default cap on how many bytes a reader will consume from a
// stream, matching the body cap used by the scan and recon clients.
const MaxBytes int64 = 32 << 20

// defaultLineBytes caps a line; initialLineBytes is the starting allocation.
const (
	defaultLineBytes = 32 << 20
	initialLineBytes = 64 << 10
)

// Event is one dispatched SSE event.
type Event struct {
	// ID is the value of the event's "id:" field, if any. It is scoped to the
	// event: a later block with no "id:" field yields an empty ID.
	ID string
	// Data is the event's payload: every "data:" line within the block joined
	// with U+000A, with the single trailing newline removed.
	Data string
}

// Reader parses SSE events from a stream. It is safe for single-goroutine use.
type Reader struct {
	sc      *bufio.Scanner
	id      string
	data    strings.Builder
	hasData bool
}

// NewReader returns a Reader over r with the default 32 MiB line limit.
func NewReader(r io.Reader) *Reader {
	return NewReaderSize(r, defaultLineBytes)
}

// NewReaderSize returns a Reader whose line buffer grows to maxLine bytes.
// Callers reading to completion must bound the total stream separately.
func NewReaderSize(r io.Reader, maxLine int) *Reader {
	if maxLine <= 0 {
		maxLine = defaultLineBytes
	}
	sc := bufio.NewScanner(r)
	// Grow on demand instead of allocating maxLine for every response.
	initial := initialLineBytes
	if maxLine < initial {
		initial = maxLine
	}
	sc.Buffer(make([]byte, initial), maxLine)
	return &Reader{sc: sc}
}

// Next returns the next event that carries a non-empty data payload.
//
// It returns io.EOF when exhausted and dispatches a trailing unterminated block.
func (r *Reader) Next() (Event, error) {
	for {
		if !r.sc.Scan() {
			if ev, ok := r.flush(); ok {
				return ev, nil
			}
			if err := r.sc.Err(); err != nil {
				return Event{}, err
			}
			return Event{}, io.EOF
		}
		line := r.sc.Text()
		switch {
		case line == "":
			if ev, ok := r.flush(); ok {
				return ev, nil
			}
		case strings.HasPrefix(line, ":"):
			// Comment line.
		default:
			name, value := parseField(line)
			switch name {
			case "data":
				r.data.WriteString(value)
				r.data.WriteByte('\n')
				r.hasData = true
			case "id":
				// Per spec, an "id:" line containing NUL is ignored.
				if !strings.ContainsRune(value, '\x00') {
					r.id = value
				}
			}
		}
	}
}

// flush returns a non-empty buffered event and resets the buffer.
func (r *Reader) flush() (Event, bool) {
	defer r.reset()
	if !r.hasData {
		return Event{}, false
	}
	s := strings.TrimSuffix(r.data.String(), "\n")
	if s == "" {
		return Event{}, false
	}
	return Event{ID: r.id, Data: s}, true
}

func (r *Reader) reset() {
	r.id = ""
	r.data.Reset()
	r.hasData = false
}

// parseField splits an SSE line into its field name and value. A line with no
// colon is the field name with an empty value. When a colon is present, exactly
// one leading U+0020 is stripped from the value (per spec, not all whitespace).
func parseField(line string) (name, value string) {
	if i := strings.IndexByte(line, ':'); i >= 0 {
		name = line[:i]
		// Strip exactly one leading U+0020 (per spec), not all whitespace.
		value = strings.TrimPrefix(line[i+1:], " ")
		return name, value
	}
	return line, ""
}

// FirstData returns the first data payload while reading at most max bytes. It
// stops without draining the stream and returns nil when no payload exists.
func FirstData(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = MaxBytes
	}
	rd := NewReaderSize(io.LimitReader(r, max), int(max))
	ev, err := rd.Next()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []byte(ev.Data), nil
}

// maxScannedEvents bounds streams with many small non-matching events.
const maxScannedEvents = 64

// FirstMatching returns the first payload accepted by want, reading at most max
// bytes without draining the stream. MCP permits notifications and requests
// before the response, so callers cannot assume the first event is the answer.
// found is false when no match is found within the byte and event limits.
func FirstMatching(r io.Reader, max int64, want func([]byte) bool) (data []byte, found bool, err error) {
	if max <= 0 {
		max = MaxBytes
	}
	rd := NewReaderSize(io.LimitReader(r, max), int(max))
	for i := 0; i < maxScannedEvents; i++ {
		ev, err := rd.Next()
		if err == io.EOF {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if ev.Data == "" {
			continue
		}
		payload := []byte(ev.Data)
		if want == nil || want(payload) {
			return payload, true, nil
		}
	}
	return nil, false, nil
}

// IsJSONRPCResponse reports whether payload contains a JSON-RPC result or error.
// Notifications and server requests return false. Malformed JSON returns true so
// callers surface the invalid response instead of scanning past it.
func IsJSONRPCResponse(payload []byte) bool {
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return true
	}
	return len(envelope.Result) > 0 || len(envelope.Error) > 0
}
