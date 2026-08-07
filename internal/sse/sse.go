// Package sse parses Server-Sent Events streams.
//
// MCP Streamable HTTP carries JSON-RPC responses over SSE. An SSE event's
// payload may span several "data:" lines, which the client joins with a newline
// (HTML "Interpreting an event stream"). Returning only the first "data:" line
// (as a naive reader does) captures a fragment when a server chunks a response
// that way, so the payload fails to parse and a rule silently reports clean.
// This package implements the spec-correct join so the first complete event is
// returned intact.
package sse

import (
	"bufio"
	"io"
	"strings"
)

// MaxBytes is the default cap on how many bytes a reader will consume from a
// stream, matching the body cap used by the scan and recon clients.
const MaxBytes int64 = 32 << 20

// defaultLineBytes caps a single line when no limit is supplied. initialLineBytes
// is what the scanner starts with; it grows from there on demand, so the cap
// costs nothing until a line actually approaches it.
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

// NewReader returns a Reader over r with the default 1 MB per-line buffer.
func NewReader(r io.Reader) *Reader {
	return NewReaderSize(r, defaultLineBytes)
}

// NewReaderSize returns a Reader over r whose per-line buffer grows to maxLine
// bytes; a longer line ends the stream with bufio.ErrTooLong. The total stream
// length is unbounded, so callers that read to completion should bound the
// reader themselves (a context deadline, or io.LimitReader via FirstData).
func NewReaderSize(r io.Reader, maxLine int) *Reader {
	if maxLine <= 0 {
		maxLine = defaultLineBytes
	}
	sc := bufio.NewScanner(r)
	// Start small and let the scanner grow to maxLine only if a line needs it.
	// Allocating maxLine up front made the ceiling cost real on every read: an
	// SSE reply is the normal case for MCP streamable HTTP, so a large ceiling
	// would allocate that much per response even for a few hundred bytes of data.
	initial := initialLineBytes
	if maxLine < initial {
		initial = maxLine
	}
	sc.Buffer(make([]byte, initial), maxLine)
	return &Reader{sc: sc}
}

// Next returns the next event that carries a non-empty data payload.
//
// It returns io.EOF when the stream is exhausted and another error (for example
// bufio.ErrTooLong) when a line could not be read. A trailing block with no
// terminating blank line is still dispatched at EOF, so servers that omit the
// final blank line are handled.
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

// flush materializes and clears the buffered event. It returns the event and
// true only when the block carried a non-empty joined payload; otherwise it
// resets the buffer and returns false.
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

// FirstData returns the joined payload of the first event that carries data, or
// nil when the stream ends with no such event. It reads at most max bytes and
// stops at the first event without draining the rest of the stream, which keeps
// a long-lived SSE connection from blocking. A non-nil error means the stream
// could not be read (for example a single line overrunning max); callers that
// treat "no payload" as a clean result should ignore it.
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
