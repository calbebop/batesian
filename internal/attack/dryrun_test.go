package attack

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDryRunClientDoesNotDial is the core safety guarantee: a dry-run HTTP client
// records the request it would send but never opens a connection, and it redacts
// the bearer token so a shared plan cannot leak credentials.
func TestDryRunClientDoesNotDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var dialed int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&dialed, 1)
			conn.Close()
		}
	}()

	rec := &Recorder{}
	rec.SetCurrentRule("test-rule")
	opts := Options{DryRun: true, Recorder: rec, Token: "supersecret"}
	c := NewHTTPClient(opts, NewVars("http://"+ln.Addr().String(), ""))

	resp, err := c.POST(context.Background(), "{{BaseURL}}/initialize",
		map[string]string{"X-Probe": "1"}, map[string]any{"jsonrpc": "2.0"})
	if err != nil {
		t.Fatalf("dry-run POST returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("synthetic response status = %d, want 200", resp.StatusCode)
	}

	if atomic.LoadInt32(&dialed) != 0 {
		t.Fatal("dry run dialed the target; nothing should be sent")
	}

	reqs := rec.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.RuleID != "test-rule" {
		t.Errorf("RuleID = %q, want test-rule", r.RuleID)
	}
	if r.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", r.Method)
	}
	if !strings.HasSuffix(r.URL, "/initialize") {
		t.Errorf("URL = %q, want suffix /initialize", r.URL)
	}
	if !strings.Contains(r.Body, "jsonrpc") {
		t.Errorf("Body = %q, missing request payload", r.Body)
	}
	if got := r.Headers["Authorization"]; got != "<redacted>" {
		t.Errorf("Authorization = %q, want <redacted> (token must not leak into the plan)", got)
	}
	if r.Headers["X-Probe"] != "1" {
		t.Errorf("custom header not recorded: %v", r.Headers)
	}
}

// TestTransportSelectsByMode confirms the shared Transport factory returns the
// recording transport only in a dry run, and a real *http.Transport otherwise.
func TestTransportSelectsByMode(t *testing.T) {
	if _, ok := Transport(Options{}).(*http.Transport); !ok {
		t.Errorf("non-dry-run Transport = %T, want *http.Transport", Transport(Options{}))
	}
	if _, ok := Transport(Options{DryRun: true, Recorder: &Recorder{}}).(*dryRunRoundTripper); !ok {
		t.Error("dry-run Transport should be the recording transport")
	}
}
