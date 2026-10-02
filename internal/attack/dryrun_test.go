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
	if r.Headers["X-Probe"] != "<redacted>" {
		t.Errorf("custom header value not redacted: %v", r.Headers)
	}
}

func TestDryRunRedactsCredentialsInEveryRequestField(t *testing.T) {
	rec := &Recorder{}
	body := `{"jsonrpc":"2.0","method":"initialize","params":{"password":"body-secret","nested":[{"value":"nested-secret"}],"callback":"http://oob.batesian.invalid/abc?token=callback-secret"}}`
	req, err := http.NewRequest(http.MethodPost,
		"https://user-secret:pass-secret@example.com/mcp?key-secret=query-secret&key=other-secret#fragment-secret",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer bearer-secret")
	req.Header.Set("Cookie", "sid=cookie-secret")
	req.Header.Set("X-API-Key", "api-key-secret")
	req.Header.Set("Mcp-Session-Id", "session-secret")
	req.Header.Set("X-Tenant", "tenant-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := Transport(Options{DryRun: true, Recorder: rec}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	reqs := rec.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	for _, secret := range []string{
		"user-secret", "pass-secret", "key-secret", "query-secret", "other-secret", "fragment-secret",
		"bearer-secret", "cookie-secret", "api-key-secret", "session-secret",
		"tenant-secret", "body-secret", "nested-secret", "callback-secret",
	} {
		if strings.Contains(r.URL+r.Body+strings.Join(headerValues(r.Headers), " "), secret) {
			t.Errorf("recorded request contains %q: %+v", secret, r)
		}
	}
	if !strings.Contains(r.URL, "/mcp?REDACTED") {
		t.Errorf("URL lost endpoint or query marker: %s", r.URL)
	}
	if !strings.Contains(r.Body, `"method":"initialize"`) || !strings.Contains(r.Body, DryRunOOBPlaceholderURL) {
		t.Errorf("body lost safe protocol context: %s", r.Body)
	}
	if r.BodyDigest == "" {
		t.Error("request body has no digest for endpoint grouping")
	}
}

func TestDryRunRedactsNonJSONBody(t *testing.T) {
	if got := redactBody([]byte("token=plain-secret")); got != "<redacted>" {
		t.Fatalf("redactBody = %q", got)
	}
}

func headerValues(h map[string]string) []string {
	values := make([]string, 0, len(h))
	for _, v := range h {
		values = append(values, v)
	}
	return values
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
