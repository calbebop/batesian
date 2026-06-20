package attack

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
)

// RecordedRequest is one outbound HTTP request captured during a dry run.
type RecordedRequest struct {
	RuleID  string
	Method  string
	URL     string
	Headers map[string]string // Authorization value is redacted
	Body    string
}

// Recorder collects the requests a dry run would have sent instead of sending
// them. It is safe for concurrent use, though the engine drives rules
// sequentially and stamps the active rule via SetCurrentRule.
type Recorder struct {
	mu      sync.Mutex
	current string
	reqs    []RecordedRequest
}

// SetCurrentRule labels subsequently recorded requests with ruleID. The engine
// calls this before running each rule so the dry-run plan can group by rule.
func (r *Recorder) SetCurrentRule(ruleID string) {
	r.mu.Lock()
	r.current = ruleID
	r.mu.Unlock()
}

// Requests returns a copy of the recorded requests in capture order.
func (r *Recorder) Requests() []RecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecordedRequest, len(r.reqs))
	copy(out, r.reqs)
	return out
}

func (r *Recorder) record(method, rawURL string, header http.Header, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, RecordedRequest{
		RuleID:  r.current,
		Method:  method,
		URL:     rawURL,
		Headers: redactHeaders(header),
		Body:    string(body),
	})
}

// redactHeaders flattens headers to a single-valued map and masks credentials so
// a shared dry-run plan never leaks bearer tokens.
func redactHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") {
			out[k] = "<redacted>"
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// dryRunRoundTripper records each request and returns a benign synthetic response
// without performing any network I/O. It holds no real transport, so it cannot
// reach the network by construction; that is the dry-run safety guarantee.
type dryRunRoundTripper struct {
	rec *Recorder
}

func (d *dryRunRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	rec := d.rec
	if rec == nil {
		rec = &Recorder{} // defensive: a dry run with no recorder still must not dial
	}
	// A forged Host lives in req.Host, not req.Header; surface it so the recorded
	// plan shows the effective Host an executor set (e.g. host-injection probes).
	header := req.Header.Clone()
	if req.Host != "" {
		header.Set("Host", req.Host)
	}
	rec.record(req.Method, req.URL.String(), header, body)
	return syntheticResponse(req), nil
}

// syntheticResponse is the stand-in a dry run hands back to the caller: an empty
// JSON 200 so executors can parse a response without anything being sent. Any
// findings derived from it are discarded; a dry run reports the request plan, not
// results.
func syntheticResponse(req *http.Request) *http.Response {
	body := []byte("{}")
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// Transport returns the RoundTripper for a scan-path HTTP client. In a dry run it
// returns a recording transport that sends nothing; otherwise a real
// *http.Transport honoring opts.SkipTLS. Routing every scan-path client through
// this one function is what makes the dry-run "send nothing" guarantee total.
func Transport(opts Options) http.RoundTripper {
	if opts.DryRun {
		return &dryRunRoundTripper{rec: opts.Recorder}
	}
	tr := &http.Transport{}
	if opts.SkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return tr
}
