package attack

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/calbebop/batesian/internal/httpx"
)

// DryRunOOBPlaceholderURL replaces live callback URLs during a dry run.
const DryRunOOBPlaceholderURL = "http://oob.batesian.invalid"

// RecordedRequest is one outbound HTTP request captured during a dry run.
type RecordedRequest struct {
	RuleID  string
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	// BodyDigest distinguishes requests whose redacted bodies look alike.
	BodyDigest string
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
		RuleID:     r.current,
		Method:     method,
		URL:        RedactURL(rawURL),
		Headers:    redactHeaders(header),
		Body:       redactBody(body),
		BodyDigest: digestBody(body),
	})
}

// RedactURL removes userinfo, queries, and fragments from a displayed URL.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<redacted URL>"
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	if u.RawQuery != "" {
		u.RawQuery = "REDACTED"
	}
	return u.String()
}

// Header values are hidden by default; only fixed protocol values are shown.
func redactHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		value := strings.Join(v, ", ")
		switch {
		case strings.EqualFold(k, "Content-Type") && value == "application/json":
			out[k] = value
		case strings.EqualFold(k, "Accept") && value == "application/json, text/event-stream":
			out[k] = value
		default:
			out[k] = "<redacted>"
		}
	}
	return out
}

func digestBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func redactBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return "<redacted>"
	}
	redacted, err := json.Marshal(redactJSON(value, ""))
	if err != nil {
		return "<redacted>"
	}
	return string(redacted)
}

func redactJSON(value interface{}, key string) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, child := range v {
			v[k] = redactJSON(child, k)
		}
		return v
	case []interface{}:
		for i, child := range v {
			v[i] = redactJSON(child, key)
		}
		return v
	case string:
		if key == "method" && safeDryRunMethod(v) {
			return v
		}
		if strings.HasPrefix(v, DryRunOOBPlaceholderURL) {
			return DryRunOOBPlaceholderURL + "/<callback>"
		}
		return "<redacted>"
	case float64, bool:
		return "<redacted>"
	default:
		return v
	}
}

func safeDryRunMethod(method string) bool {
	switch method {
	case "initialize", "ping", "server/discover", "tools/list", "tools/call",
		"resources/list", "resources/read", "prompts/list", "prompts/get",
		"completion/complete", "logging/setLevel", "tasks/get", "tasks/list",
		"tasks/cancel", "tasks/result", "message/send", "message/stream",
		"SendMessage", "GetTask", "ListTasks", "CancelTask", "GetAgentCard":
		return true
	default:
		return false
	}
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
// *http.Transport honoring opts.SkipTLS and opts.Proxy. Routing every scan-path
// client through this one function is what makes the dry-run "send nothing"
// guarantee total, and it is why one change here reaches the shared client plus
// the two rules that keep their own (confused-deputy and sse-resume-replay).
//
// A bare &http.Transport{} does not consult the environment, so before this every
// scan ignored HTTPS_PROXY while the OAuth clients honoured it. See
// httpx.ProxyFunc.
func Transport(opts Options) http.RoundTripper {
	if opts.DryRun {
		return &dryRunRoundTripper{rec: opts.Recorder}
	}
	tr := &http.Transport{}
	if opts.SkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	proxy, err := httpx.ProxyFunc(opts.Proxy)
	if err != nil {
		// Fail every request rather than fall back to a direct connection: a
		// mistyped proxy that silently bypasses the operator's interception is
		// precisely the outcome this option exists to prevent.
		return &erroringRoundTripper{err: err}
	}
	tr.Proxy = proxy
	return tr
}

// erroringRoundTripper fails every request with a fixed error. It reports a
// misconfigured proxy at the point of use, so the failure is attributable instead
// of appearing as a scan that mysteriously reached nothing.
type erroringRoundTripper struct{ err error }

func (e *erroringRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}
