package attack_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestNewUnauthHTTPClient_StripsToken(t *testing.T) {
	opts := attack.Options{
		Token:          "super-secret",
		TimeoutSeconds: 30,
		SkipTLS:        true,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewUnauthHTTPClient(opts, vars)

	if attack.TokenOf(c) != "" {
		t.Errorf("NewUnauthHTTPClient: expected empty token, got %q", attack.TokenOf(c))
	}
}

func TestNewHTTPClient_PreservesToken(t *testing.T) {
	opts := attack.Options{
		Token:          "my-token",
		TimeoutSeconds: 10,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewHTTPClient(opts, vars)

	if attack.TokenOf(c) != "my-token" {
		t.Errorf("NewHTTPClient: expected token %q, got %q", "my-token", attack.TokenOf(c))
	}
}

// TestUserAgent_IncludesVersion verifies the User-Agent header reflects
// attack.Version so support / supportability of bug reports stays accurate.
func TestUserAgent_IncludesVersion(t *testing.T) {
	prev := attack.Version
	attack.Version = "0.99.0-test"
	t.Cleanup(func() { attack.Version = prev })

	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
	if _, err := c.GET(context.Background(), srv.URL, nil); err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if !strings.Contains(seen, "batesian/0.99.0-test") {
		t.Errorf("expected User-Agent to contain batesian/0.99.0-test, got %q", seen)
	}
}

// TestResponseContainsAny_SkipsEmptySubstring guards against the empty-needle
// false positive: strings.Contains(body, "") is always true, so an optional,
// absent value (e.g. a missing contextId) must not match any body.
func TestResponseContainsAny_SkipsEmptySubstring(t *testing.T) {
	r := &attack.Response{Body: []byte(`{"jsonrpc":"2.0","result":null}`)}

	if r.ContainsAny("") {
		t.Error(`ContainsAny("") matched; empty needle must be skipped`)
	}
	if r.ContainsAny("", "absent") {
		t.Error(`ContainsAny("", "absent") matched; neither needle is present`)
	}
	if !r.ContainsAny("", "result") {
		t.Error(`ContainsAny("", "result") did not match a present non-empty needle`)
	}
}

// TestResponse_IsAccepted guards the canonical JSON-RPC success oracle. The
// older IsSuccess() && !isJSONRPCError(body) idiom treated any 2xx that was not a
// JSON-RPC error envelope as success - including HTML, empty bodies, and "{}" -
// which false-positived targets that answer an unauthenticated probe with a 2xx
// non-JSON body. IsAccepted must require a real result envelope.
func TestResponse_IsAccepted(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
		want bool
	}{
		{"valid result object", 200, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, true},
		{"null result is a valid success", 200, `{"result":null}`, true},
		{"empty-object result is a valid success", 200, `{"result":{}}`, true},
		{"error envelope is rejection", 200, `{"jsonrpc":"2.0","error":{"code":-32600}}`, false},
		{"html body is rejection", 200, `<html><body>please log in</body></html>`, false},
		{"empty body is rejection", 200, ``, false},
		{"bare object with no result is rejection", 200, `{"jsonrpc":"2.0"}`, false},
		{"non-2xx is rejection", 401, `{"result":{}}`, false},
		{"both result and error is rejection", 200, `{"result":{},"error":{"code":-1}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &attack.Response{StatusCode: tc.code, Body: []byte(tc.body)}
			if got := r.IsAccepted(); got != tc.want {
				t.Errorf("IsAccepted() = %v, want %v (body=%q)", got, tc.want, tc.body)
			}
		})
	}
}

// TestResponse_IsJSON guards the raw-HTTP body gate used where a response is a
// bare JSON object (not a JSON-RPC result envelope), e.g. an A2A extended card
// fetched over HTTP GET.
func TestResponse_IsJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"object", `{"name":"agent","url":"https://x"}`, true},
		{"empty object", `{}`, true},
		{"html", `<html>`, false},
		{"empty", ``, false},
		{"array is not an object", `[1,2,3]`, false},
		{"null is not an object", `null`, false},
		{"bare scalar", `"hello"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &attack.Response{StatusCode: 200, Body: []byte(tc.body)}
			if got := r.IsJSON(); got != tc.want {
				t.Errorf("IsJSON() = %v, want %v (body=%q)", got, tc.want, tc.body)
			}
		})
	}
}

// TestHTTPClient_DoesNotFollowRedirects guards S1: the scan client must return
// the 3xx itself rather than follow it. Following would both mask an auth
// rejection (302 -> 200 login page read as success) and risk bouncing a request
// carrying the operator's bearer token to a third-party host.
func TestHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	loginHit := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound) // 302
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		select {
		case loginHit <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
	resp, err := c.GET(context.Background(), srv.URL+"/start", nil)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (redirect not followed), got %d", resp.StatusCode)
	}
	select {
	case <-loginHit:
		t.Fatal("client followed the redirect to /login; it must return the 3xx")
	default:
	}
}

// TestHTTPClient_RedirectDoesNotForwardToken guards the security property behind
// S1: because the client does not follow redirects, a request carrying the
// operator's bearer token is never forwarded to the redirect target (which may
// be a third-party host). A redirecting endpoint must not become a token leak.
func TestHTTPClient_RedirectDoesNotForwardToken(t *testing.T) {
	gotAuthz := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sink", http.StatusFound) // 302
	})
	mux.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotAuthz <- r.Header.Get("Authorization"):
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5, Token: "operator-bearer-secret"}, attack.NewVars(srv.URL, ""))
	resp, err := c.GET(context.Background(), srv.URL+"/start", nil)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (redirect not followed), got %d", resp.StatusCode)
	}
	select {
	case authz := <-gotAuthz:
		t.Fatalf("bearer token was forwarded to the redirect target (Authorization=%q); the client must not follow redirects", authz)
	default:
		// good: /sink was never reached, so the token stayed put
	}
}

// A body that fits must arrive whole. The previous 1 MB cap truncated silently,
// and a truncated JSON-RPC result is unparseable, which rules that treat an
// unparseable probe the same as a refused one reported as a clean surface. A
// wide-open MCP server was measured producing 1 finding with 1.33 MB responses
// and 7 with 20 KB ones, with nothing else changed.
func TestHTTPClient_LargeBodyIsNotTruncated(t *testing.T) {
	// Comfortably past the old 1 MB limit, comfortably under the new one.
	payload := `{"jsonrpc":"2.0","id":1,"result":{"pad":"` + strings.Repeat("x", 4<<20) + `"}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 30}, attack.NewVars(srv.URL, ""))
	resp, err := client.POST(context.Background(), srv.URL, nil, map[string]interface{}{"jsonrpc": "2.0"})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if len(resp.Body) != len(payload) {
		t.Fatalf("body is %d bytes, want %d: a fitting body must not be shortened", len(resp.Body), len(payload))
	}
	// The point of not truncating: the result still parses, so the rule sees a
	// success rather than what looks like a malformed reply.
	if !resp.IsAccepted() {
		t.Error("a large but valid JSON-RPC result must read as accepted")
	}
}

// Over the limit is an explicit error, not a quietly shortened body. Returning a
// truncated body would be indistinguishable from a server sending malformed JSON.
func TestHTTPClient_OverLimitBodyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 33 MB of payload, past the 32 MB ceiling.
		_, _ = io.WriteString(w, `{"result":"`+strings.Repeat("x", 33<<20)+`"}`)
	}))
	defer srv.Close()

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 60}, attack.NewVars(srv.URL, ""))
	resp, err := client.POST(context.Background(), srv.URL, nil, map[string]interface{}{"jsonrpc": "2.0"})
	if err == nil {
		t.Fatalf("expected an error for an over-limit body, got a %d byte response", len(resp.Body))
	}
	if !strings.Contains(err.Error(), "read limit") {
		t.Errorf("error should name the read limit, got: %v", err)
	}
}
