package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/auth"
)

func performPKCEFlowForTest(ctx context.Context, cfg auth.PKCEFlowConfig, client *http.Client) (*auth.TokenResponse, error) {
	return auth.PerformPKCEFlowWithClient(ctx, cfg, client)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTunnelProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}))
	t.Cleanup(func() {
		proxy.CloseClientConnections()
		proxy.Close()
	})
	return proxy, hits
}

// TestPerformPKCEFlow_RejectsHTTPAuthURL verifies the public function refuses
// authorization URLs that would expose the auth code over cleartext.
func TestPerformPKCEFlow_RejectsHTTPAuthURL(t *testing.T) {
	_, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
		AuthURL:  "http://auth.example.com/authorize",
		TokenURL: "https://auth.example.com/token",
		ClientID: "c",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS error for http:// authorization URL, got: %v", err)
	}
}

// TestPerformPKCEFlow_RejectsHTTPTokenURL verifies the public function refuses
// token endpoints that would expose authorization codes / tokens over cleartext.
func TestPerformPKCEFlow_RejectsHTTPTokenURL(t *testing.T) {
	_, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
		AuthURL:  "https://auth.example.com/authorize",
		TokenURL: "http://auth.example.com/token",
		ClientID: "c",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS error for http:// token URL, got: %v", err)
	}
}

// TestPerformPKCEFlow_RequiresClientID verifies validation of required parameters.
func TestPerformPKCEFlow_RequiresClientID(t *testing.T) {
	_, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
		AuthURL:  "https://auth.example.com/authorize",
		TokenURL: "https://auth.example.com/token",
	})
	if err == nil || !strings.Contains(err.Error(), "client ID") {
		t.Fatalf("expected client ID error, got: %v", err)
	}
}

func TestPerformPKCEFlowRejectsInvalidRedirectPort(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			_, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
				AuthURL:      "https://auth.example.com/authorize",
				TokenURL:     "https://auth.example.com/token",
				ClientID:     "client",
				RedirectPort: port,
			})
			want := fmt.Sprintf("redirect port must be between 1 and 65535, got %d", port)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q, got %v", want, err)
			}
		})
	}
}

// TestPerformPKCEFlow_HappyPath completes consent through a local callback.
func TestPerformPKCEFlow_HappyPath(t *testing.T) {
	const fakeCode = "fake-auth-code-xyz"
	const fakeAccess = "test-access-token"

	var (
		seenVerifier string
		seenCode     string
		seenResource string
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			http.NotFound(w, r)
		case "/token":
			_ = r.ParseForm()
			seenCode = r.FormValue("code")
			seenVerifier = r.FormValue("code_verifier")
			seenResource = r.FormValue("resource")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": fakeAccess,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	port := pickFreePort(t)

	urlCh := make(chan string, 1)
	warningCh := make(chan string, 1)
	logger := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "one-time state value") {
			warningCh <- msg
		}
		if strings.Contains(msg, "https://") && strings.Contains(msg, "code_challenge") {
			urlCh <- strings.TrimSpace(msg)
		}
	}

	type flowResult struct {
		tok *auth.TokenResponse
		err error
	}
	resultCh := make(chan flowResult, 1)
	go func() {
		tok, err := performPKCEFlowForTest(context.Background(), auth.PKCEFlowConfig{
			AuthURL:         srv.URL + "/authorize",
			TokenURL:        srv.URL + "/token",
			ClientID:        "test-client",
			RedirectPort:    port,
			Scopes:          []string{"read"},
			Resource:        "https://mcp.example.com/mcp",
			OpenBrowser:     false,
			Logger:          logger,
			CallbackTimeout: 10 * time.Second,
		}, srv.Client())
		resultCh <- flowResult{tok: tok, err: err}
	}()

	var authURL string
	select {
	case authURL = <-urlCh:
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not print authorization URL within 5s")
	}
	select {
	case <-warningCh:
	default:
		t.Fatal("flow printed the authorization URL without a privacy warning")
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("authorization URL missing state parameter")
	}
	if got := parsed.Query().Get("code_challenge"); got == "" {
		t.Error("authorization URL missing code_challenge parameter")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %q", got)
	}
	if got := parsed.Query().Get("response_type"); got != "code" {
		t.Errorf("expected response_type=code, got %q", got)
	}
	if got := parsed.Query().Get("resource"); got != "https://mcp.example.com/mcp" {
		t.Errorf("authorization resource = %q", got)
	}

	cb := fmt.Sprintf("http://127.0.0.1:%d/callback?code=%s&state=%s", port, fakeCode, state)
	resp, err := http.Get(cb)
	if err != nil {
		t.Fatalf("hitting callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback returned %d, expected 200", resp.StatusCode)
	}

	var res flowResult
	select {
	case res = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatal("flow did not complete within 10s of callback")
	}
	if res.err != nil {
		t.Fatalf("flow returned error: %v", res.err)
	}
	if res.tok.AccessToken != fakeAccess {
		t.Errorf("expected access_token=%q, got %q", fakeAccess, res.tok.AccessToken)
	}

	if seenVerifier == "" {
		t.Error("token endpoint did not see code_verifier")
	}
	if seenCode != fakeCode {
		t.Errorf("token endpoint received code=%q, expected %q", seenCode, fakeCode)
	}
	if seenResource != "https://mcp.example.com/mcp" {
		t.Errorf("token endpoint received resource=%q", seenResource)
	}
}

func TestPerformPKCEFlowUsesRequestTimeoutAfterCallback(t *testing.T) {
	tokenStarted := make(chan struct{}, 1)
	tokenClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		tokenStarted <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}

	port := pickFreePort(t)
	urlCh := make(chan string, 1)
	logger := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "code_challenge") {
			urlCh <- strings.TrimSpace(msg)
		}
	}

	resultCh := make(chan error, 1)
	const requestTimeout = 50 * time.Millisecond
	go func() {
		_, err := performPKCEFlowForTest(context.Background(), auth.PKCEFlowConfig{
			AuthURL:         "https://auth.example.com/authorize",
			TokenURL:        "https://auth.example.com/token",
			ClientID:        "client",
			RedirectPort:    port,
			OpenBrowser:     false,
			Logger:          logger,
			Timeout:         requestTimeout,
			CallbackTimeout: 2 * time.Second,
		}, tokenClient)
		resultCh <- err
	}()

	var authURL string
	select {
	case authURL = <-urlCh:
	case <-time.After(2 * time.Second):
		t.Fatal("flow did not print an authorization URL")
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}
	time.Sleep(2 * requestTimeout)
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback?code=test&state=%s", port, parsed.Query().Get("state"))
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("hitting callback: %v", err)
	}
	resp.Body.Close()

	select {
	case err := <-resultCh:
		if err == nil || !strings.Contains(err.Error(), "auth code exchange timed out") || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected token request timeout, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("token exchange ignored its request timeout")
	}
	select {
	case <-tokenStarted:
	default:
		t.Fatal("flow timed out before the token exchange")
	}
}

func TestPerformPKCEFlowUsesProxyAndSkipTLS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"proxied-token"}`))
	}))
	defer target.Close()

	proxy, proxyHits := newTunnelProxy(t)

	port := pickFreePort(t)
	urlCh := make(chan string, 1)
	logger := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "code_challenge") {
			urlCh <- strings.TrimSpace(msg)
		}
	}

	type flowResult struct {
		token string
		err   error
	}
	resultCh := make(chan flowResult, 1)
	go func() {
		token, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
			AuthURL:         "https://auth.example.com/authorize",
			TokenURL:        target.URL + "/token",
			ClientID:        "client",
			RedirectPort:    port,
			OpenBrowser:     false,
			Logger:          logger,
			Timeout:         time.Second,
			Proxy:           proxy.URL,
			SkipTLS:         true,
			CallbackTimeout: 2 * time.Second,
		})
		result := flowResult{err: err}
		if token != nil {
			result.token = token.AccessToken
		}
		resultCh <- result
	}()

	var authURL string
	select {
	case authURL = <-urlCh:
	case <-time.After(2 * time.Second):
		t.Fatal("flow did not print an authorization URL")
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback?code=test&state=%s", port, parsed.Query().Get("state"))
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("hitting callback: %v", err)
	}
	resp.Body.Close()

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("flow failed: %v", result.err)
		}
		if result.token != "proxied-token" {
			t.Fatalf("token = %q, want proxied-token", result.token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("token exchange did not return")
	}
	if proxyHits.Load() == 0 {
		t.Fatal("proxy was not contacted")
	}
}

func TestPerformPKCEFlow_StateMismatchKeepsLoginPending(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"valid-token"}`)
	}))
	defer srv.Close()

	port := pickFreePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	urlCh := make(chan string, 1)
	type flowResult struct {
		token *auth.TokenResponse
		err   error
	}
	resultCh := make(chan flowResult, 1)
	go func() {
		token, err := performPKCEFlowForTest(ctx, auth.PKCEFlowConfig{
			AuthURL:      srv.URL + "/authorize",
			TokenURL:     srv.URL + "/token",
			ClientID:     "c",
			RedirectPort: port,
			OpenBrowser:  false,
			Logger: func(format string, args ...interface{}) {
				msg := fmt.Sprintf(format, args...)
				if strings.Contains(msg, "code_challenge") {
					urlCh <- strings.TrimSpace(msg)
				}
			},
			CallbackTimeout: 5 * time.Second,
		}, srv.Client())
		resultCh <- flowResult{token, err}
	}()

	var authURL string
	select {
	case authURL = <-urlCh:
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not print authorization URL")
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("authorization URL missing state")
	}

	cb := fmt.Sprintf("http://127.0.0.1:%d/callback?code=anything&state=tampered", port)
	resp, err := http.Get(cb)
	if err != nil {
		t.Fatalf("hitting callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched callback status = %d, want 400", resp.StatusCode)
	}

	select {
	case result := <-resultCh:
		t.Fatalf("mismatched callback ended the login: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}

	cb = fmt.Sprintf("http://127.0.0.1:%d/callback?code=valid&state=%s", port, url.QueryEscape(state))
	resp, err = http.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid callback status = %d, want 200", resp.StatusCode)
	}
	select {
	case result := <-resultCh:
		if result.err != nil || result.token == nil || result.token.AccessToken != "valid-token" {
			t.Fatalf("valid callback did not finish login: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("valid callback did not finish login")
	}
}

func TestPerformPKCEFlowRejectsInvalidIssuer(t *testing.T) {
	for _, issuer := range []string{
		"http://auth.example", "https://auth.example?x=1", "https://auth.example?",
		"https://auth.example#fragment", "https://user@auth.example", "https://auth.example:0",
	} {
		t.Run(issuer, func(t *testing.T) {
			_, err := auth.PerformPKCEFlow(context.Background(), auth.PKCEFlowConfig{
				AuthURL: "https://auth.example/authorize", TokenURL: "https://auth.example/token",
				Issuer: issuer, ClientID: "client",
			})
			if err == nil || !strings.Contains(err.Error(), "OAuth issuer") {
				t.Fatalf("issuer %q accepted: %v", issuer, err)
			}
		})
	}
}

func TestPerformPKCEFlowIssuerCallback(t *testing.T) {
	const issuer = "https://auth.example/tenant"
	tests := []struct {
		name, expectedIssuer string
		badIssuer            []string
		badError             bool
		badSuffix, wantError string
	}{
		{name: "mismatched", expectedIssuer: issuer, badIssuer: []string{"https://other.example"}},
		{name: "missing", expectedIssuer: issuer},
		{name: "duplicate", expectedIssuer: issuer, badIssuer: []string{issuer, issuer}},
		{name: "unexpected", badIssuer: []string{issuer}},
		{name: "error response", expectedIssuer: issuer, badIssuer: []string{"https://other.example"}, badError: true},
		{name: "malformed query", expectedIssuer: issuer, badIssuer: []string{issuer}, badSuffix: "&iss=%zz", wantError: "invalid query"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var exchanges atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/token" {
					http.NotFound(w, r)
					return
				}
				exchanges.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"access_token":"valid-token"}`)
			}))
			defer srv.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			port := pickFreePort(t)
			urlCh := make(chan string, 1)
			resultCh := make(chan error, 1)
			go func() {
				_, err := performPKCEFlowForTest(ctx, auth.PKCEFlowConfig{
					AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token",
					Issuer: tc.expectedIssuer, ClientID: "client", RedirectPort: port,
					CallbackTimeout: 5 * time.Second,
					Logger: func(format string, args ...interface{}) {
						msg := fmt.Sprintf(format, args...)
						if strings.Contains(msg, "code_challenge") {
							urlCh <- strings.TrimSpace(msg)
						}
					},
				}, srv.Client())
				resultCh <- err
			}()

			var authorizationURL string
			select {
			case authorizationURL = <-urlCh:
			case <-time.After(5 * time.Second):
				t.Fatal("flow did not print authorization URL")
			}
			parsed, err := url.Parse(authorizationURL)
			if err != nil {
				t.Fatal(err)
			}
			state := parsed.Query().Get("state")
			if state == "" {
				t.Fatal("authorization URL missing state")
			}
			callback := func(issuers []string, oauthError bool, suffix string) *http.Response {
				t.Helper()
				query := url.Values{"state": {state}}
				if oauthError {
					query.Set("error", "access_denied")
				} else {
					query.Set("code", "valid")
				}
				for _, value := range issuers {
					query.Add("iss", value)
				}
				resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?%s%s", port, query.Encode(), suffix))
				if err != nil {
					t.Fatal(err)
				}
				return resp
			}

			bad := callback(tc.badIssuer, tc.badError, tc.badSuffix)
			body, err := io.ReadAll(bad.Body)
			bad.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			wantError := tc.wantError
			if wantError == "" {
				wantError = "issuer mismatch"
			}
			if bad.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), wantError) {
				t.Fatalf("invalid issuer response: %d %s", bad.StatusCode, body)
			}
			if tc.badError && strings.Contains(string(body), "access_denied") {
				t.Fatalf("unverified OAuth error appeared in response: %s", body)
			}
			select {
			case err := <-resultCh:
				t.Fatalf("invalid issuer ended the flow: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			if exchanges.Load() != 0 {
				t.Fatal("invalid issuer caused a token exchange")
			}

			goodIssuer := []string(nil)
			if tc.expectedIssuer != "" {
				goodIssuer = []string{tc.expectedIssuer}
			}
			good := callback(goodIssuer, false, "")
			good.Body.Close()
			if good.StatusCode != http.StatusOK {
				t.Fatalf("valid callback returned %d", good.StatusCode)
			}
			select {
			case err := <-resultCh:
				if err != nil {
					t.Fatalf("valid callback failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("valid callback did not finish")
			}
			if exchanges.Load() != 1 {
				t.Fatalf("token exchanges = %d, want 1", exchanges.Load())
			}
		})
	}
}

func TestPerformPKCEFlowErrorRequiresMatchingState(t *testing.T) {
	tests := []struct {
		name      string
		stateMode string
	}{
		{name: "missing", stateMode: "missing"},
		{name: "mismatched", stateMode: "mismatched"},
		{name: "duplicate", stateMode: "duplicate"},
		{name: "matching", stateMode: "matching"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := pickFreePort(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			urlCh := make(chan string, 1)
			resultCh := make(chan error, 1)
			go func() {
				_, err := auth.PerformPKCEFlow(ctx, auth.PKCEFlowConfig{
					AuthURL:         "https://auth.example.com/authorize",
					TokenURL:        "https://auth.example.com/token",
					Issuer:          "https://auth.example.com",
					ClientID:        "client",
					RedirectPort:    port,
					CallbackTimeout: 5 * time.Second,
					Logger: func(format string, args ...interface{}) {
						msg := fmt.Sprintf(format, args...)
						if strings.Contains(msg, "code_challenge") {
							urlCh <- strings.TrimSpace(msg)
						}
					},
				})
				resultCh <- err
			}()

			var authURL string
			select {
			case authURL = <-urlCh:
			case <-time.After(5 * time.Second):
				t.Fatal("flow did not print authorization URL")
			}
			parsed, err := url.Parse(authURL)
			if err != nil {
				t.Fatal(err)
			}
			state := parsed.Query().Get("state")
			if state == "" {
				t.Fatal("authorization URL missing state")
			}

			query := url.Values{"error": {"access_denied"}, "error_description": {"denied"}, "iss": {"https://auth.example.com"}}
			switch tc.stateMode {
			case "mismatched":
				query.Set("state", "tampered")
			case "duplicate":
				query.Add("state", state)
				query.Add("state", "tampered")
			case "matching":
				query.Set("state", state)
			}
			callback := fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, query.Encode())
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get(callback)
			if err != nil {
				t.Fatalf("hitting callback: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("callback status = %d, want 400", resp.StatusCode)
			}
			if tc.stateMode != "matching" && strings.Contains(string(body), "access_denied") {
				t.Fatalf("unverified OAuth error appeared in callback response: %s", body)
			}
			if tc.stateMode == "matching" && !strings.Contains(string(body), "access_denied") {
				t.Fatalf("verified OAuth error missing from callback response: %s", body)
			}
			if tc.stateMode != "matching" {
				select {
				case err := <-resultCh:
					t.Fatalf("unverified OAuth error ended the login: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				query.Set("state", state)
				callback = fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, query.Encode())
				resp, err = client.Get(callback)
				if err != nil {
					t.Fatalf("hitting valid callback: %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("valid OAuth error status = %d, want 400", resp.StatusCode)
				}
			}

			select {
			case err := <-resultCh:
				if err == nil || !strings.Contains(err.Error(), "authorization server returned error: access_denied") {
					t.Fatalf("flow error = %v, want verified access_denied", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("flow did not return after callback")
			}
		})
	}
}

// pickFreePort asks the kernel for an unused TCP port on 127.0.0.1.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not pick free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
