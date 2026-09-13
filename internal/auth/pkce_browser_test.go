package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// TestPerformPKCEFlow_HappyPath completes consent through a local callback.
func TestPerformPKCEFlow_HappyPath(t *testing.T) {
	const fakeCode = "fake-auth-code-xyz"
	const fakeAccess = "test-access-token"

	var (
		seenVerifier string
		seenCode     string
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			http.NotFound(w, r)
		case "/token":
			_ = r.ParseForm()
			seenCode = r.FormValue("code")
			seenVerifier = r.FormValue("code_verifier")
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
	logger := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
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
		if err == nil || (!strings.Contains(err.Error(), "Client.Timeout") && !strings.Contains(err.Error(), "context deadline exceeded")) {
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

// TestPerformPKCEFlow_StateMismatch verifies that a callback with a tampered
// state parameter is rejected (CSRF protection).
func TestPerformPKCEFlow_StateMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	port := pickFreePort(t)

	resultCh := make(chan error, 1)
	go func() {
		_, err := performPKCEFlowForTest(context.Background(), auth.PKCEFlowConfig{
			AuthURL:         srv.URL + "/authorize",
			TokenURL:        srv.URL + "/token",
			ClientID:        "c",
			RedirectPort:    port,
			OpenBrowser:     false,
			Logger:          func(string, ...interface{}) {},
			CallbackTimeout: 5 * time.Second,
		}, srv.Client())
		resultCh <- err
	}()

	// Give the flow a moment to bind the listener.
	time.Sleep(150 * time.Millisecond)

	cb := fmt.Sprintf("http://127.0.0.1:%d/callback?code=anything&state=tampered", port)
	resp, err := http.Get(cb)
	if err != nil {
		t.Fatalf("hitting callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case err := <-resultCh:
		if err == nil || !strings.Contains(err.Error(), "state") {
			t.Fatalf("expected state mismatch error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not reject tampered state within 5s")
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
