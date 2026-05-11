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

// performPKCEFlowForTest forwards to the test-only export that lets us pass a
// trusted http.Client for the token exchange leg.
func performPKCEFlowForTest(ctx context.Context, cfg auth.PKCEFlowConfig, client *http.Client) (*auth.TokenResponse, error) {
	return auth.PerformPKCEFlowWithClient(ctx, cfg, client)
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

// TestPerformPKCEFlow_HappyPath drives the full flow using a fake authorization
// server and a programmatic browser stand-in. The test:
//  1. Spins up an httptest TLS server acting as both auth + token endpoint.
//  2. Picks an unused local port for the redirect listener.
//  3. Starts PerformPKCEFlow in a goroutine.
//  4. Parses the printed authorization URL to capture state and challenge.
//  5. Issues a callback to 127.0.0.1:<port>/callback with a fake code.
//  6. The flow exchanges the code at the fake token endpoint.
//  7. Asserts the access token comes back correctly.
func TestPerformPKCEFlow_HappyPath(t *testing.T) {
	const fakeCode = "fake-auth-code-xyz"
	const fakeAccess = "test-access-token"

	var (
		seenVerifier string
		seenCode     string
	)

	// Use NewTLSServer so AuthURL/TokenURL satisfy the https:// guard.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			// In a real flow the server would render a consent screen here;
			// the test simulates user approval by hitting the callback directly,
			// so this branch is unused.
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

	// Pick an unused port so this test doesn't conflict with the default 9876.
	port := pickFreePort(t)

	// Channel to capture the authorization URL printed by the flow.
	urlCh := make(chan string, 1)
	logger := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		// The auth URL line starts with "  https://" (leading double-space prefix).
		if strings.Contains(msg, "https://") && strings.Contains(msg, "code_challenge") {
			urlCh <- strings.TrimSpace(msg)
		}
	}

	// Drive the flow in a goroutine; we'll feed it a callback below.
	type flowResult struct {
		tok *auth.TokenResponse
		err error
	}
	resultCh := make(chan flowResult, 1)
	go func() {
		// PerformPKCEFlow will hit srv's TLS endpoints; we need a CA-aware client
		// for the token exchange. Since we cannot inject one through the public
		// API, the test redirects the token URL to our trusted test server by
		// stashing the cert in the system pool would be heavy. Instead we use
		// the fact that NewTLSServer produces a self-signed cert and rely on
		// the InsecureSkipVerify option below. For this test we use the helper
		// performPKCEFlowForTest which exercises the same code path via a custom
		// http.Client that trusts the test server.
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

	// Wait until the flow has printed the authorization URL.
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

	// Simulate the user being redirected to the local callback after consenting.
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

	// Wait for the flow to complete the token exchange and return.
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

	// Verify the token endpoint received the matching verifier and code.
	if seenVerifier == "" {
		t.Error("token endpoint did not see code_verifier")
	}
	if seenCode != fakeCode {
		t.Errorf("token endpoint received code=%q, expected %q", seenCode, fakeCode)
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
