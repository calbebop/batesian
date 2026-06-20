package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PKCEFlowConfig holds parameters for the interactive PKCE authorization code flow.
type PKCEFlowConfig struct {
	// AuthURL is the OAuth 2.0 authorization endpoint
	// (e.g. https://auth.example.com/authorize).
	AuthURL string

	// TokenURL is the OAuth 2.0 token endpoint where the authorization code
	// will be exchanged for an access token.
	TokenURL string

	// ClientID is the OAuth client identifier registered with the authorization server.
	ClientID string

	// RedirectPort is the local TCP port the callback listener binds to on
	// 127.0.0.1. The full redirect URI is http://127.0.0.1:<port>/callback.
	// Defaults to 9876 when zero.
	RedirectPort int

	// Scopes is the list of scopes to request.
	Scopes []string

	// Audience is the optional API audience identifier (Auth0/Okta-style).
	Audience string

	// OpenBrowser controls whether the CLI attempts to open the system browser
	// automatically. When false, the user is expected to manually open the
	// printed authorization URL.
	OpenBrowser bool

	// Logger receives status messages during the flow (URL prompts, success
	// confirmations). Pass io.Discard for silent operation. May be nil.
	Logger func(format string, args ...interface{})

	// CallbackTimeout is the maximum time to wait for the redirect callback.
	// Defaults to 5 minutes when zero.
	CallbackTimeout time.Duration
}

// PerformPKCEFlow runs an interactive OAuth 2.0 authorization code flow with PKCE.
// It generates a verifier/challenge, builds an authorization URL, optionally
// opens the user's browser, listens for the redirect callback, and exchanges
// the returned code for tokens.
//
// Both AuthURL and TokenURL must use HTTPS. The function blocks until the user
// completes the consent flow or CallbackTimeout elapses.
func PerformPKCEFlow(ctx context.Context, cfg PKCEFlowConfig) (*TokenResponse, error) {
	if !strings.HasPrefix(cfg.AuthURL, "https://") {
		return nil, fmt.Errorf("authorization URL must use HTTPS (got: %s)", cfg.AuthURL)
	}
	if !strings.HasPrefix(cfg.TokenURL, "https://") {
		return nil, fmt.Errorf("token URL must use HTTPS (got: %s)", cfg.TokenURL)
	}
	if cfg.ClientID == "" {
		return nil, errors.New("PKCE flow requires a client ID")
	}
	return performPKCEFlowWithClient(ctx, cfg, nil)
}

// performPKCEFlowWithClient is the inner implementation. When tokenClient is
// non-nil it is used for the token exchange; this allows tests to inject a
// trusted client when the token endpoint is an httptest TLS server.
func performPKCEFlowWithClient(ctx context.Context, cfg PKCEFlowConfig, tokenClient *http.Client) (*TokenResponse, error) {
	if cfg.RedirectPort == 0 {
		cfg.RedirectPort = 9876
	}
	if cfg.CallbackTimeout == 0 {
		cfg.CallbackTimeout = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = func(string, ...interface{}) {}
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE parameters: %w", err)
	}

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("generating state parameter: %w", err)
	}

	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", cfg.RedirectPort)

	authURL, err := buildAuthURL(cfg, pkce.Challenge, state, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("building authorization URL: %w", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.RedirectPort))
	if err != nil {
		return nil, fmt.Errorf("listening on 127.0.0.1:%d for OAuth callback: %w", cfg.RedirectPort, err)
	}
	defer listener.Close()

	code, callbackErr := waitForCallback(ctx, listener, state, cfg.CallbackTimeout, cfg.Logger, authURL, cfg.OpenBrowser)
	if callbackErr != nil {
		return nil, callbackErr
	}

	cfg.Logger("Exchanging authorization code for access token...")
	exchangeCfg := AuthCodeConfig{
		TokenURL:     cfg.TokenURL,
		ClientID:     cfg.ClientID,
		RedirectURI:  redirectURI,
		Code:         code,
		PKCEVerifier: pkce.Verifier,
	}
	var tok *TokenResponse
	if tokenClient != nil {
		tok, err = exchangeAuthCodeWithClient(ctx, exchangeCfg, tokenClient)
	} else {
		tok, err = ExchangeAuthCode(ctx, exchangeCfg)
	}
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	cfg.Logger("Token acquired (expires in %ds)", tok.ExpiresIn)
	return tok, nil
}

// buildAuthURL constructs the authorization URL with PKCE parameters.
func buildAuthURL(cfg PKCEFlowConfig, challenge, state, redirectURI string) (string, error) {
	parsed, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Audience != "" {
		q.Set("audience", cfg.Audience)
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// generateState produces a cryptographically random state parameter for CSRF protection.
func generateState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// waitForCallback opens the browser (best-effort), serves a single HTTP
// callback handler on the given listener, and returns the authorization code.
// State is verified against the value sent in the authorization request.
func waitForCallback(
	ctx context.Context,
	listener net.Listener,
	expectedState string,
	timeout time.Duration,
	logger func(string, ...interface{}),
	authURL string,
	openBrowser bool,
) (string, error) {
	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		errParam := q.Get("error")
		if errParam != "" {
			desc := q.Get("error_description")
			respondCallbackError(w, errParam, desc)
			once.Do(func() {
				resultCh <- result{err: fmt.Errorf("authorization server returned error: %s (%s)", errParam, desc)}
			})
			return
		}
		gotState := q.Get("state")
		if gotState != expectedState {
			respondCallbackError(w, "state mismatch", "the state parameter did not match the value sent in the authorization request")
			once.Do(func() {
				resultCh <- result{err: errors.New("state parameter mismatch (possible CSRF; aborting)")}
			})
			return
		}
		code := q.Get("code")
		if code == "" {
			respondCallbackError(w, "missing code", "no authorization code returned by the server")
			once.Do(func() {
				resultCh <- result{err: errors.New("authorization server did not return a code")}
			})
			return
		}
		respondCallbackSuccess(w)
		once.Do(func() {
			resultCh <- result{code: code}
		})
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger("Open this URL to authorize Batesian:")
	logger("  %s", authURL)
	if openBrowser {
		if err := openInBrowser(authURL); err != nil {
			logger("(could not auto-open browser: %v -- copy the URL manually)", err)
		}
	}
	logger("Waiting for callback on %s ...", listener.Addr().String())

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %s waiting for OAuth callback", timeout)
	case r := <-resultCh:
		return r.code, r.err
	}
}

// successPage is the HTML rendered to the browser after a successful callback.
// It contains no user-controlled data.
var successPage = template.Must(template.New("ok").Parse(
	`<!doctype html><html><head><title>Batesian authorization complete</title>` +
		`<style>body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#eaeaea;` +
		`display:flex;align-items:center;justify-content:center;height:100vh;margin:0}` +
		`div{text-align:center;padding:2rem;background:#1a1a1a;border-radius:8px;border:1px solid #333}` +
		`h1{margin-top:0;font-weight:500}p{color:#999}</style></head><body>` +
		`<div><h1>Authorization complete</h1><p>You can close this tab and return to your terminal.</p></div>` +
		`</body></html>`))

// errorPage renders the failure page. The Err and Desc fields are auto-escaped
// by html/template so callers may pass raw values from the OAuth callback.
var errorPage = template.Must(template.New("err").Parse(
	`<!doctype html><html><head><title>Batesian authorization failed</title>` +
		`<style>body{font-family:system-ui,sans-serif;background:#0f0f0f;color:#eaeaea;` +
		`display:flex;align-items:center;justify-content:center;height:100vh;margin:0}` +
		`div{text-align:center;padding:2rem;background:#1a1a1a;border-radius:8px;border:1px solid #ff5555}` +
		`h1{margin-top:0;font-weight:500;color:#ff5555}code{background:#222;padding:0.25rem 0.5rem;border-radius:4px}</style></head>` +
		`<body><div><h1>Authorization failed</h1><p><code>{{.Err}}</code></p><p>{{.Desc}}</p></div></body></html>`))

// respondCallbackSuccess writes a friendly HTML page to the user's browser
// after a successful authorization callback.
func respondCallbackSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = successPage.Execute(w, nil)
}

// respondCallbackError writes an error page so the user knows the flow failed.
// errParam and desc come from the OAuth provider; html/template escapes them
// before rendering.
func respondCallbackError(w http.ResponseWriter, errParam, desc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = errorPage.Execute(w, struct{ Err, Desc string }{Err: errParam, Desc: desc})
}

// openInBrowser launches the user's default web browser for the given URL.
// It returns an error if no platform-appropriate command is available.
//
// The target is validated as an https:// authorization URL by PerformPKCEFlow
// before reaching this function, so the variable arg to exec.Command is bounded
// to URLs we generated ourselves.
//
// On Windows, the URL is launched via cmd /c start "" "<url>" to avoid the
// quirk where start treats the first quoted argument as a window title.
func openInBrowser(target string) error {
	if !strings.HasPrefix(target, "https://") {
		return fmt.Errorf("refusing to open non-https URL in browser: %q", target)
	}
	switch runtime.GOOS {
	case "windows":
		// #nosec G204 -- target validated as https URL above.
		return exec.Command("cmd", "/c", "start", "", target).Start()
	case "darwin":
		// #nosec G204 -- target validated as https URL above.
		return exec.Command("open", target).Start()
	default:
		// #nosec G204 -- target validated as https URL above.
		return exec.Command("xdg-open", target).Start()
	}
}
