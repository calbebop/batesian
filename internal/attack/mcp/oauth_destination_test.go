package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func oauthMetadataTarget(t *testing.T, metadata map[string]interface{}, fallback http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
			return
		}
		fallback.ServeHTTP(w, r)
	}))
}

func TestOAuthDCR_RejectsUnapprovedRegistrationOrigin(t *testing.T) {
	var hits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer collector.Close()

	target := oauthMetadataTarget(t, map[string]interface{}{
		"registration_endpoint": collector.URL + "/register",
	}, http.NotFoundHandler())
	defer target.Close()

	_, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), target.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("unapproved registration origin received %d requests", hits.Load())
	}
}

func TestOAuthMetadataSSRF_RejectsUnapprovedRegistrationOrigin(t *testing.T) {
	var hits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer collector.Close()

	target := oauthMetadataTarget(t, map[string]interface{}{
		"registration_endpoint": collector.URL + "/register",
	}, http.NotFoundHandler())
	defer target.Close()

	_, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(context.Background(), target.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("unapproved registration origin received %d requests", hits.Load())
	}
}

func TestConfusedDeputy_RejectsUnapprovedAuthorizationOriginBeforeRegistration(t *testing.T) {
	var registrations atomic.Int32
	collector := httptest.NewServer(http.NotFoundHandler())
	defer collector.Close()

	target := oauthMetadataTarget(t, map[string]interface{}{
		"registration_endpoint":  "{{BaseURL}}/register",
		"authorization_endpoint": collector.URL + "/authorize",
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			registrations.Add(1)
		}
		http.NotFound(w, r)
	}))
	defer target.Close()

	_, err := mcpattack.NewConfusedDeputyExecutor(confusedDeputyRC()).Execute(context.Background(), target.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if registrations.Load() != 0 {
		t.Fatalf("registration ran before authorization endpoint validation")
	}
}

func TestOAuthAudience_RejectsUnapprovedResourceMetadataOrigin(t *testing.T) {
	var hits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"resource":"https://api.example.test/mcp"}`))
	}))
	defer collector.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s/metadata"`, collector.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer target.Close()

	_, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(context.Background(), target.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("unapproved resource metadata origin received %d requests", hits.Load())
	}
}

func TestOAuthDCR_AllowsExplicitAdditionalOrigin(t *testing.T) {
	var registrations atomic.Int32
	var authorization string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			http.NotFound(w, r)
			return
		}
		registrations.Add(1)
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"client_id":"client-1","scope":"tools:write"}`))
	}))
	defer authServer.Close()

	target := oauthMetadataTarget(t, map[string]interface{}{
		"registration_endpoint": authServer.URL + "/register",
	}, http.NotFoundHandler())
	defer target.Close()

	opts := testOpts()
	opts.OAuthOrigins = []string{authServer.URL}
	opts.Token = "operator-secret"
	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(context.Background(), target.URL, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if registrations.Load() != 1 || len(findings) != 1 {
		t.Fatalf("expected one authorized registration and finding, got registrations=%d findings=%d",
			registrations.Load(), len(findings))
	}
	if authorization != "" {
		t.Fatalf("external registration request carried operator credential %q", authorization)
	}
}
