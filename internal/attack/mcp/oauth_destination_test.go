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
			document := make(map[string]interface{}, len(metadata)+1)
			for key, value := range metadata {
				document[key] = value
			}
			if _, ok := document["issuer"]; !ok {
				document["issuer"] = "http://" + r.Host
			}
			_ = json.NewEncoder(w).Encode(document)
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

func TestOAuthDCR_PathResourceDiscoversExternalIssuer(t *testing.T) {
	for _, tc := range []struct {
		name, issuerSuffix, resourceSuffix string
		approve, scanRoot                  bool
		wantRegistration                   bool
	}{
		{"unapproved", "", "", false, false, false},
		{"approved", "", "", true, false, true},
		{"root target", "", "", true, true, true},
		{"issuer mismatch", "/wrong", "", true, false, false},
		{"resource mismatch", "", "/other", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var metadataHits, registrations atomic.Int32
			var authServer *httptest.Server
			authServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/oauth-authorization-server/tenant":
					metadataHits.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{
						"issuer":                authServer.URL + "/tenant" + tc.issuerSuffix,
						"registration_endpoint": authServer.URL + "/register",
					})
				case "/register":
					registrations.Add(1)
					w.WriteHeader(http.StatusBadRequest)
				default:
					http.NotFound(w, r)
				}
			}))
			defer authServer.Close()

			var target *httptest.Server
			target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"resource":              target.URL + "/mcp" + tc.resourceSuffix,
						"authorization_servers": []string{authServer.URL + "/tenant"},
					})
					return
				}
				http.NotFound(w, r)
			}))
			defer target.Close()

			opts := testOpts()
			if tc.approve {
				opts.OAuthOrigins = []string{authServer.URL}
			}
			scanTarget := target.URL + "/mcp"
			if tc.scanRoot {
				scanTarget = target.URL
			}
			findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(t.Context(), scanTarget, opts)
			if len(findings) != 0 {
				t.Fatalf("unexpected finding: %+v", findings)
			}
			if tc.wantRegistration {
				if err != nil || metadataHits.Load() != 1 || registrations.Load() != 1 {
					t.Fatalf("approved issuer not reached: metadata=%d registrations=%d err=%v", metadataHits.Load(), registrations.Load(), err)
				}
			} else if !errors.Is(err, attack.ErrInconclusive) || registrations.Load() != 0 || ((!tc.approve || tc.resourceSuffix != "") && metadataHits.Load() != 0) {
				t.Fatalf("issuer should remain untested: metadata=%d registrations=%d err=%v", metadataHits.Load(), registrations.Load(), err)
			}
		})
	}
}

func TestOAuthDCR_ChallengeOnlyResourceMetadata(t *testing.T) {
	var registrations atomic.Int32
	var metadataCredential atomic.Bool
	var authServer *httptest.Server
	authServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                authServer.URL,
				"registration_endpoint": authServer.URL + "/register",
			})
		case "/register":
			registrations.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer authServer.Close()

	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/prm"`, target.URL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/prm":
			if r.Header.Get("Authorization") != "" {
				metadataCredential.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"resource":              target.URL + "/mcp",
				"authorization_servers": []string{authServer.URL},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	opts := testOpts()
	opts.OAuthOrigins = []string{authServer.URL}
	opts.Token = "operator-secret"
	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(t.Context(), target.URL, opts)
	if err != nil || len(findings) != 0 || registrations.Load() != 1 || metadataCredential.Load() {
		t.Fatalf("challenge-only metadata was not followed safely: findings=%+v registrations=%d credential=%t err=%v",
			findings, registrations.Load(), metadataCredential.Load(), err)
	}
}

func TestOAuthDCR_RejectsUnapprovedChallengeMetadataOrigin(t *testing.T) {
	var metadataHits atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://example.test/mcp"}`))
	}))
	defer collector.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/prm"`, collector.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer target.Close()

	findings, err := mcpattack.NewOAuthDCRExecutor(oauthRC()).Execute(t.Context(), target.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || metadataHits.Load() != 0 {
		t.Fatalf("unapproved metadata origin was contacted: findings=%+v hits=%d err=%v", findings, metadataHits.Load(), err)
	}
}
