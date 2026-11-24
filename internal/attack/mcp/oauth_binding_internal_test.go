package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestProtectedResourceMetadataBinding(t *testing.T) {
	const origin = "https://resource.example.test"
	const wellKnown = origin + "/.well-known/oauth-protected-resource"
	for _, tc := range []struct {
		name, target, resource, metadata, challenged string
		want                                         bool
	}{
		{"root", origin, origin, wellKnown, "", true},
		{"wrong root resource", origin, origin + "/mcp", wellKnown, "", false},
		{"path", origin + "/mcp", origin + "/mcp", wellKnown + "/mcp", "", true},
		{"case difference", origin, "https://RESOURCE.example.test", wellKnown, "", false},
		{"query", origin + "/mcp?tenant=one", origin + "/mcp?tenant=one", wellKnown + "/mcp?tenant=one", "", true},
		{"wrong query", origin + "/mcp?tenant=one", origin + "/mcp?tenant=two", wellKnown + "/mcp?tenant=one", "", false},
		{"challenge", origin, origin + "/mcp", origin + "/metadata", origin + "/mcp", true},
		{"wrong challenge resource", origin, origin, origin + "/metadata", origin + "/mcp", false},
		{"invalid well-known suffix", origin, origin, wellKnown + "-other", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := prmMatchesTarget(tc.target, tc.resource, tc.metadata, tc.challenged); got != tc.want {
				t.Fatalf("prmMatchesTarget() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOAuthWellKnownURLsRetainResourceQuery(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"https://resource.example.test/mcp?tenant=one", "https://resource.example.test/.well-known/oauth-protected-resource/mcp?tenant=one"},
		{"https://resource.example.test/mcp/?tenant=one", "https://resource.example.test/.well-known/oauth-protected-resource/mcp/?tenant=one"},
	} {
		urls := oauthWellKnownURLs(tc.target, "/.well-known/oauth-protected-resource")
		if len(urls) == 0 || urls[0] != tc.want {
			t.Errorf("first metadata URL for %q = %q, want %q", tc.target, urls, tc.want)
		}
	}
}

func TestDiscoverOAuthFields_TrailingSlashIssuer(t *testing.T) {
	for _, suffix := range []string{"/issuer/", "/"} {
		for _, wrongClaim := range []bool{false, true} {
			t.Run(suffix+"/wrong="+fmt.Sprint(wrongClaim), func(t *testing.T) {
				var metadataReads atomic.Int32
				var srv *httptest.Server
				metadataPath := "/.well-known/oauth-authorization-server" + strings.TrimSuffix(suffix, "/")
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					issuer := srv.URL + suffix
					switch r.URL.Path {
					case "/.well-known/oauth-protected-resource/mcp/":
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"resource": srv.URL + "/mcp/", "authorization_servers": []string{issuer},
						})
					case metadataPath:
						metadataReads.Add(1)
						if wrongClaim {
							issuer = strings.TrimSuffix(issuer, "/")
						}
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]string{
							"issuer": issuer, "registration_endpoint": srv.URL + "/register",
						})
					default:
						http.NotFound(w, r)
					}
				}))
				defer srv.Close()

				target := srv.URL + "/mcp/"
				client := attack.NewUnauthHTTPClient(attack.Options{}, attack.NewVars(target, ""))
				fields, err := discoverOAuthFields(t.Context(), client, target, "registration_endpoint")
				if metadataReads.Load() != 1 {
					t.Fatalf("issuer metadata reads = %d, want 1", metadataReads.Load())
				}
				if wrongClaim {
					if fields != nil || !errors.Is(err, attack.ErrInconclusive) {
						t.Fatalf("mismatched issuer accepted: fields=%v err=%v", fields, err)
					}
				} else if err != nil || fields["registration_endpoint"] != srv.URL+"/register" {
					t.Fatalf("valid issuer metadata ignored: fields=%v err=%v", fields, err)
				}
			})
		}
	}
}

func TestDiscoverOAuthFields_TrailingSlashTargetIssuerFallback(t *testing.T) {
	for _, wrongClaim := range []bool{false, true} {
		t.Run(fmt.Sprint(wrongClaim), func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/oauth-authorization-server/mcp" {
					http.NotFound(w, r)
					return
				}
				issuer := srv.URL + "/mcp/"
				if wrongClaim {
					issuer = srv.URL + "/other/"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer": issuer, "registration_endpoint": srv.URL + "/register",
				})
			}))
			defer srv.Close()

			target := srv.URL + "/mcp/"
			client := attack.NewUnauthHTTPClient(attack.Options{}, attack.NewVars(target, ""))
			fields, err := discoverOAuthFields(t.Context(), client, target, "registration_endpoint")
			if wrongClaim {
				if fields != nil || !errors.Is(err, attack.ErrInconclusive) {
					t.Fatalf("mismatched issuer accepted: fields=%v err=%v", fields, err)
				}
			} else if err != nil || fields["registration_endpoint"] != srv.URL+"/register" {
				t.Fatalf("valid issuer metadata ignored: fields=%v err=%v", fields, err)
			}
		})
	}
}
