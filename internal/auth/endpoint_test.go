package auth

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestParseOAuthEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "HTTPS", raw: "https://auth.example.com/token"},
		{name: "mixed-case scheme", raw: "HTTPS://auth.example.com/token"},
		{name: "query", raw: "https://auth.example.com/token?tenant=one&value=%23"},
		{name: "IPv6", raw: "https://[2001:db8::1]:8443/token"},
		{name: "HTTP", raw: "http://auth.example.com/token", wantErr: "must use HTTPS"},
		{name: "relative", raw: "/token", wantErr: "must use HTTPS"},
		{name: "missing host", raw: "https:///token", wantErr: "must include a host"},
		{name: "opaque", raw: "https:token", wantErr: "must include a host"},
		{name: "fragment", raw: "https://auth.example.com/token#section", wantErr: "must not include a fragment"},
		{name: "empty fragment", raw: "https://auth.example.com/token#", wantErr: "must not include a fragment"},
		{name: "malformed query", raw: "https://auth.example.com/token?one=1;two=2", wantErr: "invalid query"},
		{name: "invalid port", raw: "https://auth.example.com:65536/token", wantErr: "invalid port"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOAuthEndpoint(tc.raw, "token URL")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("parseOAuthEndpoint: %v", err)
				}
				if got == nil || !strings.EqualFold(got.Scheme, "https") {
					t.Fatalf("parsed URL = %#v", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildAuthURLPreservesQuery(t *testing.T) {
	got, err := buildAuthURL(PKCEFlowConfig{
		AuthURL:  "https://auth.example.com/authorize?tenant=one&tenant=two&value=%23",
		ClientID: "client",
		Scopes:   []string{"read", "write"},
	}, "challenge", "state", "http://127.0.0.1:9876/callback")
	if err != nil {
		t.Fatalf("buildAuthURL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	query := parsed.Query()
	if !reflect.DeepEqual(query["tenant"], []string{"one", "two"}) {
		t.Fatalf("tenant query = %v", query["tenant"])
	}
	if query.Get("value") != "#" || query.Get("client_id") != "client" || query.Get("scope") != "read write" {
		t.Fatalf("query = %v", query)
	}
}

func TestOAuthEntryPointsRejectMalformedEndpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchClientCredentialsToken(ctx, ClientCredentialsConfig{TokenURL: "https:///token"}); err == nil || !strings.Contains(err.Error(), "token URL must include a host") {
		t.Fatalf("client credentials validation error = %v", err)
	}
	if _, err := ExchangeAuthCode(ctx, AuthCodeConfig{TokenURL: "https://auth.example.com/token#fragment"}); err == nil || !strings.Contains(err.Error(), "token URL must not include a fragment") {
		t.Fatalf("authorization-code validation error = %v", err)
	}

	logged := false
	_, err := PerformPKCEFlow(ctx, PKCEFlowConfig{
		AuthURL:  "https://auth.example.com/authorize",
		TokenURL: "https:///token",
		ClientID: "client",
		Logger:   func(string, ...interface{}) { logged = true },
	})
	if err == nil || !strings.Contains(err.Error(), "token URL must include a host") {
		t.Fatalf("PKCE validation error = %v", err)
	}
	if logged {
		t.Fatal("PKCE logged interactive flow details before endpoint validation")
	}
}
